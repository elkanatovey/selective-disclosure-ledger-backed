# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Byte oriented wrappers around the file oriented command line tool.

Each helper writes opaque inputs into a private temporary directory, invokes
the tool and reads the opaque outputs back. Uploaded private keys only ever
exist inside that directory and are overwritten and removed before the request
completes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cli import CliClient
from .cli.parsing import merge_official_scitt
from .errors import CliError
from .models import BundleInspection, SelectionRequest, VerificationReport
from .scitt_verify import OfficialVerifier
from .workspace import secure_workspace, write_private_file


@dataclass(frozen=True)
class IssuedArtifacts:
    """The opaque bytes produced by the ``issue`` command."""

    registered_statement: bytes
    disclosures: bytes


@dataclass(frozen=True)
class ExtractedStatements:
    """The exact statement bytes carried inside a bundle."""

    registered_statement: bytes
    transparent_statement: bytes


def _write(path: Path, payload: bytes) -> Path:
    return write_private_file(path, payload)


def derive_public_key(cli: CliClient, private_key: bytes) -> bytes:
    """Derive the public key for an imported private key, locally."""
    with secure_workspace() as workspace:
        private_path = _write(workspace / "private.pem", private_key)
        public_path = workspace / "public.pem"
        cli.derive_public_key(private_key=private_path, output=public_path)
        return public_path.read_bytes()


def issue_certificate(
    cli: CliClient,
    *,
    root_key: Path,
    root_cert: Path,
    public_key: bytes,
) -> bytes:
    """Issue a leaf certificate for an enrolled public key."""
    with secure_workspace() as workspace:
        public_path = _write(workspace / "public.pem", public_key)
        output = workspace / "leaf.pem"
        cli.issue_certificate(
            root_key=root_key,
            root_cert=root_cert,
            public_key=public_path,
            output=output,
        )
        return output.read_bytes()


def issue_statement(
    cli: CliClient,
    *,
    report: Mapping[str, Any],
    private_key: bytes,
    leaf_cert: bytes,
    root_cert: bytes,
) -> IssuedArtifacts:
    """Create the registered statement and disclosure set for a report."""
    with secure_workspace() as workspace:
        report_path = _write(
            workspace / "report.json",
            json.dumps(report, ensure_ascii=True, sort_keys=True).encode("utf-8"),
        )
        private_path = _write(workspace / "private.pem", private_key)
        leaf_path = _write(workspace / "leaf.pem", leaf_cert)
        root_path = _write(workspace / "root.pem", root_cert)
        registered = workspace / "registered.cose"
        disclosures = workspace / "disclosures.cbor"
        cli.issue_statement(
            report_json=report_path,
            private_key=private_path,
            leaf_cert=leaf_path,
            root_cert=root_path,
            registered=registered,
            disclosures=disclosures,
        )
        return IssuedArtifacts(
            registered_statement=registered.read_bytes(),
            disclosures=disclosures.read_bytes(),
        )


def create_bundle(
    cli: CliClient,
    *,
    registered_statement: bytes,
    transparent_statement: bytes,
    disclosures: bytes,
    scitt_url: str,
    txid: str,
) -> bytes:
    """Build the full proof bundle after transparency registration."""
    with secure_workspace() as workspace:
        registered_path = _write(workspace / "registered.cose", registered_statement)
        transparent_path = _write(workspace / "transparent.cose", transparent_statement)
        disclosures_path = _write(workspace / "disclosures.cbor", disclosures)
        output = workspace / "bundle.cbor"
        cli.create_bundle(
            registered=registered_path,
            transparent=transparent_path,
            disclosures=disclosures_path,
            scitt_url=scitt_url,
            txid=txid,
            output=output,
        )
        return output.read_bytes()


def inspect_bundle(cli: CliClient, bundle: bytes) -> BundleInspection:
    """Return the tool's rendering of a bundle."""
    with secure_workspace() as workspace:
        bundle_path = _write(workspace / "bundle.cbor", bundle)
        report = workspace / "inspection.json"
        return cli.inspect_bundle(bundle=bundle_path, json_output=report)


def present_bundle(cli: CliClient, bundle: bytes, selection: SelectionRequest) -> bytes:
    """Return a redacted bundle produced from a selection document."""
    with secure_workspace() as workspace:
        bundle_path = _write(workspace / "bundle.cbor", bundle)
        selection_path = _write(
            workspace / "selection.json",
            json.dumps(
                selection.to_cli_document(), ensure_ascii=True, sort_keys=True
            ).encode("utf-8"),
        )
        output = workspace / "presented.cbor"
        cli.present_bundle(
            bundle=bundle_path, selection_json=selection_path, output=output
        )
        return output.read_bytes()


def extract_statements(cli: CliClient, bundle: bytes) -> ExtractedStatements:
    """Return the exact statement bytes a bundle carries.

    Nothing here parses or re-encodes them; the tool copies the bytes out
    verbatim so that the official SCITT verifier is given exactly what was
    registered.
    """
    with secure_workspace() as workspace:
        bundle_path = _write(workspace / "bundle.cbor", bundle)
        registered = workspace / "registered.cose"
        transparent = workspace / "transparent.cose"
        cli.extract_statements(
            bundle=bundle_path, registered=registered, transparent=transparent
        )
        return ExtractedStatements(
            registered_statement=registered.read_bytes(),
            transparent_statement=transparent.read_bytes(),
        )


def verify_bundle(
    cli: CliClient,
    verifier: OfficialVerifier,
    *,
    bundle: bytes,
    msrc_root: bytes,
    scitt_trust: bytes,
    trust_name: str = "scitt-keys.cbor",
) -> VerificationReport:
    """Verify a bundle with both independent engines and merge the results.

    The C++ tool checks the MSRC chain, the issuer signature, the disclosures
    and the statement binding. The SCITT receipt is checked only by the
    official upstream verifier, which is given the exact bytes the bundle
    carries and the separately imported transparency service trust store. The
    merged report passes only if all five checks pass.
    """
    with secure_workspace() as workspace:
        bundle_path = _write(workspace / "bundle.cbor", bundle)
        msrc_root_path = _write(workspace / "msrc-root.pem", msrc_root)
        report_path = workspace / "verification.json"
        report = cli.verify_bundle(
            bundle=bundle_path,
            msrc_root=msrc_root_path,
            json_output=report_path,
        )

    try:
        statements = extract_statements(cli, bundle)
    except CliError as error:
        return merge_official_scitt(
            report,
            status="unknown",
            detail=(
                "The exact statement bytes could not be read out of the "
                f"bundle, so the official SCITT verifier was not run: "
                f"{error.message}"
            ),
        )

    official = verifier.verify(
        registered=statements.registered_statement,
        transparent=statements.transparent_statement,
        trust_store=scitt_trust,
        name=trust_name,
    )
    return merge_official_scitt(report, status=official.status, detail=official.detail)
