# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The single place that maps demo operations onto CLI command lines.

Every subcommand, flag name and output convention of the C++ tool is expressed
here. If the tool's interface changes, only this module changes. Callers work
with paths, opaque bytes and typed models.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..errors import CliError, truncate_detail
from ..models import BundleInspection, VerificationReport
from .parsing import parse_inspection, parse_verification
from .protocol import CliResult, CliRunner


@dataclass(frozen=True)
class IssuedStatement:
    """Paths produced by the ``issue`` subcommand."""

    registered: Path
    disclosures: Path


@dataclass(frozen=True)
class ExtractedStatements:
    """Paths produced by the ``bundle extract`` subcommand."""

    registered: Path
    transparent: Path


class CliClient:
    """Typed facade over the selective-disclosure command line tool."""

    def __init__(self, runner: CliRunner, *, timeout: float | None = None) -> None:
        self.runner = runner
        self.timeout = timeout

    def _run(
        self, args: list[str], *, cwd: Path | None = None, check: bool = True
    ) -> CliResult:
        return self.runner.run(args, cwd=cwd, timeout=self.timeout, check=check)

    @staticmethod
    def _require_output(path: Path, description: str) -> Path:
        if not path.is_file() or path.stat().st_size == 0:
            raise CliError(
                "The selective-disclosure tool produced no output.",
                detail=f"Expected {description} at '{path.name}'.",
            )
        return path

    @staticmethod
    def _load_json(path: Path, description: str) -> object:
        if not path.is_file():
            raise CliError(
                "The selective-disclosure tool produced no report.",
                detail=f"Expected {description} at '{path.name}'.",
            )
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CliError(
                "The selective-disclosure tool produced an unreadable report.",
                detail=f"{description}: {error}",
            ) from error

    def derive_public_key(self, *, private_key: Path, output: Path) -> Path:
        """Derive a public key from a private key without transmitting it."""
        self._run(
            [
                "key",
                "public",
                "--private-key",
                str(private_key),
                "--output",
                str(output),
            ]
        )
        return self._require_output(output, "a public key")

    def issue_certificate(
        self,
        *,
        root_key: Path,
        root_cert: Path,
        public_key: Path,
        output: Path,
    ) -> Path:
        """Issue a short-lived leaf certificate for an enrolled public key."""
        self._run(
            [
                "issue-cert",
                "--root-key",
                str(root_key),
                "--root-cert",
                str(root_cert),
                "--public-key",
                str(public_key),
                "--output",
                str(output),
            ]
        )
        return self._require_output(output, "a leaf certificate")

    def issue_statement(
        self,
        *,
        report_json: Path,
        private_key: Path,
        leaf_cert: Path,
        root_cert: Path,
        registered: Path,
        disclosures: Path,
    ) -> IssuedStatement:
        """Create the registered statement and its disclosure set."""
        self._run(
            [
                "issue",
                "--report-json",
                str(report_json),
                "--private-key",
                str(private_key),
                "--leaf-cert",
                str(leaf_cert),
                "--root-cert",
                str(root_cert),
                "--registered",
                str(registered),
                "--disclosures",
                str(disclosures),
            ]
        )
        return IssuedStatement(
            registered=self._require_output(registered, "a registered statement"),
            disclosures=self._require_output(disclosures, "a disclosure set"),
        )

    def create_bundle(
        self,
        *,
        registered: Path,
        transparent: Path,
        disclosures: Path,
        scitt_url: str,
        txid: str,
        output: Path,
    ) -> Path:
        """Combine registered statement, receipt and disclosures into a bundle."""
        self._run(
            [
                "bundle",
                "create",
                "--registered",
                str(registered),
                "--transparent",
                str(transparent),
                "--disclosures",
                str(disclosures),
                "--scitt-url",
                scitt_url,
                "--txid",
                txid,
                "--output",
                str(output),
            ]
        )
        return self._require_output(output, "a bundle")

    def inspect_bundle(self, *, bundle: Path, json_output: Path) -> BundleInspection:
        """Return the tool's rendering of the disclosures inside a bundle."""
        self._run(
            [
                "bundle",
                "inspect",
                "--bundle",
                str(bundle),
                "--json-output",
                str(json_output),
            ]
        )
        return parse_inspection(self._load_json(json_output, "an inspection report"))

    def present_bundle(
        self, *, bundle: Path, selection_json: Path, output: Path
    ) -> Path:
        """Produce a redacted bundle from a selection document."""
        self._run(
            [
                "bundle",
                "present",
                "--bundle",
                str(bundle),
                "--selection-json",
                str(selection_json),
                "--output",
                str(output),
            ]
        )
        return self._require_output(output, "a presented bundle")

    def extract_statements(
        self, *, bundle: Path, registered: Path, transparent: Path
    ) -> ExtractedStatements:
        """Copy the exact statement bytes a bundle carries out of it.

        The tool writes the bytes verbatim; nothing re-encodes them. They are
        the inputs the official SCITT verifier must be given so that the
        receipt is bound to the bytes that were actually registered.
        """
        self._run(
            [
                "bundle",
                "extract",
                "--bundle",
                str(bundle),
                "--registered",
                str(registered),
                "--transparent",
                str(transparent),
            ]
        )
        return ExtractedStatements(
            registered=self._require_output(registered, "a registered statement"),
            transparent=self._require_output(transparent, "a transparent statement"),
        )

    def verify_bundle(
        self,
        *,
        bundle: Path,
        msrc_root: Path,
        json_output: Path,
    ) -> VerificationReport:
        """Verify a bundle against the separately supplied MSRC trust anchor.

        The tool performs the four checks it owns: the MSRC certificate chain,
        the issuer signature, disclosure consistency and the binding between
        the registered and transparent statements. It does not verify the SCITT
        receipt; that is the official verifier's job, and its result is merged
        in by the caller.

        A non-zero exit code is treated as a verification outcome as long as
        the tool wrote a report; otherwise it is surfaced as a tool failure.
        """
        result = self._run(
            [
                "verify",
                "--bundle",
                str(bundle),
                "--msrc-root",
                str(msrc_root),
                "--json-output",
                str(json_output),
            ],
            check=False,
        )
        if result.returncode != 0 and not json_output.is_file():
            raise CliError(
                "The selective-disclosure tool could not verify the bundle.",
                detail=(
                    f"Command 'verify' exited with {result.returncode}: "
                    f"{truncate_detail(result.stderr, 2000) or 'no output'}"
                ),
                returncode=result.returncode,
            )
        return parse_verification(self._load_json(json_output, "a verification report"))
