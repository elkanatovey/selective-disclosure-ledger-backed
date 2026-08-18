#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A deterministic stand-in for the C++ selective-disclosure tool.

The real tool owns every CBOR, COSE and X.509 operation. This test double
mimics only its command line contract and file conventions so that the control
plane can be exercised without building the C++ core. Its artifact format is
deliberately private to the tests.

Failure injection is driven by environment variables:

``FAKE_CLI_FAIL``
    Comma separated command names that must exit non-zero.
``FAKE_CLI_EMPTY``
    Comma separated command names that must produce an empty output file.
``FAKE_CLI_SLEEP``
    Seconds to sleep before doing any work.
``FAKE_CLI_TAMPER``
    When set, ``verify`` reports a failed issuer signature check.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import zlib
from pathlib import Path
from typing import Any

MAGIC = b"\x00FAKEBUNDLE\x00"
PUBLIC_PEM = (
    b"-----BEGIN PUBLIC KEY-----\nDERIVED-PUBLIC-KEY\n-----END PUBLIC KEY-----\n"
)
LEAF_PEM = b"-----BEGIN CERTIFICATE-----\nLEAF-CERTIFICATE\n-----END CERTIFICATE-----\n"
CHUNK_SIZE = 6
FIELD_ORDER = ("title", "component", "severity", "fingerprint", "references")


def _checksum(payload: bytes) -> int:
    return zlib.crc32(payload) & 0xFFFFFFFF


def _write(path: str, payload: bytes, command: str) -> None:
    empty = os.environ.get("FAKE_CLI_EMPTY", "")
    if command in {item.strip() for item in empty.split(",") if item.strip()}:
        payload = b""
    Path(path).write_bytes(payload)


def _fail_if_requested(command: str) -> None:
    failures = {
        item.strip()
        for item in os.environ.get("FAKE_CLI_FAIL", "").split(",")
        if item.strip()
    }
    if command in failures:
        sys.stderr.write(f"simulated failure for '{command}'\n")
        raise SystemExit(3)


def _load_bundle(path: str) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        sys.stderr.write("not a bundle\n")
        raise SystemExit(4)
    document = json.loads(raw[len(MAGIC) :].decode("utf-8"))
    assert isinstance(document, dict)
    return document


def _bundle_bytes(document: dict[str, Any]) -> bytes:
    return MAGIC + json.dumps(document, sort_keys=True).encode("utf-8")


def _report_of(document: dict[str, Any]) -> dict[str, Any]:
    disclosures = base64.b64decode(document["disclosures_b64"])
    payload = json.loads(disclosures[2:-1].decode("utf-8"))
    report: dict[str, Any] = payload["report"]
    return report


def cmd_key_public(args: argparse.Namespace) -> int:
    """Derive a public key artifact from a private key file."""
    private = Path(args.private_key).read_bytes()
    if b"PRIVATE" not in private:
        sys.stderr.write("not a private key\n")
        return 5
    _write(args.output, PUBLIC_PEM, "key public")
    return 0


def cmd_issue_cert(args: argparse.Namespace) -> int:
    """Issue a leaf certificate for a public key."""
    public = Path(args.public_key).read_bytes()
    if b"PUBLIC" not in public:
        sys.stderr.write("not a public key\n")
        return 5
    Path(args.root_key).read_bytes()
    Path(args.root_cert).read_bytes()
    suffix = f"# key: {_checksum(public):08x}\n".encode("ascii")
    _write(args.output, LEAF_PEM + suffix, "issue-cert")
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    """Create a registered statement and a disclosure set."""
    report = json.loads(Path(args.report_json).read_text(encoding="utf-8"))
    private = Path(args.private_key).read_bytes()
    if b"PRIVATE" not in private:
        sys.stderr.write("not a private key\n")
        return 5
    leaf = Path(args.leaf_cert).read_bytes()
    Path(args.root_cert).read_bytes()
    canonical = json.dumps(report, sort_keys=True).encode("utf-8")
    registered = (
        b"\xd2\x84\xa1"
        + json.dumps(
            {
                "kind": "registered-statement",
                "report_crc": _checksum(canonical),
                "leaf_crc": _checksum(leaf),
            },
            sort_keys=True,
        ).encode("utf-8")
        + b"\xff"
    )
    disclosures = (
        b"\xa1\x01"
        + json.dumps({"report": report}, sort_keys=True).encode("utf-8")
        + b"\xfe"
    )
    _write(args.registered, registered, "issue")
    _write(args.disclosures, disclosures, "issue")
    return 0


def cmd_bundle_create(args: argparse.Namespace) -> int:
    """Combine the statement, receipt and disclosures into one bundle."""
    document = {
        "registered_b64": base64.b64encode(Path(args.registered).read_bytes()).decode(
            "ascii"
        ),
        "transparent_b64": base64.b64encode(Path(args.transparent).read_bytes()).decode(
            "ascii"
        ),
        "disclosures_b64": base64.b64encode(Path(args.disclosures).read_bytes()).decode(
            "ascii"
        ),
        "scitt_url": args.scitt_url,
        "txid": args.txid,
        "redacted_fields": [],
        "redacted_body_chunks": [],
    }
    _write(args.output, _bundle_bytes(document), "bundle create")
    return 0


def cmd_bundle_inspect(args: argparse.Namespace) -> int:
    """Render the disclosures a bundle still carries."""
    document = _load_bundle(args.bundle)
    report = _report_of(document)
    dropped_fields = set(document.get("redacted_fields", []))
    dropped_chunks = set(document.get("redacted_body_chunks", []))

    fields = []
    for name in FIELD_ORDER:
        value = report.get(name, "")
        if isinstance(value, list):
            value = "\n".join(str(item) for item in value)
        disclosed = name not in dropped_fields
        fields.append(
            {
                "name": name,
                "label": name.replace("_", " ").title(),
                "disclosed": disclosed,
                "value": str(value) if disclosed else None,
            }
        )

    body = str(report.get("body", ""))
    chunks = []
    for index in range(0, max(len(body), 1), CHUNK_SIZE):
        position = index // CHUNK_SIZE
        disclosed = position not in dropped_chunks
        chunks.append(
            {
                "index": position,
                "text": body[index : index + CHUNK_SIZE] if disclosed else "",
                "disclosed": disclosed,
            }
        )

    inspection = {
        "fields": fields,
        "body": {"chunk_size": CHUNK_SIZE, "chunks": chunks},
        "scitt": {"url": document.get("scitt_url"), "txid": document.get("txid")},
        "notes": ["Rendered by the fake selective-disclosure tool."],
    }
    Path(args.json_output).write_text(
        json.dumps(inspection, sort_keys=True), encoding="utf-8"
    )
    return 0


def cmd_bundle_extract(args: argparse.Namespace) -> int:
    """Copy the exact statement bytes out of a bundle, unchanged."""
    document = _load_bundle(args.bundle)
    _write(
        args.registered,
        base64.b64decode(document["registered_b64"]),
        "bundle extract",
    )
    _write(
        args.transparent,
        base64.b64decode(document["transparent_b64"]),
        "bundle extract",
    )
    return 0


def cmd_bundle_present(args: argparse.Namespace) -> int:
    """Drop the selected field and body chunk disclosures."""
    document = _load_bundle(args.bundle)
    selection = json.loads(Path(args.selection_json).read_text(encoding="utf-8"))
    fields = sorted(
        set(document.get("redacted_fields", []))
        | {str(item) for item in selection.get("redact_fields", [])}
    )
    chunks = sorted(
        set(document.get("redacted_body_chunks", []))
        | {int(item) for item in selection.get("redact_body_chunks", [])}
    )
    document["redacted_fields"] = fields
    document["redacted_body_chunks"] = chunks
    _write(args.output, _bundle_bytes(document), "bundle present")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Report the four verification checks the C++ tool owns.

    The SCITT receipt is deliberately absent: it is only ever decided by the
    official upstream verifier.
    """
    document = _load_bundle(args.bundle)
    msrc_root = Path(args.msrc_root).read_bytes()
    registered = base64.b64decode(document["registered_b64"])
    report = _report_of(document)
    statement = json.loads(registered[3:-1].decode("utf-8"))
    canonical = json.dumps(report, sort_keys=True).encode("utf-8")

    signature_ok = not os.environ.get("FAKE_CLI_TAMPER")
    binding_ok = statement.get("report_crc") == _checksum(canonical)
    checks = {
        "msrc_chain": {
            "status": "pass" if b"CERTIFICATE" in msrc_root else "fail",
            "detail": "Demo root accepted." if b"CERTIFICATE" in msrc_root else "",
        },
        "issuer_signature": {
            "status": "pass" if signature_ok else "fail",
            "detail": "Signature checked by the fake tool.",
        },
        "disclosures": {
            "status": "pass",
            "detail": (
                f"{len(document.get('redacted_fields', []))} fields and "
                f"{len(document.get('redacted_body_chunks', []))} chunks dropped."
            ),
        },
        "statement_binding": {
            "status": "pass" if binding_ok else "fail",
            "detail": "Registered statement matches the disclosures.",
        },
    }
    overall = (
        "fail"
        if any(entry["status"] != "pass" for entry in checks.values())
        else "pass"
    )
    Path(args.json_output).write_text(
        json.dumps({"overall": overall, "checks": checks}, sort_keys=True),
        encoding="utf-8",
    )
    return 1 if overall == "fail" else 0


def build_parser() -> argparse.ArgumentParser:
    """Return the command line parser of the test double."""
    parser = argparse.ArgumentParser(prog="scitt-sd")
    commands = parser.add_subparsers(dest="command", required=True)

    key = commands.add_parser("key")
    key_commands = key.add_subparsers(dest="key_command", required=True)
    key_public = key_commands.add_parser("public")
    key_public.add_argument("--private-key", required=True)
    key_public.add_argument("--output", required=True)
    key_public.set_defaults(handler=cmd_key_public, name="key public")

    issue_cert = commands.add_parser("issue-cert")
    issue_cert.add_argument("--root-key", required=True)
    issue_cert.add_argument("--root-cert", required=True)
    issue_cert.add_argument("--public-key", required=True)
    issue_cert.add_argument("--output", required=True)
    issue_cert.set_defaults(handler=cmd_issue_cert, name="issue-cert")

    issue = commands.add_parser("issue")
    issue.add_argument("--report-json", required=True)
    issue.add_argument("--private-key", required=True)
    issue.add_argument("--leaf-cert", required=True)
    issue.add_argument("--root-cert", required=True)
    issue.add_argument("--registered", required=True)
    issue.add_argument("--disclosures", required=True)
    issue.set_defaults(handler=cmd_issue, name="issue")

    bundle = commands.add_parser("bundle")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", required=True)

    create = bundle_commands.add_parser("create")
    create.add_argument("--registered", required=True)
    create.add_argument("--transparent", required=True)
    create.add_argument("--disclosures", required=True)
    create.add_argument("--scitt-url", required=True)
    create.add_argument("--txid", required=True)
    create.add_argument("--output", required=True)
    create.set_defaults(handler=cmd_bundle_create, name="bundle create")

    inspect = bundle_commands.add_parser("inspect")
    inspect.add_argument("--bundle", required=True)
    inspect.add_argument("--json-output", required=True)
    inspect.set_defaults(handler=cmd_bundle_inspect, name="bundle inspect")

    extract = bundle_commands.add_parser("extract")
    extract.add_argument("--bundle", required=True)
    extract.add_argument("--registered", required=True)
    extract.add_argument("--transparent", required=True)
    extract.set_defaults(handler=cmd_bundle_extract, name="bundle extract")

    present = bundle_commands.add_parser("present")
    present.add_argument("--bundle", required=True)
    present.add_argument("--selection-json", required=True)
    present.add_argument("--output", required=True)
    present.set_defaults(handler=cmd_bundle_present, name="bundle present")

    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--msrc-root", required=True)
    verify.add_argument("--json-output", required=True)
    verify.set_defaults(handler=cmd_verify, name="verify")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the test double."""
    delay = os.environ.get("FAKE_CLI_SLEEP", "")
    if delay:
        time.sleep(float(delay))
    args = build_parser().parse_args(argv)
    _fail_if_requested(args.name)
    handler = args.handler
    result: int = handler(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
