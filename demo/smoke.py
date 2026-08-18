#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end check for the running demonstration.

Drives the whole story over HTTP: enrol a researcher, submit a report, let the
MSRC role drop some disclosures, and verify the redacted bundle with both
engines. Every check in the final report must pass.

This script only speaks HTTP and JSON, and shells out to the C++ tool with a
fixed argument vector to create a key pair. It performs no cryptography.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

REPORT = {
    "title": "Heap overflow in the demo parser",
    "component": "demo-parser",
    "severity": "high",
    "fingerprint": "0xdeadbeef",
    "references": "https://example.invalid/advisory/1",
    "body": (
        "The parser copies an attacker controlled length into a fixed buffer. "
        "Contact the reporter at researcher@example.invalid for the private "
        "proof of concept. The internal tracking identifier is DEMO-4711 and "
        "the affected customer is Contoso."
    ),
}

EXPECTED_CHECKS = {
    "msrc_chain",
    "issuer_signature",
    "disclosures",
    "statement_binding",
    "scitt_receipt",
}


class SmokeError(RuntimeError):
    """A step of the end-to-end check did not behave as required."""


def check(condition: bool, message: str) -> None:
    """Raise a readable failure when an expectation does not hold."""
    if not condition:
        raise SmokeError(message)


def expect_ok(response: httpx.Response, what: str) -> Any:
    """Return the JSON body of a successful response."""
    if response.status_code >= 400:
        raise SmokeError(
            f"{what} failed with HTTP {response.status_code}: {response.text}"
        )
    return response.json()


def generate_key(cli: str, destination: Path) -> Path:
    """Ask the C++ tool for a fresh researcher key pair."""
    completed = subprocess.run(  # noqa: S603 - fixed argument vector
        [cli, "key", "generate", "--output", str(destination)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SmokeError(
            f"key generation failed ({completed.returncode}): "
            f"{completed.stderr or completed.stdout}"
        )
    check(destination.is_file(), f"the tool did not write {destination}")
    return destination


def enrol(client: httpx.Client, key: Path) -> str:
    """Enrol the researcher and confirm the private key stayed local."""
    with key.open("rb") as handle:
        body = expect_ok(
            client.post(
                "/api/researcher/enroll",
                data={"subject": "Demo researcher"},
                files={
                    "private_key": ("researcher.key", handle, "application/x-pem-file")
                },
            ),
            "enrollment",
        )
    check(
        body["private_key_transmitted"] is False,
        "the enrollment response did not confirm that the private key stayed local",
    )
    check(body["leaf_certificate_bytes"] > 0, "no leaf certificate was issued")
    return str(body["enrollment_id"])


def submit(client: httpx.Client, enrollment_id: str, key: Path) -> dict[str, Any]:
    """Run the one click submission and require every stage to succeed."""
    with key.open("rb") as handle:
        response = client.post(
            "/api/researcher/submit",
            data={"enrollment_id": enrollment_id, **REPORT},
            files={"private_key": ("researcher.key", handle, "application/x-pem-file")},
        )
    body = expect_ok(response, "submission")
    stages = {stage["name"]: stage["status"] for stage in body["stages"]}
    check(
        body["status"] == "complete",
        f"the submission did not complete: {body['message']} ({stages})",
    )
    order = [stage["name"] for stage in body["stages"]]
    check(
        order.index("scitt_register") < order.index("msrc_deliver"),
        f"MSRC delivery was not ordered after SCITT registration: {order}",
    )
    check(body["scitt"]["registered"] is True, "the statement was not registered")
    check(bool(body["scitt"]["txid"]), "no transparency transaction identifier")
    return dict(body)


def download(client: httpx.Client, url: str, what: str) -> bytes:
    """Fetch an artefact and require it to be non-empty."""
    response = client.get(url)
    if response.status_code >= 400:
        raise SmokeError(f"{what} download failed with HTTP {response.status_code}")
    check(bool(response.content), f"{what} was empty")
    return response.content


def redact(client: httpx.Client, submission_id: str) -> tuple[str, bytes]:
    """Inspect the stored bundle and drop a field and a body chunk."""
    inspection = expect_ok(
        client.post(f"/api/msrc/submissions/{submission_id}/inspect"),
        "inspection",
    )
    bundle_id = str(inspection["bundle_id"])
    fields = inspection["inspection"]["fields"]
    chunks = inspection["inspection"]["body_chunks"]
    check(bool(fields), "the tool reported no disclosable fields")
    check(bool(chunks), "the tool reported no body chunks")

    redactable = [field["name"] for field in fields if field.get("disclosed", True)]
    check("fingerprint" in redactable, f"fingerprint is not redactable: {redactable}")

    presentation = expect_ok(
        client.post(
            f"/api/msrc/imports/{bundle_id}/present",
            json={"redact_fields": ["fingerprint"], "redact_body_chunks": [0]},
        ),
        "presentation",
    )
    check(
        presentation["redacted_fields"] == ["fingerprint"],
        f"unexpected redacted fields: {presentation['redacted_fields']}",
    )
    check(
        presentation["redacted_body_chunks"] == [0],
        f"unexpected redacted chunks: {presentation['redacted_body_chunks']}",
    )
    redacted = download(client, presentation["download_url"], "redacted bundle")
    return bundle_id, redacted


def verify(
    client: httpx.Client, bundle: bytes, msrc_root: Path, trust_store: Path
) -> dict[str, Any]:
    """Verify the redacted bundle with both engines."""
    body = expect_ok(
        client.post(
            "/api/verifier/verify",
            files={
                "bundle": ("presentation.bundle", bundle, "application/octet-stream"),
                "msrc_root": (
                    "msrc-root.pem",
                    msrc_root.read_bytes(),
                    "application/x-pem-file",
                ),
                "scitt_trust": (
                    trust_store.name,
                    trust_store.read_bytes(),
                    "application/octet-stream",
                ),
            },
        ),
        "verification",
    )
    report = body["report"]
    seen = {item["id"]: item for item in report["checks"]}
    missing = EXPECTED_CHECKS - set(seen)
    check(not missing, f"the report is missing checks: {sorted(missing)}")
    for identifier, item in sorted(seen.items()):
        check(
            item["status"] == "pass",
            f"check {identifier} did not pass: {item['status']} - {item.get('detail')}",
        )
    sources = {item["id"]: item for item in report["sources"]}
    check(
        {"cpp_cli", "official_scitt"} <= set(sources),
        f"the report does not name both engines: {sorted(sources)}",
    )
    check(
        sources["official_scitt"]["status"] == "pass",
        f"the official SCITT verifier did not pass: {sources['official_scitt']}",
    )
    check(report["overall"] == "pass", f"the overall verdict is {report['overall']}")
    return dict(report)


def check_redaction_is_visible(
    client: httpx.Client, bundle_id: str, bundle: bytes
) -> None:
    """Confirm the redacted disclosures are gone from the presentation."""
    inspection = expect_ok(
        client.post(
            "/api/msrc/inspect",
            files={
                "bundle": ("presentation.bundle", bundle, "application/octet-stream")
            },
        ),
        "presentation inspection",
    )
    check(inspection["bundle_id"] != bundle_id, "the presentation reused the import id")
    fields = {field["name"]: field for field in inspection["inspection"]["fields"]}
    check(
        fields["fingerprint"]["disclosed"] is False,
        "the fingerprint field is still disclosed after redaction",
    )
    chunks = inspection["inspection"]["body_chunks"]
    check(chunks[0]["disclosed"] is False, "the first body chunk is still disclosed")
    check(
        any(chunk["disclosed"] for chunk in chunks[1:]),
        "every body chunk was dropped, so nothing remains to read",
    )


def run(web: str, mock: str, trust_store: Path, cli: str) -> int:
    """Run the whole check and report the outcome."""
    with tempfile.TemporaryDirectory(prefix="sdc-smoke-") as workspace:
        key = generate_key(cli, Path(workspace) / "researcher.key")
        with (
            httpx.Client(base_url=web, timeout=120.0) as client,
            httpx.Client(base_url=mock, timeout=60.0) as mock_client,
        ):
            root = expect_ok(mock_client.get("/healthz"), "mock MSRC health")
            check(
                root["cli_configured"] is True, "the mock MSRC has no issuance material"
            )
            msrc_root = Path(workspace) / "msrc-root.pem"
            msrc_root.write_bytes(download(mock_client, "/msrc-root", "MSRC root"))

            enrollment_id = enrol(client, key)
            submission = submit(client, enrollment_id, key)
            download(client, submission["statement_url"], "registered statement")
            download(client, submission["transparent_url"], "transparency token")
            download(client, submission["bundle_url"], "bundle")

            stored = expect_ok(
                client.get("/api/msrc/submissions"), "stored submissions"
            )
            check(bool(stored["submissions"]), "the MSRC received no submission")
            submission_id = str(submission["msrc_submission_id"])

            bundle_id, redacted = redact(client, submission_id)
            check_redaction_is_visible(client, bundle_id, redacted)
            report = verify(client, redacted, msrc_root, trust_store)

    sys.stdout.write("end-to-end check passed\n")
    for item in report["sources"]:
        sys.stdout.write(f"  {item['label']}: {item['status']}\n")
    for item in report["checks"]:
        sys.stdout.write(f"  {item['id']}: {item['status']}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the end-to-end check."""
    parser = argparse.ArgumentParser(prog="smoke.py")
    parser.add_argument("--web", default="http://127.0.0.1:8080")
    parser.add_argument("--mock", default="http://127.0.0.1:8081")
    parser.add_argument("--trust-store", required=True)
    parser.add_argument("--cli", default=os.environ.get("SDC_CLI", "build/scitt-sd"))
    args = parser.parse_args(argv)

    try:
        return run(args.web, args.mock, Path(args.trust_store), args.cli)
    except SmokeError as error:
        sys.stderr.write(f"end-to-end check failed: {error}\n")
        return 1
    except httpx.HTTPError as error:
        sys.stderr.write(f"end-to-end check could not reach a service: {error}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
