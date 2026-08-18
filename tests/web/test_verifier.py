# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Verifier tests: the C++ tool and the official SCITT verifier are merged."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from conftest import ROOT_CERT, SCITT_TRUST, Harness

CLI_CHECKS = (
    "msrc_chain",
    "issuer_signature",
    "disclosures",
    "statement_binding",
)
SCITT_CHECK = "scitt_receipt"


def checks_of(payload: dict[str, Any]) -> dict[str, str]:
    """Return check identifier to status for a verification report."""
    return {item["id"]: item["status"] for item in payload["checks"]}


def sources_of(payload: dict[str, Any]) -> dict[str, str]:
    """Return source identifier to status for a verification report."""
    return {item["id"]: item["status"] for item in payload["sources"]}


@pytest.fixture
def verified_bundle(harness: Harness) -> bytes:
    """Return a bundle produced by a complete researcher submission."""
    enrollment = harness.enroll()
    response = harness.submit(enrollment)
    assert response.status_code == 200, response.text
    return harness.stored_bundle(response.json()["submission_id"])


def test_verification_reports_five_checks_and_two_sources(
    harness: Harness, verified_bundle: bytes
) -> None:
    """Both engines report, and every check is present exactly once."""
    response = harness.verify(verified_bundle)
    assert response.status_code == 200, response.text
    payload = response.json()["report"]

    statuses = checks_of(payload)
    assert list(statuses) == [*CLI_CHECKS, SCITT_CHECK]
    assert all(status == "pass" for status in statuses.values())
    assert payload["overall"] == "pass"

    sources = sources_of(payload)
    assert sources == {"cpp_cli": "pass", "official_scitt": "pass"}


def test_official_verifier_receives_the_exact_statement_bytes(
    harness: Harness, verified_bundle: bytes
) -> None:
    """The registered and transparent bytes are passed through unchanged."""
    import hashlib

    enrollment_response = harness.web.get("/api/researcher/submissions")
    submission_id = enrollment_response.json()["submissions"][0]["submission_id"]
    registered = harness.web.get(
        f"/api/researcher/submissions/{submission_id}/statement"
    ).content
    transparent = harness.web.get(
        f"/api/researcher/submissions/{submission_id}/transparent"
    ).content

    response = harness.verify(verified_bundle)
    assert response.status_code == 200, response.text

    calls = harness.official.calls
    assert len(calls) == 1
    assert calls[0]["registered_sha256"] == hashlib.sha256(registered).hexdigest()
    assert calls[0]["transparent_sha256"] == hashlib.sha256(transparent).hexdigest()
    assert calls[0]["registered_bytes"] == len(registered)
    assert calls[0]["transparent_bytes"] == len(transparent)


def test_official_verifier_receives_the_imported_trust_store(
    harness: Harness, verified_bundle: bytes
) -> None:
    """Trust material is written into a directory the loader understands."""
    import hashlib

    response = harness.verify(verified_bundle)
    assert response.status_code == 200, response.text
    call = harness.official.calls[0]
    assert call["trust_files"] == ["scitt-keys.cbor"]
    assert (
        call["trust_sha256"]["scitt-keys.cbor"]
        == hashlib.sha256(SCITT_TRUST).hexdigest()
    )


def test_json_trust_material_is_stored_as_service_parameters(
    harness: Harness, verified_bundle: bytes
) -> None:
    """A JSON service parameters file keeps its JSON name for the loader."""
    response = harness.verify(
        verified_bundle,
        scitt_trust=b'{"serviceCertificate": "demo"}',
        trust_name="service-parameters.json",
    )
    assert response.status_code == 200, response.text
    assert harness.official.calls[0]["trust_files"] == ["service-parameters.json"]


def test_official_failure_fails_the_whole_report(
    harness: Harness, verified_bundle: bytes
) -> None:
    """A rejected receipt fails the overall result even if the tool passes."""
    harness.official.set_result("fail")
    response = harness.verify(verified_bundle)
    assert response.status_code == 200, response.text
    payload = response.json()["report"]

    statuses = checks_of(payload)
    assert all(statuses[name] == "pass" for name in CLI_CHECKS)
    assert statuses[SCITT_CHECK] == "fail"
    assert payload["overall"] == "fail"
    assert sources_of(payload) == {"cpp_cli": "pass", "official_scitt": "fail"}


def test_official_crash_never_reports_a_pass(
    harness: Harness, verified_bundle: bytes
) -> None:
    """A wrapper that dies is unresolved, never a pass."""
    harness.official.set_result("crash")
    response = harness.verify(verified_bundle)
    payload = response.json()["report"]
    assert checks_of(payload)[SCITT_CHECK] == "unknown"
    assert payload["overall"] != "pass"


def test_official_garbage_output_never_reports_a_pass(
    harness: Harness, verified_bundle: bytes
) -> None:
    """Non-JSON output is unresolved, never a pass."""
    harness.official.set_result("garbage")
    response = harness.verify(verified_bundle)
    payload = response.json()["report"]
    assert checks_of(payload)[SCITT_CHECK] == "unknown"
    assert payload["overall"] != "pass"
    assert (
        "JSON"
        in dict((item["id"], item["detail"]) for item in payload["checks"])[SCITT_CHECK]
    )


def test_official_verifier_absence_is_reported_as_skipped(
    harness: Harness, verified_bundle: bytes, tmp_path: Any
) -> None:
    """A missing submodule venv is reported, and never passes."""
    from scitt_selective_disclosure.scitt_verify import ScittVerifier

    missing = ScittVerifier(
        tmp_path / "no-such-python", tmp_path / "no-such-wrapper.py"
    )
    result = missing.verify(
        registered=b"a", transparent=b"b", trust_store=b"c", name="scitt-keys.cbor"
    )
    assert result.status == "skipped"
    assert not result.passed
    assert "demo/run.sh" in result.detail


def test_tampered_bundle_fails_the_tool_check(
    harness: Harness, verified_bundle: bytes
) -> None:
    """A failing tool check fails the report even if the receipt passes."""
    os.environ["FAKE_CLI_TAMPER"] = "1"
    try:
        response = harness.verify(verified_bundle)
    finally:
        os.environ.pop("FAKE_CLI_TAMPER", None)

    payload = response.json()["report"]
    statuses = checks_of(payload)
    assert statuses["issuer_signature"] == "fail"
    assert statuses[SCITT_CHECK] == "pass"
    assert payload["overall"] == "fail"
    assert sources_of(payload) == {"cpp_cli": "fail", "official_scitt": "pass"}


def test_wrong_msrc_root_fails_the_chain_check(
    harness: Harness, verified_bundle: bytes
) -> None:
    """Trust material really is used, not assumed."""
    response = harness.verify(
        verified_bundle, msrc_root=b"-----BEGIN NOT A CERT-----\nx\n"
    )
    payload = response.json()["report"]
    assert checks_of(payload)["msrc_chain"] == "fail"
    assert payload["overall"] == "fail"


def test_extraction_failure_leaves_the_receipt_unresolved(
    harness: Harness, verified_bundle: bytes
) -> None:
    """If the exact bytes cannot be read out, nothing may claim a pass."""
    os.environ["FAKE_CLI_FAIL"] = "bundle extract"
    try:
        response = harness.verify(verified_bundle)
    finally:
        os.environ.pop("FAKE_CLI_FAIL", None)

    payload = response.json()["report"]
    assert checks_of(payload)[SCITT_CHECK] == "unknown"
    assert payload["overall"] != "pass"
    assert harness.official.calls == []


def test_report_is_exported_and_re_imported_without_loss(
    harness: Harness, verified_bundle: bytes
) -> None:
    """A stored report round-trips through export and import unchanged."""
    response = harness.verify(verified_bundle)
    payload = response.json()
    report_id = payload["report_id"]

    exported = harness.web.get(f"/api/verifier/reports/{report_id}")
    assert exported.status_code == 200
    assert exported.json() == payload["report"]

    download = harness.web.get(f"/api/verifier/reports/{report_id}/download")
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]

    imported = harness.web.post(
        "/api/verifier/reports/import",
        files={"report": ("report.json", download.content, "application/json")},
    )
    assert imported.status_code == 200
    assert imported.json() == payload["report"]


def test_imported_report_cannot_claim_an_unearned_pass(harness: Harness) -> None:
    """An edited export is re-scored from its own checks."""
    forged = {
        "overall": "pass",
        "checks": [{"id": name, "label": name, "status": "pass"} for name in CLI_CHECKS]
        + [{"id": SCITT_CHECK, "label": SCITT_CHECK, "status": "fail"}],
        "sources": [{"id": "official_scitt", "label": "x", "status": "fail"}],
    }
    response = harness.web.post(
        "/api/verifier/reports/import",
        files={
            "report": (
                "report.json",
                json.dumps(forged).encode("utf-8"),
                "application/json",
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["overall"] == "fail"


def test_imported_report_missing_the_receipt_is_not_a_pass(
    harness: Harness,
) -> None:
    """Dropping the receipt check does not turn a report into a pass."""
    forged = {
        "overall": "pass",
        "checks": [
            {"id": name, "label": name, "status": "pass"} for name in CLI_CHECKS
        ],
    }
    response = harness.web.post(
        "/api/verifier/reports/import",
        files={
            "report": (
                "report.json",
                json.dumps(forged).encode("utf-8"),
                "application/json",
            )
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert SCITT_CHECK not in checks_of(payload)
    assert len(payload["checks"]) == 4


def test_import_rejects_a_non_json_upload(harness: Harness) -> None:
    """Malformed exports are refused."""
    response = harness.web.post(
        "/api/verifier/reports/import",
        files={"report": ("report.json", b"not json", "application/json")},
    )
    assert response.status_code == 400


def test_export_rejects_a_traversal_identifier(harness: Harness) -> None:
    """Report identifiers are validated before any filesystem access."""
    for candidate in ("../../etc/passwd", "..", "%2e%2e%2f", "a" * 33):
        response = harness.web.get(f"/api/verifier/reports/{candidate}")
        assert response.status_code in {400, 404}, candidate


def test_verify_rejects_an_oversized_bundle(harness: Harness) -> None:
    """Uploads are bounded before anything is written."""
    oversized = b"x" * (harness.settings.max_bundle_bytes + 1)
    response = harness.verify(oversized)
    assert response.status_code == 400
    assert "limit" in response.json()["message"].lower()


def test_verify_rejects_a_bundle_with_a_path_in_its_name(harness: Harness) -> None:
    """Upload file names may not contain a path."""
    response = harness.web.post(
        "/api/verifier/verify",
        files={
            "bundle": ("../../evil.cbor", b"payload", "application/cbor"),
            "msrc_root": ("root.pem", ROOT_CERT, "application/x-pem-file"),
            "scitt_trust": ("keys.cbor", SCITT_TRUST, "application/cbor"),
        },
    )
    assert response.status_code == 400


def test_verify_rejects_an_unexpected_extension(harness: Harness) -> None:
    """Only the declared artifact kinds are accepted."""
    response = harness.web.post(
        "/api/verifier/verify",
        files={
            "bundle": ("bundle.exe", b"payload", "application/cbor"),
            "msrc_root": ("root.pem", ROOT_CERT, "application/x-pem-file"),
            "scitt_trust": ("keys.cbor", SCITT_TRUST, "application/cbor"),
        },
    )
    assert response.status_code == 400
