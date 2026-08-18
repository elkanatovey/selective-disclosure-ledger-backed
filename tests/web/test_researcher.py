# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Researcher enrollment and one click submission tests."""

from __future__ import annotations

from conftest import PRIVATE_KEY, Harness


def stage_status(payload: dict[str, object], name: str) -> str:
    """Return the reported status of one pipeline stage."""
    stages = payload["stages"]
    assert isinstance(stages, list)
    for stage in stages:
        assert isinstance(stage, dict)
        if stage["name"] == name:
            return str(stage["status"])
    raise AssertionError(f"no stage named {name}")


def test_enrollment_sends_the_public_key_and_never_the_private_key(
    harness: Harness,
) -> None:
    """Only the derived public key leaves the researcher control plane."""
    response = harness.web.post(
        "/api/researcher/enroll",
        data={"subject": "Demo researcher"},
        files={"private_key": ("key.pem", PRIVATE_KEY, "application/x-pem-file")},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["private_key_transmitted"] is False
    assert payload["public_key_bytes"] > 0

    enrollments = [
        item for item in harness.msrc_transport.requests if item.path == "/enroll"
    ]
    assert len(enrollments) == 1
    body = enrollments[0].content
    assert b"PUBLIC KEY" in body
    assert b"PRIVATE" not in body
    assert PRIVATE_KEY not in body


def test_enrollment_rejects_a_public_key_upload(harness: Harness) -> None:
    """The enrollment route needs a private key to derive from."""
    response = harness.web.post(
        "/api/researcher/enroll",
        data={"subject": "Demo researcher"},
        files={
            "private_key": (
                "public.pem",
                b"-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n",
                "application/x-pem-file",
            )
        },
    )
    assert response.status_code in {400, 502}


def test_mock_msrc_enrollment_refuses_a_private_key(harness: Harness) -> None:
    """The mock service accepts public keys only."""
    response = harness.mock.post(
        "/enroll",
        data={"subject": "Demo researcher"},
        files={"public_key": ("key.pem", PRIVATE_KEY, "application/x-pem-file")},
    )
    assert response.status_code == 400
    assert "private" in response.json()["message"].lower()


def test_submission_registers_with_scitt_before_reaching_msrc(
    harness: Harness,
) -> None:
    """The ordered pipeline never sends the report to MSRC first."""
    enrollment = harness.enroll()
    harness.call_log.clear()
    response = harness.submit(enrollment)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "complete"
    assert payload["scitt"]["registered"] is True
    assert payload["scitt"]["txid"]
    assert payload["msrc_submission_id"]

    registration = harness.call_log.index("scitt:POST /entries")
    transparent = harness.call_log.index(
        f"scitt:GET /entries/{harness.scitt.txid}/statement"
    )
    delivery = harness.call_log.index("msrc:POST /submissions")
    assert registration < transparent < delivery
    assert all(
        stage_status(payload, name) == "pass"
        for name in ("issue", "scitt_register", "bundle_create", "msrc_deliver")
    )


def test_submission_registers_the_exact_statement_bytes(harness: Harness) -> None:
    """The bytes posted to SCITT are the stored registered statement."""
    enrollment = harness.enroll()
    response = harness.submit(enrollment)
    submission_id = response.json()["submission_id"]

    stored = harness.web.get(f"/api/researcher/submissions/{submission_id}/statement")
    assert stored.status_code == 200
    assert len(harness.scitt.registrations) == 1
    assert harness.scitt.registrations[0].content == stored.content
    assert harness.scitt.registrations[0].headers["content-type"] == "application/cose"


def test_transparency_token_is_downloadable_verbatim(harness: Harness) -> None:
    """The transparent statement is stored and served byte for byte."""
    enrollment = harness.enroll()
    response = harness.submit(enrollment)
    payload = response.json()
    assert payload["transparent_url"]

    token = harness.web.get(payload["transparent_url"])
    assert token.status_code == 200
    assert token.content == harness.scitt.receipt
    assert token.headers["content-type"] == "application/cose"
    assert "attachment" in token.headers["content-disposition"]


def test_transparency_history_is_retried_before_delivery(harness: Harness) -> None:
    """A transient historical-query delay must not substitute the receipt."""
    enrollment = harness.enroll()
    harness.scitt.historical_unavailable_count = 2

    response = harness.submit(enrollment)

    assert response.status_code == 200, response.text
    statement_reads = [
        request
        for request in harness.scitt.requests
        if request.path == f"/entries/{harness.scitt.txid}/statement"
    ]
    assert len(statement_reads) == 3


def test_transparency_token_is_absent_before_registration(harness: Harness) -> None:
    """A submission that never registered has no token to download."""
    enrollment = harness.enroll()
    harness.scitt.status_code = 503
    response = harness.submit(enrollment)
    submission_id = response.json()["submission_id"]
    token = harness.web.get(f"/api/researcher/submissions/{submission_id}/transparent")
    assert token.status_code == 404


def test_scitt_failure_stops_the_pipeline_before_msrc(harness: Harness) -> None:
    """A refused registration must not leak the report to MSRC."""
    enrollment = harness.enroll()
    harness.call_log.clear()
    harness.scitt.status_code = 503

    response = harness.submit(enrollment)
    assert response.status_code == 502
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["scitt"]["registered"] is False
    assert stage_status(payload, "scitt_register") == "fail"
    assert stage_status(payload, "bundle_create") == "skipped"
    assert stage_status(payload, "msrc_deliver") == "skipped"
    assert not [item for item in harness.call_log if item.startswith("msrc:POST")]
    assert harness.mock_submissions() == []


def test_missing_transaction_identifier_is_a_registration_failure(
    harness: Harness,
) -> None:
    """Without a transaction identifier nothing downstream may run."""
    enrollment = harness.enroll()
    harness.scitt.omit_txid = True
    response = harness.submit(enrollment)
    assert response.status_code == 502
    assert response.json()["scitt"]["registered"] is False
    assert harness.mock_submissions() == []


def test_issue_failure_reports_a_failed_first_stage(harness: Harness) -> None:
    """A tool failure at issuance stops everything."""
    enrollment = harness.enroll()
    harness.call_log.clear()
    monkeypatched = harness.settings.cli_path
    assert monkeypatched.is_file()

    import os

    os.environ["FAKE_CLI_FAIL"] = "issue"
    try:
        response = harness.submit(enrollment)
    finally:
        os.environ.pop("FAKE_CLI_FAIL", None)

    assert response.status_code == 502
    payload = response.json()
    assert stage_status(payload, "issue") == "fail"
    assert stage_status(payload, "scitt_register") == "skipped"
    assert not harness.scitt.registrations
    assert harness.mock_submissions() == []


def test_partial_failure_is_recoverable_by_bundle_download(harness: Harness) -> None:
    """A delivery failure keeps SCITT proof and offers the bundle."""
    enrollment = harness.enroll()
    harness.msrc_transport.failing_paths.add("/submissions")

    response = harness.submit(enrollment)
    assert response.status_code == 207
    payload = response.json()
    assert payload["status"] == "partial"
    assert payload["scitt"]["registered"] is True
    assert stage_status(payload, "scitt_register") == "pass"
    assert stage_status(payload, "bundle_create") == "pass"
    assert stage_status(payload, "msrc_deliver") == "fail"
    assert payload["bundle_url"]
    assert payload["retry_url"]

    bundle = harness.web.get(payload["bundle_url"])
    assert bundle.status_code == 200
    assert bundle.content
    assert "attachment" in bundle.headers["content-disposition"]


def test_second_stage_retry_recovers_without_re_registering(
    harness: Harness,
) -> None:
    """Retrying delivery reuses the stored proof and never re-registers."""
    enrollment = harness.enroll()
    harness.msrc_transport.failing_paths.add("/submissions")
    first = harness.submit(enrollment)
    assert first.status_code == 207
    payload = first.json()
    submission_id = payload["submission_id"]
    original_txid = payload["scitt"]["txid"]
    registrations_before = len(harness.scitt.registrations)

    harness.msrc_transport.failing_paths.clear()
    retry = harness.web.post(payload["retry_url"])
    assert retry.status_code == 200, retry.text
    retried = retry.json()
    assert retried["status"] == "complete"
    assert retried["scitt"]["txid"] == original_txid
    assert retried["msrc_submission_id"]
    assert len(harness.scitt.registrations) == registrations_before

    stored = harness.mock_submissions()
    assert len(stored) == 1
    assert stored[0]["scitt_txid"] == original_txid
    assert harness.stored_bundle(submission_id)


def test_retry_delivers_the_exact_stored_bundle(harness: Harness) -> None:
    """The retried delivery carries the bytes the tool produced."""
    enrollment = harness.enroll()
    harness.msrc_transport.failing_paths.add("/submissions")
    payload = harness.submit(enrollment).json()
    stored = harness.stored_bundle(payload["submission_id"])

    harness.msrc_transport.failing_paths.clear()
    retry = harness.web.post(payload["retry_url"])
    assert retry.status_code == 200

    msrc_id = retry.json()["msrc_submission_id"]
    delivered = harness.mock.get(f"/submissions/{msrc_id}/bundle")
    assert delivered.status_code == 200
    assert delivered.content == stored


def test_retry_refuses_a_submission_that_never_registered(harness: Harness) -> None:
    """Recovery is only offered where transparency proof exists."""
    enrollment = harness.enroll()
    harness.scitt.status_code = 503
    payload = harness.submit(enrollment).json()

    retry = harness.web.post(
        f"/api/researcher/submissions/{payload['submission_id']}/deliver"
    )
    assert retry.status_code == 502
    assert retry.json()["status"] == "failed"
    assert harness.mock_submissions() == []


def test_bundle_creation_failure_is_recoverable(harness: Harness) -> None:
    """A bundle build failure after registration stays recoverable."""
    import os

    enrollment = harness.enroll()
    os.environ["FAKE_CLI_FAIL"] = "bundle create"
    try:
        response = harness.submit(enrollment)
    finally:
        os.environ.pop("FAKE_CLI_FAIL", None)

    assert response.status_code == 207
    payload = response.json()
    assert payload["status"] == "partial"
    assert payload["bundle_url"] is None
    assert payload["retry_url"]

    retry = harness.web.post(payload["retry_url"])
    assert retry.status_code == 200, retry.text
    assert retry.json()["status"] == "complete"


def test_submission_requires_a_prior_enrollment(harness: Harness) -> None:
    """The pipeline refuses to start without an enrollment record."""
    response = harness.submit("0" * 32)
    assert response.status_code == 400
    assert not harness.scitt.registrations


def test_submission_rejects_a_malformed_enrollment_identifier(
    harness: Harness,
) -> None:
    """Identifiers are validated before touching the store."""
    response = harness.submit("../../etc/passwd")
    assert response.status_code == 400


def test_submission_list_reports_stored_state(harness: Harness) -> None:
    """The listing reflects what actually happened."""
    enrollment = harness.enroll()
    harness.submit(enrollment, title="First report")
    harness.msrc_transport.failing_paths.add("/submissions")
    harness.submit(enrollment, title="Second report")

    listing = harness.web.get("/api/researcher/submissions")
    assert listing.status_code == 200
    submissions = listing.json()["submissions"]
    assert len(submissions) == 2
    by_title = {item["title"]: item for item in submissions}
    assert by_title["First report"]["status"] == "complete"
    assert by_title["Second report"]["status"] == "partial"
    assert all(item["scitt_txid"] for item in submissions)
