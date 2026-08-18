# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""MSRC role tests: import, inspect, select and export presentations."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import Harness

BODY = "abcdefghijklmnopqrstuvwx"
CHUNK_SIZE = 6


@pytest.fixture
def stored_submission(harness: Harness) -> dict[str, Any]:
    """Run a complete submission and return its identifiers."""
    enrollment = harness.enroll()
    response = harness.submit(enrollment, body=BODY)
    assert response.status_code == 200, response.text
    payload: dict[str, Any] = response.json()
    return payload


def inspect_submission(harness: Harness, msrc_submission_id: str) -> dict[str, Any]:
    """Import a stored MSRC submission through the MSRC role."""
    response = harness.web.post(f"/api/msrc/submissions/{msrc_submission_id}/inspect")
    assert response.status_code == 200, response.text
    document: dict[str, Any] = response.json()
    return document


def test_msrc_lists_the_stored_submissions(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """The MSRC role sees what the mock service holds."""
    response = harness.web.get("/api/msrc/submissions")
    assert response.status_code == 200, response.text
    submissions = response.json()["submissions"]
    assert len(submissions) == 1
    assert submissions[0]["submission_id"] == stored_submission["msrc_submission_id"]
    assert submissions[0]["scitt_txid"] == stored_submission["scitt"]["txid"]


def test_inspection_reports_whole_fields_and_stable_chunks(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Fields are whole and body chunks are six code points wide."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    inspection = document["inspection"]
    assert inspection["chunk_size"] == CHUNK_SIZE

    names = [field["name"] for field in inspection["fields"]]
    assert names == ["title", "component", "severity", "fingerprint", "references"]
    assert all(field["disclosed"] for field in inspection["fields"])

    chunks = inspection["body_chunks"]
    assert [chunk["index"] for chunk in chunks] == list(range(4))
    assert [chunk["text"] for chunk in chunks] == [
        "abcdef",
        "ghijkl",
        "mnopqr",
        "stuvwx",
    ]
    assert all(len(chunk["text"]) <= CHUNK_SIZE for chunk in chunks)
    assert "".join(chunk["text"] for chunk in chunks) == BODY


def test_chunk_indices_are_stable_across_repeated_inspections(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Toggling relies on indices that never move between inspections."""
    first = inspect_submission(harness, stored_submission["msrc_submission_id"])
    second = inspect_submission(harness, stored_submission["msrc_submission_id"])
    assert first["inspection"]["body_chunks"] == second["inspection"]["body_chunks"]
    assert first["bundle_id"] != second["bundle_id"]


def test_presentation_drops_the_selected_field_and_chunks(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """A selection removes whole fields and the chosen chunks only."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    bundle_id = document["bundle_id"]

    response = harness.web.post(
        f"/api/msrc/imports/{bundle_id}/present",
        json={"redact_fields": ["fingerprint"], "redact_body_chunks": [1, 2]},
    )
    assert response.status_code == 200, response.text
    presentation = response.json()
    assert presentation["redacted_fields"] == ["fingerprint"]
    assert presentation["redacted_body_chunks"] == [1, 2]

    exported = harness.web.get(presentation["download_url"])
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]

    reimported = harness.web.post(
        "/api/msrc/inspect",
        files={"bundle": ("presented.cbor", exported.content, "application/cbor")},
    )
    assert reimported.status_code == 200, reimported.text
    inspection = reimported.json()["inspection"]

    fields = {field["name"]: field for field in inspection["fields"]}
    assert fields["fingerprint"]["disclosed"] is False
    assert fields["fingerprint"]["value"] is None
    assert fields["title"]["disclosed"] is True
    assert fields["title"]["value"]

    chunks = {chunk["index"]: chunk for chunk in inspection["body_chunks"]}
    assert [index for index, chunk in chunks.items() if not chunk["disclosed"]] == [
        1,
        2,
    ]
    assert chunks[0]["text"] == "abcdef"
    assert chunks[3]["text"] == "stuvwx"
    assert chunks[1]["text"] == ""


def test_presentation_selection_is_cumulative(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Presenting a presented bundle can only remove more, never restore."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    first = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": ["severity"], "redact_body_chunks": [0]},
    ).json()
    exported = harness.web.get(first["download_url"]).content

    reimported = harness.web.post(
        "/api/msrc/inspect",
        files={"bundle": ("presented.cbor", exported, "application/cbor")},
    ).json()
    second = harness.web.post(
        f"/api/msrc/imports/{reimported['bundle_id']}/present",
        json={"redact_fields": [], "redact_body_chunks": [3]},
    ).json()

    final = harness.web.post(
        "/api/msrc/inspect",
        files={
            "bundle": (
                "presented.cbor",
                harness.web.get(second["download_url"]).content,
                "application/cbor",
            )
        },
    ).json()["inspection"]

    fields = {field["name"]: field["disclosed"] for field in final["fields"]}
    assert fields["severity"] is False
    hidden = [
        chunk["index"] for chunk in final["body_chunks"] if not chunk["disclosed"]
    ]
    assert hidden == [0, 3]


def test_empty_selection_is_accepted(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Exporting without redacting anything is a valid presentation."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    response = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": [], "redact_body_chunks": []},
    )
    assert response.status_code == 200
    assert response.json()["redacted_fields"] == []


def test_selection_rejects_unknown_keys(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """The selection document has a closed shape."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    response = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": [], "redact_body_chunks": [], "redact_all": True},
    )
    assert response.status_code == 400


def test_selection_rejects_negative_chunk_indices(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Indices are validated before reaching the tool."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    response = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": [], "redact_body_chunks": [-1]},
    )
    assert response.status_code == 400


def test_selection_rejects_an_oversized_chunk_list(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Selections are bounded."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    response = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": [], "redact_body_chunks": list(range(100000))},
    )
    assert response.status_code == 400


def test_selection_deduplicates_and_sorts_chunk_indices(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """Repeated toggles collapse into one stable selection."""
    document = inspect_submission(harness, stored_submission["msrc_submission_id"])
    response = harness.web.post(
        f"/api/msrc/imports/{document['bundle_id']}/present",
        json={"redact_fields": ["title", "title"], "redact_body_chunks": [2, 0, 2]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["redacted_fields"] == ["title"]
    assert payload["redacted_body_chunks"] == [0, 2]


def test_present_rejects_an_unknown_import(harness: Harness) -> None:
    """A presentation needs a real imported bundle."""
    response = harness.web.post(
        f"/api/msrc/imports/{'0' * 32}/present",
        json={"redact_fields": [], "redact_body_chunks": []},
    )
    assert response.status_code == 404


def test_present_rejects_a_traversal_identifier(harness: Harness) -> None:
    """Identifiers never reach the filesystem unvalidated."""
    response = harness.web.post(
        "/api/msrc/imports/..%2F..%2Fetc/present",
        json={"redact_fields": [], "redact_body_chunks": []},
    )
    assert response.status_code in {400, 404}


def test_inspect_rejects_an_oversized_upload(harness: Harness) -> None:
    """Imports are bounded before anything is stored."""
    response = harness.web.post(
        "/api/msrc/inspect",
        files={
            "bundle": (
                "bundle.cbor",
                b"x" * (harness.settings.max_bundle_bytes + 1),
                "application/cbor",
            )
        },
    )
    assert response.status_code == 400


def test_inspect_rejects_an_empty_upload(harness: Harness) -> None:
    """An empty import is refused."""
    response = harness.web.post(
        "/api/msrc/inspect",
        files={"bundle": ("bundle.cbor", b"", "application/cbor")},
    )
    assert response.status_code == 400


def test_mock_msrc_presentation_export(
    harness: Harness, stored_submission: dict[str, Any]
) -> None:
    """The mock service can also present a submission it holds."""
    submission_id = stored_submission["msrc_submission_id"]
    response = harness.mock.post(
        f"/submissions/{submission_id}/present",
        json={"redact_fields": ["component"], "redact_body_chunks": [0]},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    exported = harness.mock.get(payload["download_url"])
    assert exported.status_code == 200
    assert exported.content

    listing = harness.mock.get(f"/submissions/{submission_id}")
    assert listing.json()["presentations"] == [payload["presentation_id"]]


def test_mock_msrc_rejects_an_unknown_submission(harness: Harness) -> None:
    """Unknown identifiers are refused, not guessed at."""
    response = harness.mock.get(f"/submissions/{'0' * 32}")
    assert response.status_code == 404
