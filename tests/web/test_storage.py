# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Storage tests: traversal safety, atomicity and bounds."""

from __future__ import annotations

from pathlib import Path

import pytest

from scitt_selective_disclosure.errors import CapacityError, NotFoundError, RequestError
from scitt_selective_disclosure.storage import Store, new_record_id, validate_record_id


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """A store rooted in an empty directory."""
    return Store(tmp_path / "data")


TRAVERSAL_IDS = (
    "../../etc/passwd",
    "..",
    ".",
    "",
    "/etc/passwd",
    "a" * 31,
    "a" * 33,
    "0123456789ABCDEF0123456789abcdef",
    "0123456789abcdef0123456789abcde/",
    "0123456789abcdef0123456789abcd..",
)

TRAVERSAL_NAMES = (
    "../evil.json",
    "..",
    "/etc/passwd",
    "sub/dir.json",
    ".hidden.json",
    "no-suffix",
    "name.toolongsuffix",
    "\x00.json",
)


@pytest.mark.parametrize("candidate", TRAVERSAL_IDS)
def test_record_identifiers_reject_traversal(candidate: str) -> None:
    """Only opaque hexadecimal identifiers are accepted."""
    with pytest.raises(RequestError):
        validate_record_id(candidate)


@pytest.mark.parametrize("candidate", TRAVERSAL_NAMES)
def test_artifact_names_reject_traversal(store: Store, candidate: str) -> None:
    """Artifact names may not escape their record directory."""
    record = store.create_record("reports")
    with pytest.raises(RequestError):
        store.write_bytes("reports", record, candidate, b"payload")


@pytest.mark.parametrize("candidate", ("../evil", "Reports", "1reports", "a" * 33, ""))
def test_collection_names_reject_traversal(store: Store, candidate: str) -> None:
    """Collection names are a closed vocabulary."""
    with pytest.raises(RequestError):
        store.create_record(candidate)


def test_write_and_read_round_trip(store: Store) -> None:
    """Opaque bytes survive a round trip unchanged."""
    record = store.create_record("reports")
    payload = bytes(range(256))
    store.write_bytes("reports", record, "artifact.cbor", payload)
    assert store.read_bytes("reports", record, "artifact.cbor") == payload


def test_written_files_are_private_and_atomic(store: Store) -> None:
    """No temporary file is left behind and the mode is restrictive."""
    record = store.create_record("reports")
    path = store.write_bytes("reports", record, "artifact.cbor", b"payload")
    assert path.stat().st_mode & 0o777 == 0o600
    leftovers = [item for item in path.parent.iterdir() if item.name.startswith(".tmp")]
    assert leftovers == []


def test_overwrite_replaces_the_previous_contents(store: Store) -> None:
    """A rewrite is a replacement, not an append."""
    record = store.create_record("reports")
    store.write_bytes("reports", record, "artifact.cbor", b"first")
    store.write_bytes("reports", record, "artifact.cbor", b"second")
    assert store.read_bytes("reports", record, "artifact.cbor") == b"second"


def test_reading_an_unknown_record_raises(store: Store) -> None:
    """Missing records are reported, never invented."""
    with pytest.raises(NotFoundError):
        store.read_bytes("reports", new_record_id(), "artifact.cbor")


def test_reading_an_unknown_artifact_raises(store: Store) -> None:
    """Missing artifacts are reported."""
    record = store.create_record("reports")
    with pytest.raises(NotFoundError):
        store.read_bytes("reports", record, "artifact.cbor")


def test_unreadable_metadata_is_reported(store: Store) -> None:
    """Corrupt metadata never surfaces as a partially decoded document."""
    record = store.create_record("reports")
    store.write_bytes("reports", record, "meta.json", b"\xff\xfe not json")
    with pytest.raises(NotFoundError):
        store.read_json("reports", record, "meta.json")


def test_non_object_metadata_is_reported(store: Store) -> None:
    """A JSON array is not acceptable metadata."""
    record = store.create_record("reports")
    store.write_bytes("reports", record, "meta.json", b"[1, 2, 3]")
    with pytest.raises(NotFoundError):
        store.read_json("reports", record, "meta.json")


def test_store_is_bounded(tmp_path: Path) -> None:
    """A bounded store refuses new records rather than evicting old ones."""
    store = Store(tmp_path / "data", max_records=3)
    created = [store.create_record("reports") for _ in range(3)]
    assert len(set(created)) == 3
    with pytest.raises(CapacityError) as error:
        store.create_record("reports")
    assert "full" in str(error.value)
    assert store.count_records("reports") == 3
    for record in created:
        assert store.exists("reports", record)


def test_bounds_are_per_collection(tmp_path: Path) -> None:
    """One saturated collection does not block another."""
    store = Store(tmp_path / "data", max_records=1)
    store.create_record("reports")
    assert store.create_record("imports")
    with pytest.raises(CapacityError):
        store.create_record("reports")


def test_listing_is_newest_first_and_bounded(store: Store) -> None:
    """Listings are ordered and truncated."""
    records = [store.create_record("reports") for _ in range(5)]
    for index, record in enumerate(records):
        store.write_bytes("reports", record, "meta.json", b"{}")
        path = store.record_dir("reports", record)
        import os

        os.utime(path, (1000 + index, 1000 + index))

    listing = store.list_records("reports")
    assert [item.record_id for item in listing] == list(reversed(records))
    assert store.list_records("reports", limit=2) == listing[:2]
    assert listing[0].artifacts == ("meta.json",)


def test_listing_ignores_unexpected_directories(store: Store) -> None:
    """Only well formed record directories are listed."""
    record = store.create_record("reports")
    (store.root / "reports" / "not-a-record").mkdir()
    (store.root / "reports" / "stray.txt").write_bytes(b"x")
    listing = store.list_records("reports")
    assert [item.record_id for item in listing] == [record]


def test_has_artifact_is_false_for_unknown_records(store: Store) -> None:
    """Presence checks never create records implicitly."""
    assert store.has_artifact("reports", new_record_id(), "meta.json") is False
