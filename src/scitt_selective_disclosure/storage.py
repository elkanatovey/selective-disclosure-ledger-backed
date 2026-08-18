# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Opaque, traversal-safe storage for demo artifacts.

Artifacts are stored as bytes. Nothing in this module inspects or decodes
security artifacts; the store only moves opaque files and small JSON metadata
documents written by the control plane.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import CapacityError, NotFoundError, RequestError
from .workspace import DIRECTORY_MODE

RECORD_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
COLLECTION_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ARTIFACT_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}\.[a-z0-9]{1,8}$")
ARTIFACT_FILE_MODE = 0o600
DEFAULT_MAX_RECORDS = 500


def new_record_id() -> str:
    """Return an opaque, unguessable record identifier."""
    return secrets.token_hex(16)


def validate_record_id(record_id: str) -> str:
    """Return the identifier if it is a well formed opaque record id."""
    if not RECORD_ID_PATTERN.fullmatch(record_id):
        raise RequestError("Invalid record identifier.")
    return record_id


def _validate_collection(collection: str) -> str:
    if not COLLECTION_PATTERN.fullmatch(collection):
        raise RequestError("Invalid record collection.")
    return collection


def _validate_artifact_name(name: str) -> str:
    if not ARTIFACT_NAME_PATTERN.fullmatch(name):
        raise RequestError("Invalid artifact name.")
    return name


@dataclass(frozen=True)
class RecordInfo:
    """Metadata about a stored record."""

    record_id: str
    created_at: float
    artifacts: tuple[str, ...]


class Store:
    """A directory of opaque artifacts addressed by generated identifiers."""

    def __init__(self, root: Path, *, max_records: int = DEFAULT_MAX_RECORDS) -> None:
        self.root = root
        self.max_records = max_records

    def _collection_dir(self, collection: str) -> Path:
        path = self.root / _validate_collection(collection)
        path.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
        return path

    def count_records(self, collection: str) -> int:
        """Return how many records a collection currently holds."""
        directory = self._collection_dir(collection)
        return sum(
            1
            for child in directory.iterdir()
            if child.is_dir() and RECORD_ID_PATTERN.fullmatch(child.name)
        )

    def record_dir(self, collection: str, record_id: str) -> Path:
        """Return the directory for a record, creating it when needed."""
        path = self._collection_dir(collection) / validate_record_id(record_id)
        path.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
        return path

    def create_record(self, collection: str) -> str:
        """Create an empty record and return its identifier.

        The store is bounded so that a demo deployment cannot be filled up by
        repeated submissions. When the bound is reached new records are
        refused rather than old ones being silently discarded.
        """
        if self.count_records(collection) >= self.max_records:
            raise CapacityError(
                "This demo store is full.",
                detail=(
                    f"The '{collection}' collection already holds "
                    f"{self.max_records} records, which is the configured "
                    "limit. Clear the data directory to continue."
                ),
            )
        record_id = new_record_id()
        self.record_dir(collection, record_id)
        return record_id

    def exists(self, collection: str, record_id: str) -> bool:
        """Return whether a record directory exists."""
        path = self._collection_dir(collection) / validate_record_id(record_id)
        return path.is_dir()

    def require(self, collection: str, record_id: str) -> Path:
        """Return an existing record directory or raise ``NotFoundError``."""
        path = self._collection_dir(collection) / validate_record_id(record_id)
        if not path.is_dir():
            raise NotFoundError("Record not found.")
        return path

    def write_bytes(
        self, collection: str, record_id: str, name: str, payload: bytes
    ) -> Path:
        """Atomically write an opaque artifact into a record."""
        directory = self.record_dir(collection, record_id)
        target = directory / _validate_artifact_name(name)
        handle = tempfile.NamedTemporaryFile(
            dir=directory, prefix=".tmp-", delete=False
        )
        try:
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(handle.name, ARTIFACT_FILE_MODE)
            os.replace(handle.name, target)
        except BaseException:
            try:
                os.unlink(handle.name)
            except OSError:
                pass
            raise
        return target

    def write_json(
        self, collection: str, record_id: str, name: str, payload: Mapping[str, Any]
    ) -> Path:
        """Atomically write a small JSON metadata document."""
        encoded = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        return self.write_bytes(collection, record_id, name, encoded)

    def read_bytes(self, collection: str, record_id: str, name: str) -> bytes:
        """Return an opaque artifact, or raise ``NotFoundError``."""
        path = self.require(collection, record_id) / _validate_artifact_name(name)
        try:
            return path.read_bytes()
        except OSError as error:
            raise NotFoundError("Artifact not found.", detail=str(error)) from error

    def read_json(self, collection: str, record_id: str, name: str) -> dict[str, Any]:
        """Return a stored JSON metadata document."""
        raw = self.read_bytes(collection, record_id, name)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NotFoundError("Stored metadata is unreadable.") from error
        if not isinstance(document, dict):
            raise NotFoundError("Stored metadata is unreadable.")
        return document

    def has_artifact(self, collection: str, record_id: str, name: str) -> bool:
        """Return whether an artifact exists inside a record."""
        if not self.exists(collection, record_id):
            return False
        path = self.record_dir(collection, record_id) / _validate_artifact_name(name)
        return path.is_file()

    def list_records(self, collection: str, limit: int = 200) -> list[RecordInfo]:
        """Return records in a collection, newest first."""
        directory = self._collection_dir(collection)
        records: list[RecordInfo] = []
        for child in directory.iterdir():
            if not child.is_dir() or not RECORD_ID_PATTERN.fullmatch(child.name):
                continue
            artifacts = tuple(
                sorted(item.name for item in child.iterdir() if item.is_file())
            )
            records.append(
                RecordInfo(
                    record_id=child.name,
                    created_at=child.stat().st_mtime,
                    artifacts=artifacts,
                )
            )
        records.sort(key=lambda item: (item.created_at, item.record_id), reverse=True)
        return records[:limit]
