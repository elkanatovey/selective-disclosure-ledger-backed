# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""An in-process stand-in for MSRC.

MSRC is mocked because this demo is about what a researcher and MSRC do with a
statement, not about how MSRC runs a PKI. The transparency service is NOT
mocked: statements are registered with a real one, because a receipt nobody
could check would make the whole exercise pointless.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TypeVar

import _native

MAX_RECORDS = 256

_Record = TypeVar("_Record")


@dataclass(frozen=True)
class Enrollment:
    enrollment_id: str
    subject: str
    public_key: bytes
    leaf_cert: bytes


@dataclass(frozen=True)
class Submission:
    submission_id: str
    title: str
    txid: str
    bundle: bytes


def _new_id() -> str:
    return secrets.token_hex(8)


class MockMsrc:
    """Endorses reporter public keys and receives proof bundles."""

    def __init__(self) -> None:
        identity = _native.create_root_identity()
        self._root_key = identity["private_key"]
        self.root_cert: bytes = identity["certificate"]
        self.issuer_did: str = identity["issuer_did"]
        # The public half of the key MSRC will sign disclosure releases with.
        # MSRC keeps the private half on its own page and publishes this so
        # statements can name it; the transparency service never sees it and
        # nothing about it is registered anywhere. Until MSRC publishes one,
        # statements carry no cnf claim and a release cannot be attributed.
        self.disclosure_public_key: bytes = b""
        self.enrollments: dict[str, Enrollment] = {}
        self.submissions: dict[str, Submission] = {}

    def publish_disclosure_key(self, public_key_pem: bytes) -> None:
        """Make known the key that future statements will name in cnf."""
        self.disclosure_public_key = public_key_pem

    def enroll(self, public_key_pem: bytes, subject: str) -> Enrollment:
        """Endorse a public key. The private half is never sent here."""
        leaf = _native.issue_certificate(self._root_key, self.root_cert, public_key_pem)
        record = Enrollment(_new_id(), subject, public_key_pem, leaf)
        evict(self.enrollments)
        self.enrollments[record.enrollment_id] = record
        return record

    def receive(self, bundle: bytes, title: str, txid: str) -> Submission:
        """Accept the full bundle: disclosures and receipt included."""
        record = Submission(_new_id(), title, txid, bundle)
        evict(self.submissions)
        self.submissions[record.submission_id] = record
        return record


def evict(records: dict[str, _Record]) -> None:
    # The demo keeps everything in memory, so the oldest record goes rather
    # than letting a caller grow the process without bound.
    while len(records) >= MAX_RECORDS:
        records.pop(next(iter(records)))
