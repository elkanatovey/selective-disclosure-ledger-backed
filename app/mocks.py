# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""In-process stand-ins for MSRC and a SCITT transparency service.

Neither is real. The mock ledger has no log, no inclusion proof and no
consistency proof: it signs a receipt over the exact registered statement so
the demo carries the right shape without running a ledger.
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
        # The key MSRC signs disclosure releases with. Deliberately not the CA
        # key: releasing what a report said is a different authority from
        # endorsing who wrote it.
        self._disclosure_key = _native.generate_private_key()
        self.disclosure_public_key: bytes = _native.derive_public_key(
            self._disclosure_key
        )
        self.enrollments: dict[str, Enrollment] = {}
        self.submissions: dict[str, Submission] = {}

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

    def sign_release(self, bundle: bytes) -> bytes:
        """Sign a redacted presentation with the key named in cnf."""
        release: bytes = _native.sign_release(bundle, self._disclosure_key)
        return release


class MockScitt:
    """Signs a receipt over the exact registered statement. Not a ledger."""

    def __init__(self) -> None:
        self._key = _native.generate_private_key()
        self._sequence = 0

    def register(self, statement: bytes) -> tuple[str, bytes]:
        """Return a transaction id and the statement with its receipt."""
        self._sequence += 1
        txid = f"2.{self._sequence}"
        registered = _native.mock_register_statement(statement, self._key)
        return txid, registered["transparent_statement"]


def evict(records: dict[str, _Record]) -> None:
    # The demo keeps everything in memory, so the oldest record goes rather
    # than letting a caller grow the process without bound.
    while len(records) >= MAX_RECORDS:
        records.pop(next(iter(records)))
