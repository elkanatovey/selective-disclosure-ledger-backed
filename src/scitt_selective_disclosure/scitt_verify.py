# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Adapter for the official SCITT receipt verifier.

Receipt verification is not implemented here, and it is not implemented by the
C++ core either. It is delegated to the official
``pyscitt.verify.verify_transparent_statement`` from the pinned
``scitt-ccf-ledger`` submodule, which runs in that submodule's own virtual
environment.

This module only:

* writes the exact registered statement bytes, the exact transparent statement
  bytes and the independently obtained trust store into a private directory;
* runs a fixed argument vector:
  ``<submodule venv python> demo/official_verify.py --registered ...
  --transparent ... --trust-store ...``;
* reads the JSON document the wrapper prints on standard output.

The wrapper's transitive dependency on ``pycose`` and ``cbor2`` belongs to that
isolated upstream tooling. This application and the SD-CWT core use CCF's
EverCBOR-backed ``ccf::cbor`` and CCF crypto instead.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .config import Settings
from .errors import truncate_detail
from .models import CheckStatus
from .workspace import secure_workspace, write_private_file

MAX_OUTPUT_CHARS = 4000
TRUST_STORE_DIR = "scitt-trust"
COSE_KEY_SET_NAME = "scitt-keys.cbor"
LEGACY_TRUST_NAME = "service-parameters.json"


@dataclass(frozen=True)
class OfficialResult:
    """The outcome of one official transparent statement verification."""

    status: CheckStatus
    detail: str
    receipts: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        """Return whether the official verifier accepted the receipts."""
        return self.status == "pass"


class OfficialVerifier(Protocol):
    """Verifies a transparent statement against exact registered bytes."""

    @property
    def available(self) -> bool:
        """Return whether the upstream tooling looks runnable."""
        raise NotImplementedError

    def verify(
        self, *, registered: bytes, transparent: bytes, trust_store: bytes, name: str
    ) -> OfficialResult:
        """Return the official verification outcome for these exact bytes."""
        raise NotImplementedError


def trust_store_file_name(source_name: str) -> str:
    """Return the file name to store imported trust material under.

    ``StaticTrustStore.load`` reads ``*.cbor`` COSE key sets, as published by
    ``/.well-known/scitt-keys``, and ``*.json`` service parameter documents.
    Anything else is stored as a COSE key set, which is what the demo fetches.
    """
    suffix = Path(source_name).suffix.lower()
    if suffix == ".json":
        return LEGACY_TRUST_NAME
    return COSE_KEY_SET_NAME


class ScittVerifier:
    """Runs the official verifier wrapper in the pinned submodule venv."""

    def __init__(
        self,
        python: Path,
        wrapper: Path,
        *,
        timeout: float = 120.0,
    ) -> None:
        self.python = python
        self.wrapper = wrapper
        self.timeout = timeout

    @classmethod
    def from_settings(cls, settings: Settings) -> ScittVerifier:
        """Build a verifier from the configured submodule paths."""
        return cls(
            settings.scitt_verifier_python,
            settings.scitt_verifier_wrapper,
            timeout=settings.scitt_verifier_timeout,
        )

    @property
    def available(self) -> bool:
        """Return whether the submodule venv and wrapper both exist."""
        return self.python.is_file() and self.wrapper.is_file()

    def _unavailable(self) -> OfficialResult:
        return OfficialResult(
            status="skipped",
            detail=(
                "The official SCITT verifier is not installed. Expected the "
                f"pinned submodule interpreter at '{self.python}' and the "
                f"wrapper at '{self.wrapper}'. Run demo/run.sh to create them."
            ),
        )

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argument vector
            [str(self.python), str(self.wrapper), *args],
            capture_output=True,
            timeout=self.timeout,
            check=False,
            text=True,
            errors="replace",
        )

    def verify(
        self, *, registered: bytes, transparent: bytes, trust_store: bytes, name: str
    ) -> OfficialResult:
        """Verify a transparent statement against exact registered bytes."""
        if not self.available:
            return self._unavailable()
        with secure_workspace(prefix="sdc-scitt-") as workspace:
            registered_path = write_private_file(
                workspace / "registered.cose", registered
            )
            transparent_path = write_private_file(
                workspace / "transparent.cose", transparent
            )
            trust_dir = workspace / TRUST_STORE_DIR
            trust_dir.mkdir(mode=0o700)
            write_private_file(trust_dir / trust_store_file_name(name), trust_store)
            try:
                completed = self._run(
                    [
                        "--registered",
                        str(registered_path),
                        "--transparent",
                        str(transparent_path),
                        "--trust-store",
                        str(trust_dir),
                    ]
                )
            except OSError as error:
                return OfficialResult(
                    status="unknown",
                    detail=truncate_detail(
                        "The official SCITT verifier could not be started: "
                        f"{type(error).__name__}: {error}",
                        MAX_OUTPUT_CHARS,
                    ),
                )
            except subprocess.TimeoutExpired:
                return OfficialResult(
                    status="unknown",
                    detail=(
                        "The official SCITT verifier exceeded "
                        f"{self.timeout:g} seconds."
                    ),
                )
        return parse_official_output(
            completed.returncode, completed.stdout, completed.stderr
        )


def parse_official_output(returncode: int, stdout: str, stderr: str) -> OfficialResult:
    """Normalise the wrapper's JSON document into a check result.

    A wrapper that fails to produce JSON is never reported as a pass: the
    result is ``unknown`` and carries the captured diagnostics.
    """
    try:
        document = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return OfficialResult(
            status="unknown",
            detail=truncate_detail(
                "The official SCITT verifier did not return a JSON result "
                f"(exit {returncode}): {stderr or stdout or 'no output'}",
                MAX_OUTPUT_CHARS,
            ),
        )
    if not isinstance(document, dict):
        return OfficialResult(
            status="unknown",
            detail="The official SCITT verifier returned an unexpected result.",
        )

    raw_status = document.get("status")
    status: CheckStatus
    if raw_status == "pass" and returncode == 0:
        status = "pass"
    elif raw_status == "fail":
        status = "fail"
    else:
        status = "unknown"

    detail = document.get("detail")
    receipts = document.get("receipts")
    return OfficialResult(
        status=status,
        detail=truncate_detail(
            (
                str(detail)
                if detail
                else "The official SCITT verifier reported no detail."
            ),
            MAX_OUTPUT_CHARS,
        ),
        receipts=(
            tuple(item for item in receipts if isinstance(item, dict))
            if isinstance(receipts, list)
            else ()
        ),
    )
