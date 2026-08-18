#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A deterministic stand-in for the official SCITT verifier wrapper.

The real wrapper, ``demo/official_verify.py``, runs inside the pinned
``scitt-ccf-ledger`` submodule's own virtual environment and calls
``pyscitt.verify.verify_transparent_statement``. This double mimics only its
command line contract and its JSON output so that the control plane can be
exercised without the submodule, Docker or any COSE library.

It also records every invocation into ``FAKE_OFFICIAL_LOG`` so that tests can
assert on the exact bytes that were handed to the official verifier.

Behaviour is driven by environment variables:

``FAKE_OFFICIAL_RESULT``
    ``pass`` (default), ``fail``, ``crash``, ``garbage`` or ``timeout``.
``FAKE_OFFICIAL_LOG``
    Path of a JSON lines file recording each invocation.
``FAKE_OFFICIAL_SLEEP``
    Seconds to sleep before doing any work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _record(entry: dict[str, Any]) -> None:
    log_path = os.environ.get("FAKE_OFFICIAL_LOG", "")
    if not log_path:
        return
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _emit(status: str, detail: str, receipts: list[dict[str, Any]]) -> int:
    sys.stdout.write(
        json.dumps(
            {"status": status, "detail": detail, "receipts": receipts},
            sort_keys=True,
        )
    )
    return 0 if status == "pass" else 1


def main(argv: list[str] | None = None) -> int:
    """Run the test double."""
    parser = argparse.ArgumentParser(prog="official_verify.py")
    parser.add_argument("--registered", required=True)
    parser.add_argument("--transparent", required=True)
    parser.add_argument("--trust-store", required=True)
    args = parser.parse_args(argv)

    delay = os.environ.get("FAKE_OFFICIAL_SLEEP", "")
    if delay:
        time.sleep(float(delay))

    registered = Path(args.registered).read_bytes()
    transparent = Path(args.transparent).read_bytes()
    trust_dir = Path(args.trust_store)
    trust_files = sorted(item.name for item in trust_dir.iterdir() if item.is_file())

    _record(
        {
            "registered_sha256": _digest(registered),
            "registered_bytes": len(registered),
            "transparent_sha256": _digest(transparent),
            "transparent_bytes": len(transparent),
            "trust_store": str(trust_dir),
            "trust_files": trust_files,
            "trust_sha256": {
                name: _digest((trust_dir / name).read_bytes()) for name in trust_files
            },
        }
    )

    outcome = os.environ.get("FAKE_OFFICIAL_RESULT", "pass")
    if outcome == "crash":
        sys.stderr.write("simulated official verifier crash\n")
        return 2
    if outcome == "garbage":
        sys.stdout.write("this is not JSON")
        return 0
    if outcome == "timeout":
        time.sleep(30)
        return 0

    if not trust_files:
        return _emit(
            "fail",
            "The trust store directory contains no service keys.",
            [],
        )
    if not registered or not transparent:
        return _emit("fail", "The statement bytes are empty.", [])

    if outcome == "fail":
        return _emit(
            "fail",
            "Receipt verification failed: simulated signature mismatch.",
            [],
        )
    return _emit(
        "pass",
        (
            "1 receipt verified against the registered statement "
            f"({_digest(registered)[:16]})."
        ),
        [{"service_id": "fake-scitt", "registered_sha256": _digest(registered)}],
    )


if __name__ == "__main__":
    sys.exit(main())
