#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Official SCITT receipt verification, run as upstream tooling.

This wrapper is deliberately placed under ``demo/`` rather than in the
application package: it is orchestration of an upstream tool, not part of the
shipped control plane. It MUST be run with the pinned ``scitt-ccf-ledger``
submodule's own virtual environment interpreter, where ``pyscitt`` and its
transitive ``pycose``/``cbor2`` dependencies are installed.

It implements no verification itself. It calls the official
``pyscitt.verify.verify_transparent_statement`` with:

* the exact transparent statement bytes returned by the transparency service;
* a ``StaticTrustStore`` loaded from an independently fetched
  ``/.well-known/scitt-keys`` trust store directory; and
* the exact registered statement bytes that were submitted for registration.

Because the exact registered bytes are passed in, the receipt is bound to those
bytes. No statement is reconstructed or re-encoded anywhere in this path, which
is why ``scitt validate`` is not used.

Standard output is a single JSON document and nothing else:

    {"status": "pass" | "fail", "detail": "...", "receipts": [...]}

Diagnostics go to standard error. The exit code is 0 for a pass and 1 for a
fail, so a caller can detect a crashed interpreter separately.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any

MAX_DETAIL_CHARS = 2000


def _emit(status: str, detail: str, receipts: list[Any] | None = None) -> int:
    document = {
        "status": status,
        "detail": detail[:MAX_DETAIL_CHARS],
        "receipts": receipts if receipts is not None else [],
    }
    json.dump(document, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if status == "pass" else 1


def _json_safe(value: Any) -> Any:
    """Return a JSON encodable rendering of upstream receipt details."""
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Return the parsed wrapper arguments."""
    parser = argparse.ArgumentParser(
        prog="official_verify.py",
        description="Verify a transparent statement with the official pyscitt.",
    )
    parser.add_argument(
        "--registered",
        type=Path,
        required=True,
        help="File holding the EXACT registered statement bytes.",
    )
    parser.add_argument(
        "--transparent",
        type=Path,
        required=True,
        help="File holding the EXACT transparent statement bytes.",
    )
    parser.add_argument(
        "--trust-store",
        type=Path,
        required=True,
        help="Directory holding an independently fetched scitt-keys COSE key set.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the official verification and print one JSON document."""
    args = parse_args(argv)

    try:
        # Imported lazily so that a missing upstream environment is reported as
        # a structured result rather than an import traceback.
        from pyscitt.verify import StaticTrustStore, verify_transparent_statement
    except ImportError as error:
        return _emit(
            "fail",
            "The official pyscitt package is not importable in this "
            f"interpreter: {error}. Run this wrapper with the pinned "
            "scitt-ccf-ledger submodule's venv interpreter.",
        )

    for label, path in (
        ("registered statement", args.registered),
        ("transparent statement", args.transparent),
    ):
        if not path.is_file():
            return _emit("fail", f"The {label} file '{path}' does not exist.")
    if not args.trust_store.is_dir():
        return _emit(
            "fail", f"The trust store directory '{args.trust_store}' does not exist."
        )

    registered = args.registered.read_bytes()
    transparent = args.transparent.read_bytes()
    if not registered or not transparent:
        return _emit("fail", "The statement files must not be empty.")

    try:
        trust_store = StaticTrustStore.load(args.trust_store)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as error:
        traceback.print_exc(file=sys.stderr)
        return _emit(
            "fail",
            f"The trust store could not be loaded: {type(error).__name__}: {error}",
        )

    if not getattr(trust_store, "trust_store_keys", None):
        return _emit(
            "fail",
            "The trust store contains no service keys. Fetch "
            "/.well-known/scitt-keys from the transparency service.",
        )

    try:
        receipts = verify_transparent_statement(transparent, trust_store, registered)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as error:
        traceback.print_exc(file=sys.stderr)
        return _emit(
            "fail",
            "The official verifier rejected the receipt for these exact "
            f"registered statement bytes: {type(error).__name__}: {error}",
        )

    details = _json_safe(list(receipts))
    return _emit(
        "pass",
        f"pyscitt.verify.verify_transparent_statement accepted {len(details)} "
        f"receipt(s) over the exact {len(registered)} registered statement bytes.",
        details,
    )


if __name__ == "__main__":
    sys.exit(main())
