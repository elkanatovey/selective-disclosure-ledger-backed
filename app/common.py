# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared plumbing for the three apps.

Nothing here knows about statements, bundles or keys: it is request decoding,
bounded in-memory storage, and the template and static mounts each app needs.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import TypeVar

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

HERE = Path(__file__).parent

ES256_SIGNATURE_BYTES = 64
MAX_BUNDLE_B64 = 8 * 1024 * 1024
MAX_RECORDS = 256

_Record = TypeVar("_Record")


def templates_for(app: FastAPI) -> Jinja2Templates:
    """Mount the shared static files and return the shared template set."""
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    return Jinja2Templates(directory=str(HERE / "templates"))


def evict(records: dict[str, _Record]) -> None:
    # Everything is in memory, so the oldest record goes rather than letting a
    # caller grow the process without bound.
    while len(records) >= MAX_RECORDS:
        records.pop(next(iter(records)))


def decode_signature(encoded: str) -> bytes:
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(400, "The signature is not valid base64.") from error
    if len(signature) != ES256_SIGNATURE_BYTES:
        raise HTTPException(400, "The signature must be 64 bytes of raw r||s.")
    return signature


def decode_bundle(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(400, "The bundle is not valid base64.") from error
