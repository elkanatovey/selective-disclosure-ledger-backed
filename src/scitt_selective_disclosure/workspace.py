# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Filesystem helpers for short-lived, restrictively permissioned material."""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
OVERWRITE_CHUNK = b"\x00" * 4096


@contextlib.contextmanager
def secure_workspace(prefix: str = "sdc-") -> Iterator[Path]:
    """Yield a private temporary directory that is removed on exit."""
    with tempfile.TemporaryDirectory(prefix=prefix) as name:
        path = Path(name)
        os.chmod(path, DIRECTORY_MODE)
        try:
            yield path
        finally:
            for child in sorted(path.rglob("*"), reverse=True):
                if child.is_file():
                    remove_file(child)


def write_private_file(path: Path, data: bytes) -> Path:
    """Write bytes to a new file that only the owner can read."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def remove_file(path: Path) -> None:
    """Best-effort overwrite and removal of a file holding sensitive bytes.

    Overwriting is a defence in depth measure only. Journalling filesystems and
    copy-on-write storage may retain the original blocks.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            written = 0
            while written < size:
                block = min(len(OVERWRITE_CHUNK), size - written)
                handle.write(OVERWRITE_CHUNK[:block])
                written += block
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


def read_optional_file(path: Path | None) -> bytes | None:
    """Return the contents of a configured file path, if it is readable."""
    if path is None:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None
