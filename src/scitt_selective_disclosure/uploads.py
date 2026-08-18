# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Strict validation for uploaded opaque artifacts.

Uploads are never decoded. Only the declared media type, the file name suffix
and the byte length are inspected before the bytes are handed to the command
line tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from fastapi import UploadFile

from .errors import UploadError

READ_CHUNK_BYTES = 64 * 1024
NEUTRAL_CONTENT_TYPES = ("", "application/octet-stream", "binary/octet-stream")

# PEM labels that must never be accepted where only public material belongs.
# This is a plain byte search over a PEM header, not a key parse.
PRIVATE_KEY_MARKERS = (b"PRIVATE KEY", b"BEGIN OPENSSH PRIVATE")


@dataclass(frozen=True)
class UploadKind:
    """Accepted file suffixes and media types for one class of artifact."""

    label: str
    extensions: tuple[str, ...]
    content_types: tuple[str, ...]
    reject_private_key: bool = False


BUNDLE_UPLOAD = UploadKind(
    label="bundle",
    extensions=(".cbor", ".cose", ".bundle", ".sdcwt"),
    content_types=NEUTRAL_CONTENT_TYPES
    + ("application/cbor", "application/cose", "application/sd-cwt"),
)
STATEMENT_UPLOAD = UploadKind(
    label="statement",
    extensions=(".cose", ".cbor"),
    content_types=NEUTRAL_CONTENT_TYPES + ("application/cose", "application/cbor"),
)
CERTIFICATE_UPLOAD = UploadKind(
    label="certificate",
    extensions=(".pem", ".crt", ".cer"),
    content_types=NEUTRAL_CONTENT_TYPES
    + (
        "application/x-pem-file",
        "application/x-x509-ca-cert",
        "application/pkix-cert",
        "text/plain",
    ),
)
PRIVATE_KEY_UPLOAD = UploadKind(
    label="private key",
    extensions=(".pem", ".key"),
    content_types=NEUTRAL_CONTENT_TYPES + ("application/x-pem-file", "text/plain"),
)
PUBLIC_KEY_UPLOAD = UploadKind(
    label="public key",
    extensions=(".pem", ".pub"),
    content_types=NEUTRAL_CONTENT_TYPES + ("application/x-pem-file", "text/plain"),
    reject_private_key=True,
)
TRUST_UPLOAD = UploadKind(
    label="trust material",
    extensions=(".pem", ".crt", ".cer", ".json", ".cbor"),
    content_types=NEUTRAL_CONTENT_TYPES
    + (
        "application/x-pem-file",
        "application/x-x509-ca-cert",
        "application/pkix-cert",
        "application/json",
        "application/cbor",
        "text/plain",
    ),
)
JSON_UPLOAD = UploadKind(
    label="JSON document",
    extensions=(".json",),
    content_types=NEUTRAL_CONTENT_TYPES + ("application/json", "text/plain"),
)


def safe_suffix(file_name: str | None, kind: UploadKind) -> str:
    """Return the lower case suffix of a rejected-if-unsafe upload name."""
    if not file_name:
        raise UploadError(f"A file name is required for the {kind.label} upload.")
    if "\x00" in file_name:
        raise UploadError(f"The {kind.label} file name is not accepted.")
    name = file_name.replace("\\", "/")
    if name != PurePosixPath(name).name or name in {"", ".", ".."}:
        raise UploadError(f"The {kind.label} file name must not contain a path.")
    suffix = PurePosixPath(name).suffix.lower()
    if suffix not in kind.extensions:
        allowed = ", ".join(kind.extensions)
        raise UploadError(
            f"The {kind.label} upload must use one of these extensions: {allowed}."
        )
    return suffix


def _check_content_type(declared: str | None, kind: UploadKind) -> None:
    value = (declared or "").split(";", 1)[0].strip().lower()
    if value not in kind.content_types:
        allowed = ", ".join(item for item in kind.content_types if item)
        raise UploadError(
            f"The {kind.label} upload declared an unsupported content type "
            f"'{value}'. Expected one of: {allowed}."
        )


async def read_upload(upload: UploadFile, kind: UploadKind, max_bytes: int) -> bytes:
    """Validate an upload and return its opaque bytes."""
    safe_suffix(upload.filename, kind)
    _check_content_type(upload.content_type, kind)

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise UploadError(
                f"The {kind.label} upload exceeds the {max_bytes} byte limit."
            )
        chunks.append(chunk)
    if total == 0:
        raise UploadError(f"The {kind.label} upload is empty.")
    payload = b"".join(chunks)
    if kind.reject_private_key and any(
        marker in payload for marker in PRIVATE_KEY_MARKERS
    ):
        raise UploadError(
            f"The {kind.label} upload looks like a private key. Only public "
            "key material is accepted here."
        )
    return payload


def check_text_field(name: str, value: str, max_chars: int, *, required: bool) -> str:
    """Validate a plain text form field and return its normalised value."""
    text = value.replace("\r\n", "\n").strip()
    if required and not text:
        raise UploadError(f"The {name} field is required.")
    if len(text) > max_chars:
        raise UploadError(f"The {name} field exceeds {max_chars} characters.")
    if "\x00" in text:
        raise UploadError(f"The {name} field contains unsupported characters.")
    return text


def download_file_name(prefix: str, record_id: str, suffix: str) -> str:
    """Return a predictable, traversal-free download file name."""
    safe_prefix = "".join(
        character for character in prefix if character.isalnum() or character in "-_"
    )
    safe_suffix_value = suffix if suffix.startswith(".") else f".{suffix}"
    return f"{safe_prefix or 'artifact'}-{record_id}{safe_suffix_value}"
