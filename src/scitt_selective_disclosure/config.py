# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Environment driven configuration for the demo services."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CLI_PATH = "build/scitt-sd"
DEFAULT_DATA_DIR = ".demo/data"
DEFAULT_SCITT_URL = "https://127.0.0.1:8000"
DEFAULT_MSRC_URL = "http://127.0.0.1:8081"
DEFAULT_CLI_TIMEOUT = 60.0
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_MAX_BUNDLE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_PEM_BYTES = 64 * 1024
DEFAULT_MAX_JSON_BYTES = 1024 * 1024
DEFAULT_MAX_TEXT_CHARS = 20000
DEFAULT_MAX_RECORDS = 500

# The official SCITT verifier runs out of process, in the pinned submodule's
# own virtual environment. Nothing of it is imported here.
DEFAULT_SCITT_VERIFIER_PYTHON = "third_party/scitt-ccf-ledger/venv/bin/python"
DEFAULT_SCITT_VERIFIER_WRAPPER = "demo/official_verify.py"
DEFAULT_SCITT_VERIFIER_TIMEOUT = 120.0

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _text(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, "").strip()
    return value or default


def _optional_path(env: Mapping[str, str], name: str) -> Path | None:
    value = env.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _flag(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    value = env.get(name, "").strip().lower()
    if not value:
        return default
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _number(env: Mapping[str, str], name: str, default: float) -> float:
    value = env.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive number") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive number")
    return parsed


def _size(env: Mapping[str, str], name: str, default: int) -> int:
    value = env.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _path(env: Mapping[str, str], name: str, default: str) -> Path:
    value = env.get(name, "").strip()
    return Path(value or default).expanduser()


@dataclass(frozen=True)
class Settings:
    """Resolved configuration shared by the web and mock MSRC services."""

    cli_path: Path
    cli_timeout: float
    data_dir: Path
    scitt_url: str
    scitt_timeout: float
    scitt_ca_bundle: Path | None
    scitt_insecure: bool
    scitt_verifier_python: Path
    scitt_verifier_wrapper: Path
    scitt_verifier_timeout: float
    msrc_url: str
    msrc_timeout: float
    msrc_root_key: Path | None
    msrc_root_cert: Path | None
    max_bundle_bytes: int
    max_pem_bytes: int
    max_json_bytes: int
    max_text_chars: int
    max_records: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from a process environment mapping."""
        source: Mapping[str, str] = os.environ if env is None else env
        data_dir = (
            source.get("SDC_DATA_DIR", "").strip() or source.get("DATA_DIR", "").strip()
        )
        return cls(
            cli_path=Path(_text(source, "SDC_CLI", DEFAULT_CLI_PATH)).expanduser(),
            cli_timeout=_number(source, "SDC_CLI_TIMEOUT", DEFAULT_CLI_TIMEOUT),
            data_dir=Path(data_dir or DEFAULT_DATA_DIR).expanduser(),
            scitt_url=_text(source, "SDC_SCITT_URL", DEFAULT_SCITT_URL).rstrip("/"),
            scitt_timeout=_number(source, "SDC_SCITT_TIMEOUT", DEFAULT_HTTP_TIMEOUT),
            scitt_ca_bundle=_optional_path(source, "SDC_SCITT_CA_BUNDLE"),
            scitt_insecure=_flag(source, "SDC_SCITT_INSECURE"),
            scitt_verifier_python=_path(
                source, "SDC_SCITT_VERIFIER_PYTHON", DEFAULT_SCITT_VERIFIER_PYTHON
            ),
            scitt_verifier_wrapper=_path(
                source, "SDC_SCITT_VERIFIER_WRAPPER", DEFAULT_SCITT_VERIFIER_WRAPPER
            ),
            scitt_verifier_timeout=_number(
                source, "SDC_SCITT_VERIFIER_TIMEOUT", DEFAULT_SCITT_VERIFIER_TIMEOUT
            ),
            msrc_url=_text(source, "SDC_MSRC_URL", DEFAULT_MSRC_URL).rstrip("/"),
            msrc_timeout=_number(source, "SDC_MSRC_TIMEOUT", DEFAULT_HTTP_TIMEOUT),
            msrc_root_key=_optional_path(source, "SDC_MSRC_ROOT_KEY"),
            msrc_root_cert=_optional_path(source, "SDC_MSRC_ROOT_CERT"),
            max_bundle_bytes=_size(
                source, "SDC_MAX_BUNDLE_BYTES", DEFAULT_MAX_BUNDLE_BYTES
            ),
            max_pem_bytes=_size(source, "SDC_MAX_PEM_BYTES", DEFAULT_MAX_PEM_BYTES),
            max_json_bytes=_size(source, "SDC_MAX_JSON_BYTES", DEFAULT_MAX_JSON_BYTES),
            max_text_chars=_size(source, "SDC_MAX_TEXT_CHARS", DEFAULT_MAX_TEXT_CHARS),
            max_records=_size(source, "SDC_MAX_RECORDS", DEFAULT_MAX_RECORDS),
        )

    @property
    def scitt_verify(self) -> str | bool:
        """Return the TLS verification setting for transparency service calls."""
        if self.scitt_ca_bundle is not None:
            return str(self.scitt_ca_bundle)
        return not self.scitt_insecure
