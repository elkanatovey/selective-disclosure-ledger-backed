# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Unit tests for the official SCITT verifier adapter."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scitt_selective_disclosure.config import Settings
from scitt_selective_disclosure.scitt_verify import (
    COSE_KEY_SET_NAME,
    LEGACY_TRUST_NAME,
    OfficialResult,
    ScittVerifier,
    parse_official_output,
    trust_store_file_name,
)

REGISTERED = b"\xd2\x84registered-statement"
TRANSPARENT = b"\xd2\x84transparent-statement"
TRUST = b"\x81\xa1\x01\x02"

WRAPPER = Path(__file__).resolve().parent / "fake_official_verify.py"


def build(tmp_path: Path, result: str, log: Path) -> ScittVerifier:
    """Return a verifier wired to the fake wrapper with a scripted outcome."""
    shim = tmp_path / "python-shim"
    shim.write_text(
        "#!/bin/sh\n"
        f'FAKE_OFFICIAL_RESULT="{result}" '
        f'FAKE_OFFICIAL_LOG="{log}" '
        f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o700)
    return ScittVerifier(shim, WRAPPER, timeout=30.0)


def test_trust_store_file_name_maps_cbor_key_sets() -> None:
    """COSE key sets are stored where StaticTrustStore.load will glob them."""
    assert trust_store_file_name("scitt-keys.cbor") == COSE_KEY_SET_NAME
    assert trust_store_file_name("keys") == COSE_KEY_SET_NAME
    assert trust_store_file_name("/tmp/download.CBOR") == COSE_KEY_SET_NAME


def test_trust_store_file_name_maps_legacy_parameters() -> None:
    """Legacy service parameter documents keep their JSON name."""
    assert trust_store_file_name("service-parameters.json") == LEGACY_TRUST_NAME
    assert trust_store_file_name("anything.JSON") == LEGACY_TRUST_NAME


def test_available_is_false_without_the_submodule(tmp_path: Path) -> None:
    """A missing submodule venv is detected before anything is run."""
    verifier = ScittVerifier(tmp_path / "missing", tmp_path / "absent.py")
    assert verifier.available is False


def test_missing_submodule_is_skipped_not_failed(tmp_path: Path) -> None:
    """A missing verifier is reported as skipped and points at demo/run.sh."""
    verifier = ScittVerifier(tmp_path / "missing", tmp_path / "absent.py")
    result = verifier.verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "skipped"
    assert result.passed is False
    assert "demo/run.sh" in result.detail


def test_from_settings_uses_configured_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Settings drive the interpreter, wrapper and timeout."""
    monkeypatch.setenv("SDC_SCITT_VERIFIER_PYTHON", str(tmp_path / "bin" / "python"))
    monkeypatch.setenv("SDC_SCITT_VERIFIER_WRAPPER", str(tmp_path / "verify.py"))
    monkeypatch.setenv("SDC_SCITT_VERIFIER_TIMEOUT", "17.5")
    settings = Settings.from_env()
    verifier = ScittVerifier.from_settings(settings)
    assert verifier.python == settings.scitt_verifier_python
    assert verifier.wrapper == settings.scitt_verifier_wrapper
    assert verifier.timeout == 17.5


def test_verify_passes_exact_bytes(tmp_path: Path) -> None:
    """The exact registered and transparent bytes reach the wrapper."""
    log = tmp_path / "log.json"
    result = build(tmp_path, "pass", log).verify(
        registered=REGISTERED,
        transparent=TRANSPARENT,
        trust_store=TRUST,
        name="scitt-keys.cbor",
    )
    assert result.status == "pass"
    assert result.passed is True

    call = json.loads(log.read_text(encoding="utf-8"))
    assert call["registered_sha256"] == hashlib.sha256(REGISTERED).hexdigest()
    assert call["transparent_sha256"] == hashlib.sha256(TRANSPARENT).hexdigest()
    assert call["registered_bytes"] == len(REGISTERED)
    assert call["transparent_bytes"] == len(TRANSPARENT)
    assert call["trust_files"] == [COSE_KEY_SET_NAME]
    assert call["trust_sha256"][COSE_KEY_SET_NAME] == hashlib.sha256(TRUST).hexdigest()


def test_verify_reports_receipts(tmp_path: Path) -> None:
    """Receipt metadata from the official tool is surfaced."""
    result = build(tmp_path, "pass", tmp_path / "log.json").verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.receipts
    assert result.receipts[0]["service_id"]


def test_verify_reports_failure(tmp_path: Path) -> None:
    """A rejected receipt is a failure, not an error."""
    result = build(tmp_path, "fail", tmp_path / "log.json").verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "fail"
    assert result.passed is False
    assert result.detail


def test_verify_treats_a_crash_as_unknown(tmp_path: Path) -> None:
    """A crashing wrapper never yields a pass."""
    result = build(tmp_path, "crash", tmp_path / "log.json").verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "unknown"
    assert result.passed is False


def test_verify_treats_garbage_as_unknown(tmp_path: Path) -> None:
    """Non JSON output never yields a pass."""
    result = build(tmp_path, "garbage", tmp_path / "log.json").verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "unknown"
    assert "JSON" in result.detail


def test_verify_times_out(tmp_path: Path) -> None:
    """A hanging wrapper is bounded and reported as unknown."""
    verifier = build(tmp_path, "timeout", tmp_path / "log.json")
    verifier.timeout = 0.5
    result = verifier.verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "unknown"
    assert "0.5 seconds" in result.detail


def test_verify_handles_an_unstartable_interpreter(tmp_path: Path) -> None:
    """An interpreter that exists but cannot execute is reported, not raised."""
    fake_python = tmp_path / "not-executable"
    fake_python.write_text("not a program\n", encoding="utf-8")
    fake_python.chmod(0o600)
    result = ScittVerifier(fake_python, WRAPPER).verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    assert result.status == "unknown"
    assert result.passed is False


def test_verify_removes_the_workspace(tmp_path: Path) -> None:
    """Statement bytes are not left behind on disk."""
    log = tmp_path / "log.json"
    build(tmp_path, "pass", log).verify(
        registered=REGISTERED, transparent=TRANSPARENT, trust_store=TRUST, name="k.cbor"
    )
    workspace = Path(json.loads(log.read_text(encoding="utf-8"))["trust_store"]).parent
    assert not workspace.exists()


def test_parse_requires_exit_zero_for_a_pass() -> None:
    """A pass claimed with a non-zero exit code is downgraded."""
    payload = json.dumps({"status": "pass", "detail": "ok"})
    assert parse_official_output(0, payload, "").status == "pass"
    assert parse_official_output(1, payload, "").status == "unknown"


def test_parse_rejects_unknown_status_values() -> None:
    """Only the documented statuses are honoured."""
    for status in ("passed", "PASS", "ok", "", None, 1):
        payload = json.dumps({"status": status, "detail": "d"})
        assert parse_official_output(0, payload, "").status == "unknown"


def test_parse_accepts_failure_with_any_exit_code() -> None:
    """A declared failure stays a failure."""
    payload = json.dumps({"status": "fail", "detail": "bad receipt"})
    assert parse_official_output(1, payload, "").status == "fail"
    assert parse_official_output(0, payload, "").status == "fail"


def test_parse_rejects_non_object_documents() -> None:
    """A JSON array is not a result document."""
    result = parse_official_output(0, json.dumps(["pass"]), "")
    assert result.status == "unknown"


def test_parse_reports_stderr_when_there_is_no_json() -> None:
    """Diagnostics are preserved for the operator."""
    result = parse_official_output(2, "", "ModuleNotFoundError: pyscitt")
    assert result.status == "unknown"
    assert "pyscitt" in result.detail


def test_parse_supplies_a_detail_when_one_is_missing() -> None:
    """Every result carries something the UI can display."""
    result = parse_official_output(0, json.dumps({"status": "pass"}), "")
    assert result.detail


def test_parse_keeps_only_object_receipts() -> None:
    """Malformed receipt entries are dropped rather than trusted."""
    payload = json.dumps(
        {"status": "pass", "detail": "d", "receipts": [{"a": 1}, "x", 3, None]}
    )
    assert parse_official_output(0, payload, "").receipts == ({"a": 1},)


def test_parse_tolerates_non_list_receipts() -> None:
    """A receipts field of the wrong type is ignored."""
    payload = json.dumps({"status": "pass", "detail": "d", "receipts": "many"})
    assert parse_official_output(0, payload, "").receipts == ()


def test_parse_truncates_enormous_details() -> None:
    """A hostile wrapper cannot flood the report."""
    payload = json.dumps({"status": "fail", "detail": "x" * 100_000})
    assert len(parse_official_output(1, payload, "").detail) < 5_000


def test_official_result_defaults() -> None:
    """The dataclass has usable defaults."""
    result = OfficialResult(status="skipped", detail="none")
    assert result.receipts == ()
    assert result.passed is False


@pytest.mark.parametrize("flag", ["--registered", "--transparent", "--trust-store"])
def test_wrapper_requires_every_input(flag: str) -> None:
    """The real wrapper refuses to run without its exact inputs."""
    wrapper = Path(__file__).resolve().parents[2] / "demo" / "official_verify.py"
    completed = subprocess.run(
        [sys.executable, str(wrapper), flag],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
