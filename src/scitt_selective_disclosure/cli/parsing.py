# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tolerant parsers for the JSON documents emitted by the C++ tool.

The control plane treats the tool as the only component that understands CBOR,
COSE and X.509. These helpers normalise its JSON reports into the models the
web layer renders, without inspecting any security artifact.

The C++ tool reports four checks. The fifth, the SCITT receipt, is produced by
the official upstream verifier and merged in by :func:`merge_official_scitt`.
"""

from __future__ import annotations

from typing import Any, get_args

from ..models import (
    BodyChunk,
    BundleInspection,
    CheckResult,
    CheckStatus,
    DisclosedField,
    ScittReference,
    VerificationReport,
    VerificationSource,
)

DEFAULT_CHUNK_SIZE = 6

CLI_SOURCE_ID = "cpp_cli"
CLI_SOURCE_LABEL = "C++ selective-disclosure tool"
SCITT_SOURCE_ID = "official_scitt"
SCITT_SOURCE_LABEL = "Official SCITT verifier (pyscitt)"

SCITT_CHECK_ID = "scitt_receipt"
SCITT_CHECK_LABEL = "SCITT receipt (official pyscitt)"

# The four checks the C++ tool owns, with the aliases its report may use.
CLI_CHECK_LABELS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "msrc_chain",
        "MSRC certificate chain",
        ("msrc_chain", "chain", "x509_chain", "msrc"),
    ),
    (
        "issuer_signature",
        "Issuer signature",
        ("issuer_signature", "signature", "issuer"),
    ),
    (
        "disclosures",
        "Disclosure consistency",
        ("disclosures", "disclosure", "salted_disclosures"),
    ),
    (
        "statement_binding",
        "Registered statement binding",
        ("statement_binding", "binding", "registered_statement", "statement"),
    ),
)

CHECK_LABELS_BY_ID: dict[str, str] = {
    check_id: label for check_id, label, _ in CLI_CHECK_LABELS
}
CHECK_LABELS_BY_ID[SCITT_CHECK_ID] = SCITT_CHECK_LABEL

VALID_STATUSES: frozenset[str] = frozenset(get_args(CheckStatus))
STATUS_ALIASES = {
    "ok": "pass",
    "passed": "pass",
    "success": "pass",
    "true": "pass",
    "valid": "pass",
    "error": "fail",
    "failed": "fail",
    "invalid": "fail",
    "false": "fail",
    "warning": "warn",
    "skip": "skipped",
    "not_applicable": "skipped",
}


def _as_mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_sequence(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _as_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _as_bool(value: object, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "disclosed"}:
            return True
        if lowered in {"false", "no", "0", "redacted", "removed"}:
            return False
    return default


def _as_notes(value: object) -> list[str]:
    return [note for note in _as_sequence(value) if isinstance(note, str)]


def normalise_status(value: object) -> CheckStatus:
    """Map a tool reported status onto the rendered status vocabulary."""
    if isinstance(value, bool):
        return "pass" if value else "fail"
    text = (_as_text(value) or "").strip().lower()
    text = STATUS_ALIASES.get(text, text)
    if text in VALID_STATUSES:
        return text  # type: ignore[return-value]
    return "unknown"


def combine_statuses(statuses: list[CheckStatus]) -> CheckStatus:
    """Return the overall status for a set of checks.

    Only an unbroken set of passes is an overall pass. A single failure fails
    the whole report, and anything unresolved leaves it unknown.
    """
    if not statuses:
        return "unknown"
    if "fail" in statuses:
        return "fail"
    if all(status == "pass" for status in statuses):
        return "pass"
    return "unknown"


def parse_inspection(document: object) -> BundleInspection:
    """Normalise a ``bundle inspect`` report."""
    payload = _as_mapping(document)
    fields: list[DisclosedField] = []
    for raw_field in _as_sequence(payload.get("fields")):
        entry = _as_mapping(raw_field)
        name = _as_text(entry.get("name")) or _as_text(entry.get("id"))
        if not name:
            continue
        label = _as_text(entry.get("label")) or name.replace("_", " ").title()
        fields.append(
            DisclosedField(
                name=name,
                label=label,
                disclosed=_as_bool(entry.get("disclosed", True)),
                value=_as_text(entry.get("value")),
            )
        )

    body = _as_mapping(payload.get("body"))
    raw_chunks = body.get("chunks")
    if raw_chunks is None:
        raw_chunks = payload.get("body_chunks")
    chunks: list[BodyChunk] = []
    for position, raw_chunk in enumerate(_as_sequence(raw_chunks)):
        if isinstance(raw_chunk, str):
            chunks.append(BodyChunk(index=position, text=raw_chunk, disclosed=True))
            continue
        entry = _as_mapping(raw_chunk)
        text = _as_text(entry.get("text"))
        if text is None:
            continue
        raw_index = entry.get("index")
        index_value = raw_index if isinstance(raw_index, int) else position
        chunks.append(
            BodyChunk(
                index=index_value,
                text=text,
                disclosed=_as_bool(entry.get("disclosed", True)),
            )
        )

    chunk_size_value = body.get("chunk_size", payload.get("chunk_size"))
    chunk_size = (
        chunk_size_value
        if isinstance(chunk_size_value, int) and chunk_size_value > 0
        else DEFAULT_CHUNK_SIZE
    )

    scitt_payload = _as_mapping(payload.get("scitt"))
    scitt = (
        ScittReference(
            url=_as_text(scitt_payload.get("url")),
            txid=_as_text(scitt_payload.get("txid"))
            or _as_text(scitt_payload.get("transaction_id")),
        )
        if scitt_payload
        else None
    )

    return BundleInspection(
        chunk_size=chunk_size,
        fields=fields,
        body_chunks=chunks,
        scitt=scitt,
        notes=_as_notes(payload.get("notes")),
    )


def _collect_reported_checks(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    reported: dict[str, dict[str, Any]] = {}
    raw_checks = payload.get("checks")
    if isinstance(raw_checks, dict):
        for key, value in raw_checks.items():
            if isinstance(value, dict):
                reported[str(key).lower()] = dict(value)
            else:
                reported[str(key).lower()] = {"status": value}
    else:
        for raw_check in _as_sequence(raw_checks):
            entry = _as_mapping(raw_check)
            key = _as_text(entry.get("id")) or _as_text(entry.get("name"))
            if key:
                reported[key.lower()] = entry
    return reported


def _detail_of(entry: dict[str, Any]) -> str | None:
    return _as_text(entry.get("detail")) or _as_text(entry.get("message"))


def parse_verification(document: object) -> VerificationReport:
    """Normalise a ``verify`` report into the four checks the tool owns.

    Any receipt check the tool happens to report is ignored: the receipt is
    only ever decided by the official SCITT verifier.
    """
    payload = _as_mapping(document)
    reported = _collect_reported_checks(payload)

    checks: list[CheckResult] = []
    for check_id, label, aliases in CLI_CHECK_LABELS:
        entry: dict[str, Any] = {}
        for alias in aliases:
            if alias in reported:
                entry = reported[alias]
                break
        checks.append(
            CheckResult(
                id=check_id,
                label=label,
                status=normalise_status(entry.get("status", entry.get("result"))),
                detail=_detail_of(entry),
            )
        )

    overall = combine_statuses([check.status for check in checks])
    source = VerificationSource(
        id=CLI_SOURCE_ID,
        label=CLI_SOURCE_LABEL,
        status=overall,
        detail=_as_text(payload.get("detail")),
    )
    return VerificationReport(
        overall=overall,
        checks=checks,
        sources=[source],
        notes=_as_notes(payload.get("notes")),
    )


def merge_official_scitt(
    report: VerificationReport,
    *,
    status: CheckStatus,
    detail: str,
) -> VerificationReport:
    """Return the five-check report, adding the official SCITT receipt result.

    The overall result passes only when all five checks pass. The C++ tool's
    own overall result is kept as a separate source so the two independent
    verifications are never conflated.
    """
    cli_checks = [check for check in report.checks if check.id != SCITT_CHECK_ID]
    cli_overall = combine_statuses([check.status for check in cli_checks])
    scitt_check = CheckResult(
        id=SCITT_CHECK_ID,
        label=SCITT_CHECK_LABEL,
        status=status,
        detail=detail or None,
    )
    checks = [*cli_checks, scitt_check]
    sources = [
        VerificationSource(
            id=CLI_SOURCE_ID,
            label=CLI_SOURCE_LABEL,
            status=cli_overall,
            detail=f"{len(cli_checks)} checks reported by the C++ tool.",
        ),
        VerificationSource(
            id=SCITT_SOURCE_ID,
            label=SCITT_SOURCE_LABEL,
            status=status,
            detail=detail or None,
        ),
    ]
    return VerificationReport(
        overall=combine_statuses([check.status for check in checks]),
        checks=checks,
        sources=sources,
        notes=list(report.notes),
    )


def parse_stored_report(document: object) -> VerificationReport:
    """Re-render a previously exported report without dropping any check.

    Unlike :func:`parse_verification`, this keeps every check the document
    carries, including the official SCITT receipt result, and recomputes the
    overall status from them so that an edited export cannot claim a pass it
    has not earned.
    """
    payload = _as_mapping(document)
    checks: list[CheckResult] = []
    for raw_check in _as_sequence(payload.get("checks")):
        entry = _as_mapping(raw_check)
        check_id = _as_text(entry.get("id"))
        if not check_id:
            continue
        label = (
            _as_text(entry.get("label"))
            or CHECK_LABELS_BY_ID.get(check_id)
            or check_id.replace("_", " ").capitalize()
        )
        checks.append(
            CheckResult(
                id=check_id,
                label=label,
                status=normalise_status(entry.get("status")),
                detail=_detail_of(entry),
            )
        )
    if not checks:
        return parse_verification(document)

    sources: list[VerificationSource] = []
    for raw_source in _as_sequence(payload.get("sources")):
        entry = _as_mapping(raw_source)
        source_id = _as_text(entry.get("id"))
        if not source_id:
            continue
        sources.append(
            VerificationSource(
                id=source_id,
                label=_as_text(entry.get("label")) or source_id,
                status=normalise_status(entry.get("status")),
                detail=_detail_of(entry),
            )
        )
    return VerificationReport(
        overall=combine_statuses([check.status for check in checks]),
        checks=checks,
        sources=sources,
        notes=_as_notes(payload.get("notes")),
    )
