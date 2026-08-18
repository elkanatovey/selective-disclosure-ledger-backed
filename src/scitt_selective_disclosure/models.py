# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Pydantic response and request models for the demo APIs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

StageStatus = Literal["pass", "fail", "skipped", "pending"]
CheckStatus = Literal["pass", "fail", "warn", "unknown", "skipped"]
SubmissionStatus = Literal["complete", "partial", "failed"]

MAX_SELECTED_FIELDS = 64
MAX_SELECTED_CHUNKS = 20000


class ErrorResponse(BaseModel):
    """Structured error payload returned by every API route."""

    error: str
    message: str
    detail: str | None = None


class HealthResponse(BaseModel):
    """Liveness payload including control-plane readiness hints."""

    status: Literal["ok"] = "ok"
    service: str
    cli_configured: bool
    demo_only: Literal[True] = True


class DisclosedField(BaseModel):
    """A whole-field disclosure carried by a bundle."""

    model_config = ConfigDict(extra="ignore")

    name: str
    label: str
    disclosed: bool = True
    value: str | None = None


class BodyChunk(BaseModel):
    """A six code point body disclosure with a stable index."""

    model_config = ConfigDict(extra="ignore")

    index: int
    text: str
    disclosed: bool = True


class ScittReference(BaseModel):
    """Transparency service coordinates recorded inside a bundle."""

    model_config = ConfigDict(extra="ignore")

    url: str | None = None
    txid: str | None = None


class BundleInspection(BaseModel):
    """Rendered view of a bundle as reported by the command line tool."""

    model_config = ConfigDict(extra="ignore")

    chunk_size: int = 6
    fields: list[DisclosedField] = Field(default_factory=list)
    body_chunks: list[BodyChunk] = Field(default_factory=list)
    scitt: ScittReference | None = None
    notes: list[str] = Field(default_factory=list)


class InspectionResponse(BaseModel):
    """Inspection result plus the identifier used for follow-up requests."""

    bundle_id: str
    bundle_bytes: int
    source: Literal["upload", "submission"]
    submission_id: str | None = None
    inspection: BundleInspection


class SelectionRequest(BaseModel):
    """Redaction selection submitted by the MSRC role."""

    model_config = ConfigDict(extra="forbid")

    redact_fields: list[str] = Field(default_factory=list)
    redact_body_chunks: list[int] = Field(default_factory=list)

    @field_validator("redact_fields")
    @classmethod
    def _check_fields(cls, value: list[str]) -> list[str]:
        if len(value) > MAX_SELECTED_FIELDS:
            raise ValueError("too many fields selected")
        cleaned: list[str] = []
        for item in value:
            name = item.strip()
            if not name or len(name) > 64:
                raise ValueError("invalid field name")
            if name not in cleaned:
                cleaned.append(name)
        return cleaned

    @field_validator("redact_body_chunks")
    @classmethod
    def _check_chunks(cls, value: list[int]) -> list[int]:
        if len(value) > MAX_SELECTED_CHUNKS:
            raise ValueError("too many body chunks selected")
        for index in value:
            if index < 0:
                raise ValueError("body chunk indices must not be negative")
        return sorted(set(value))

    def to_cli_document(self) -> dict[str, object]:
        """Return the JSON document handed to the command line tool."""
        return {
            "version": 1,
            "redact_fields": list(self.redact_fields),
            "redact_body_chunks": list(self.redact_body_chunks),
        }


class PresentationResponse(BaseModel):
    """Result of producing a redacted bundle."""

    presentation_id: str
    bundle_id: str
    bundle_bytes: int
    download_url: str
    redacted_fields: list[str]
    redacted_body_chunks: list[int]


class CheckResult(BaseModel):
    """One independent verification result."""

    model_config = ConfigDict(extra="ignore")

    id: str
    label: str
    status: CheckStatus = "unknown"
    detail: str | None = None


class VerificationSource(BaseModel):
    """The verdict of one independent verification engine.

    Two engines contribute to a report: the C++ selective-disclosure tool and
    the official upstream SCITT verifier. Their verdicts are reported side by
    side so a reader can always tell which component decided what.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    label: str
    status: CheckStatus = "unknown"
    detail: str | None = None


class VerificationReport(BaseModel):
    """Normalised verification outcome with a fixed set of checks."""

    model_config = ConfigDict(extra="ignore")

    overall: CheckStatus = "unknown"
    checks: list[CheckResult] = Field(default_factory=list)
    sources: list[VerificationSource] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class VerificationResponse(BaseModel):
    """Verification result plus export coordinates."""

    report_id: str
    report: VerificationReport
    report_url: str


class EnrollmentResponse(BaseModel):
    """Result of the researcher enrollment handshake."""

    enrollment_id: str
    created_at: str
    subject: str
    leaf_certificate_bytes: int
    root_certificate_bytes: int
    public_key_bytes: int
    private_key_transmitted: Literal[False] = False


class StageResult(BaseModel):
    """Outcome of one stage of the single click submission."""

    name: str
    label: str
    status: StageStatus = "pending"
    detail: str | None = None


class ScittResult(BaseModel):
    """Transparency service registration outcome."""

    registered: bool
    txid: str | None = None
    url: str | None = None
    transparent_statement_bytes: int | None = None


class SubmissionResponse(BaseModel):
    """Response for a researcher submission or a delivery retry."""

    submission_id: str
    status: SubmissionStatus
    message: str
    stages: list[StageResult]
    scitt: ScittResult
    msrc_submission_id: str | None = None
    bundle_url: str | None = None
    statement_url: str | None = None
    transparent_url: str | None = None
    retry_url: str | None = None


class SubmissionSummary(BaseModel):
    """Stored submission metadata."""

    submission_id: str
    created_at: str
    title: str
    status: SubmissionStatus | Literal["stored"]
    scitt_txid: str | None = None
    scitt_url: str | None = None
    bundle_bytes: int | None = None
    msrc_submission_id: str | None = None


class SubmissionList(BaseModel):
    """A list of stored submissions."""

    submissions: list[SubmissionSummary]


class EnrollmentIssuance(BaseModel):
    """Mock MSRC enrollment response carrying opaque certificate bytes."""

    enrollment_id: str
    created_at: str
    subject: str
    leaf_certificate_b64: str
    root_certificate_b64: str
    demo_only: Literal[True] = True


class StoredSubmission(BaseModel):
    """Mock MSRC submission record."""

    submission_id: str
    created_at: str
    title: str
    scitt_txid: str | None = None
    scitt_url: str | None = None
    bundle_bytes: int
    presentations: list[str] = Field(default_factory=list)
    demo_only: Literal[True] = True


class StoredSubmissionList(BaseModel):
    """A list of mock MSRC submission records."""

    submissions: list[StoredSubmission]
