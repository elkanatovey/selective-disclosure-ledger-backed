# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Researcher routes: enrollment handshake and one click submission.

The submission pipeline is strictly ordered. The full report and its
disclosures are only sent to the mock MSRC service after the transparency
service has confirmed registration of the exact registered statement.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import APIRouter, File, Form, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from .. import operations
from ..errors import AppError, NotFoundError, RequestError
from ..http_support import artifact_response, get_services, now_text
from ..models import (
    EnrollmentResponse,
    ScittResult,
    StageResult,
    SubmissionList,
    SubmissionResponse,
    SubmissionSummary,
)
from ..scitt import ScittRegistration
from ..services import Services
from ..storage import validate_record_id
from ..uploads import PRIVATE_KEY_UPLOAD, check_text_field, read_upload

router = APIRouter(prefix="/api/researcher", tags=["researcher"])

ENROLLMENTS: Final = "enrollments"
SUBMISSIONS: Final = "submissions"

LEAF_CERT_FILE: Final = "leaf.pem"
ROOT_CERT_FILE: Final = "root.pem"
META_FILE: Final = "meta.json"
REPORT_FILE: Final = "report.json"
REGISTERED_FILE: Final = "registered.cose"
DISCLOSURES_FILE: Final = "disclosures.cbor"
TRANSPARENT_FILE: Final = "transparent.cose"
BUNDLE_FILE: Final = "bundle.cbor"

STAGE_DEFINITIONS: Final[tuple[tuple[str, str], ...]] = (
    ("issue", "Sign the report and build the registered statement"),
    ("scitt_register", "Register the exact statement with SCITT"),
    ("bundle_create", "Build the full proof bundle"),
    ("msrc_deliver", "Deliver the bundle to MSRC"),
)

STATUS_CODES: Final[dict[str, int]] = {"complete": 200, "partial": 207, "failed": 502}
MAX_TITLE_CHARS: Final = 200
MAX_SHORT_CHARS: Final = 120


class StageTracker:
    """Records the outcome of every pipeline stage in a fixed order."""

    def __init__(self) -> None:
        self._results: dict[str, StageResult] = {
            name: StageResult(name=name, label=label, status="pending")
            for name, label in STAGE_DEFINITIONS
        }

    def passed(self, name: str, detail: str | None = None) -> None:
        """Mark a stage as successful."""
        self._results[name].status = "pass"
        self._results[name].detail = detail

    def failed(self, name: str, detail: str) -> None:
        """Mark a stage as failed and skip every later stage."""
        self._results[name].status = "fail"
        self._results[name].detail = detail
        seen = False
        for stage_name, _ in STAGE_DEFINITIONS:
            if stage_name == name:
                seen = True
                continue
            if seen and self._results[stage_name].status == "pending":
                self._results[stage_name].status = "skipped"
                self._results[stage_name].detail = "Not attempted."

    def skipped(self, name: str, detail: str) -> None:
        """Mark a stage as intentionally not attempted."""
        self._results[name].status = "skipped"
        self._results[name].detail = detail

    def as_list(self) -> list[StageResult]:
        """Return the stage results in pipeline order."""
        return [self._results[name] for name, _ in STAGE_DEFINITIONS]


def _describe(error: Exception) -> str:
    if isinstance(error, AppError):
        if error.detail:
            return f"{error.message} {error.detail}"
        return error.message
    return f"{type(error).__name__}: {error}"


def _submission_urls(submission_id: str) -> dict[str, str]:
    base = f"/api/researcher/submissions/{submission_id}"
    return {
        "bundle_url": f"{base}/bundle",
        "statement_url": f"{base}/statement",
        "transparent_url": f"{base}/transparent",
        "retry_url": f"{base}/deliver",
    }


def _write_meta(services: Services, submission_id: str, meta: dict[str, Any]) -> None:
    services.store.write_json(SUBMISSIONS, submission_id, META_FILE, meta)


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _summary(meta: dict[str, Any]) -> SubmissionSummary:
    scitt = _mapping(meta.get("scitt"))
    return SubmissionSummary(
        submission_id=str(meta.get("submission_id", "")),
        created_at=str(meta.get("created_at", "")),
        title=str(meta.get("title", "")),
        status=str(meta.get("status", "stored")),  # type: ignore[arg-type]
        scitt_txid=scitt.get("txid"),
        scitt_url=scitt.get("url"),
        bundle_bytes=meta.get("bundle_bytes"),
        msrc_submission_id=meta.get("msrc_submission_id"),
    )


def _response(
    submission_id: str,
    status: str,
    message: str,
    tracker: StageTracker,
    scitt: ScittResult,
    *,
    has_bundle: bool,
    msrc_submission_id: str | None = None,
) -> JSONResponse:
    urls = _submission_urls(submission_id)
    payload = SubmissionResponse(
        submission_id=submission_id,
        status=status,  # type: ignore[arg-type]
        message=message,
        stages=tracker.as_list(),
        scitt=scitt,
        msrc_submission_id=msrc_submission_id,
        bundle_url=urls["bundle_url"] if has_bundle else None,
        statement_url=urls["statement_url"],
        transparent_url=urls["transparent_url"] if scitt.registered else None,
        retry_url=urls["retry_url"] if status == "partial" else None,
    )
    return JSONResponse(
        status_code=STATUS_CODES[status], content=payload.model_dump(mode="json")
    )


@router.post("/enroll", response_model=EnrollmentResponse)
async def enroll(
    request: Request,
    subject: str = Form("Demo researcher"),
    private_key: UploadFile = File(...),
) -> EnrollmentResponse:
    """Derive a public key locally and obtain a short-lived MSRC leaf.

    The private key is read into a private temporary file, used by the command
    line tool to derive the public key, and removed before the response. Only
    the derived public key is transmitted to the mock MSRC service.
    """
    services = get_services(request)
    settings = services.settings
    subject_text = check_text_field("subject", subject, MAX_SHORT_CHARS, required=True)
    private_key_bytes = await read_upload(
        private_key, PRIVATE_KEY_UPLOAD, settings.max_pem_bytes
    )
    public_key = operations.derive_public_key(services.cli, private_key_bytes)
    del private_key_bytes

    material = await services.msrc.enroll(public_key=public_key, subject=subject_text)

    enrollment_id = services.store.create_record(ENROLLMENTS)
    services.store.write_bytes(
        ENROLLMENTS, enrollment_id, LEAF_CERT_FILE, material.leaf_certificate
    )
    services.store.write_bytes(
        ENROLLMENTS, enrollment_id, ROOT_CERT_FILE, material.root_certificate
    )
    created_at = material.created_at or now_text()
    services.store.write_json(
        ENROLLMENTS,
        enrollment_id,
        META_FILE,
        {
            "enrollment_id": enrollment_id,
            "created_at": created_at,
            "subject": subject_text,
            "msrc_enrollment_id": material.enrollment_id,
        },
    )
    return EnrollmentResponse(
        enrollment_id=enrollment_id,
        created_at=created_at,
        subject=subject_text,
        leaf_certificate_bytes=len(material.leaf_certificate),
        root_certificate_bytes=len(material.root_certificate),
        public_key_bytes=len(public_key),
    )


def _build_report(
    title: str,
    body: str,
    component: str,
    severity: str,
    fingerprint: str,
    references: str,
    max_text_chars: int,
) -> dict[str, Any]:
    reference_list = [line.strip() for line in references.split("\n") if line.strip()][
        :32
    ]
    return {
        "title": check_text_field("title", title, MAX_TITLE_CHARS, required=True),
        "body": check_text_field("body", body, max_text_chars, required=True),
        "component": check_text_field(
            "component", component, MAX_SHORT_CHARS, required=True
        ),
        "severity": check_text_field(
            "severity", severity, MAX_SHORT_CHARS, required=True
        ),
        "fingerprint": check_text_field(
            "fingerprint", fingerprint, MAX_SHORT_CHARS, required=False
        ),
        "references": reference_list,
    }


@router.post("/submit")
async def submit(
    request: Request,
    enrollment_id: str = Form(...),
    title: str = Form(...),
    body: str = Form(...),
    component: str = Form(...),
    severity: str = Form(...),
    fingerprint: str = Form(""),
    references: str = Form(""),
    private_key: UploadFile = File(...),
) -> Response:
    """Run the whole submission in a single, strictly ordered pipeline."""
    services = get_services(request)
    settings = services.settings
    tracker = StageTracker()

    enrollment = validate_record_id(enrollment_id)
    if not services.store.has_artifact(ENROLLMENTS, enrollment, LEAF_CERT_FILE):
        raise RequestError("Enroll with the mock MSRC service before submitting.")
    leaf_cert = services.store.read_bytes(ENROLLMENTS, enrollment, LEAF_CERT_FILE)
    root_cert = services.store.read_bytes(ENROLLMENTS, enrollment, ROOT_CERT_FILE)

    report = _build_report(
        title,
        body,
        component,
        severity,
        fingerprint,
        references,
        settings.max_text_chars,
    )
    private_key_bytes = await read_upload(
        private_key, PRIVATE_KEY_UPLOAD, settings.max_pem_bytes
    )

    submission_id = services.store.create_record(SUBMISSIONS)
    meta: dict[str, Any] = {
        "submission_id": submission_id,
        "created_at": now_text(),
        "title": report["title"],
        "status": "failed",
        "enrollment_id": enrollment,
        "scitt": {"registered": False, "txid": None, "url": settings.scitt_url},
        "msrc_submission_id": None,
        "bundle_bytes": None,
    }
    services.store.write_json(SUBMISSIONS, submission_id, REPORT_FILE, report)
    _write_meta(services, submission_id, meta)
    scitt_result = ScittResult(registered=False, url=settings.scitt_url)

    try:
        issued = operations.issue_statement(
            services.cli,
            report=report,
            private_key=private_key_bytes,
            leaf_cert=leaf_cert,
            root_cert=root_cert,
        )
    except (AppError, OSError) as error:
        tracker.failed("issue", _describe(error))
        return _response(
            submission_id,
            "failed",
            "The statement could not be created. Nothing was sent to SCITT or MSRC.",
            tracker,
            scitt_result,
            has_bundle=False,
        )
    finally:
        del private_key_bytes

    services.store.write_bytes(
        SUBMISSIONS, submission_id, REGISTERED_FILE, issued.registered_statement
    )
    services.store.write_bytes(
        SUBMISSIONS, submission_id, DISCLOSURES_FILE, issued.disclosures
    )
    tracker.passed(
        "issue", f"Registered statement is {len(issued.registered_statement)} bytes."
    )

    try:
        registration: ScittRegistration = await services.scitt.register(
            issued.registered_statement
        )
    except (AppError, OSError) as error:
        tracker.failed("scitt_register", _describe(error))
        return _response(
            submission_id,
            "failed",
            (
                "SCITT did not register the statement. The report and its "
                "disclosures were not sent to MSRC."
            ),
            tracker,
            scitt_result,
            has_bundle=False,
        )

    services.store.write_bytes(
        SUBMISSIONS, submission_id, TRANSPARENT_FILE, registration.transparent_statement
    )
    meta["scitt"] = {
        "registered": True,
        "txid": registration.txid,
        "url": registration.url,
    }
    meta["status"] = "partial"
    _write_meta(services, submission_id, meta)
    scitt_result = ScittResult(
        registered=True,
        txid=registration.txid,
        url=registration.url,
        transparent_statement_bytes=len(registration.transparent_statement),
    )
    tracker.passed(
        "scitt_register", f"Registered with transaction {registration.txid}."
    )

    try:
        bundle = operations.create_bundle(
            services.cli,
            registered_statement=issued.registered_statement,
            transparent_statement=registration.transparent_statement,
            disclosures=issued.disclosures,
            scitt_url=registration.url,
            txid=registration.txid,
        )
    except (AppError, OSError) as error:
        tracker.failed("bundle_create", _describe(error))
        _write_meta(services, submission_id, meta)
        return _response(
            submission_id,
            "partial",
            (
                "SCITT registration succeeded, but the proof bundle could not be "
                "built. Retry delivery to rebuild and send it."
            ),
            tracker,
            scitt_result,
            has_bundle=False,
        )

    services.store.write_bytes(SUBMISSIONS, submission_id, BUNDLE_FILE, bundle)
    meta["bundle_bytes"] = len(bundle)
    _write_meta(services, submission_id, meta)
    tracker.passed("bundle_create", f"Bundle is {len(bundle)} bytes.")

    try:
        msrc_submission_id = await services.msrc.submit_bundle(
            bundle=bundle,
            title=report["title"],
            scitt_txid=registration.txid,
            scitt_url=registration.url,
        )
    except (AppError, OSError) as error:
        tracker.failed("msrc_deliver", _describe(error))
        return _response(
            submission_id,
            "partial",
            (
                "SCITT registration succeeded, but the bundle was not delivered to "
                "MSRC. Download the bundle or retry delivery."
            ),
            tracker,
            scitt_result,
            has_bundle=True,
        )

    meta["msrc_submission_id"] = msrc_submission_id
    meta["status"] = "complete"
    _write_meta(services, submission_id, meta)
    tracker.passed("msrc_deliver", f"MSRC submission {msrc_submission_id}.")
    return _response(
        submission_id,
        "complete",
        "SCITT registered the statement and MSRC accepted the bundle.",
        tracker,
        scitt_result,
        has_bundle=True,
        msrc_submission_id=msrc_submission_id,
    )


@router.post("/submissions/{submission_id}/deliver")
async def deliver(request: Request, submission_id: str) -> Response:
    """Rebuild the bundle if needed and retry delivery to the mock MSRC."""
    services = get_services(request)
    record = validate_record_id(submission_id)
    meta = services.store.read_json(SUBMISSIONS, record, META_FILE)
    scitt_meta = _mapping(meta.get("scitt"))
    txid = scitt_meta.get("txid")
    url = scitt_meta.get("url") or services.settings.scitt_url
    tracker = StageTracker()
    tracker.skipped("issue", "Reusing the stored registered statement.")

    if not scitt_meta.get("registered") or not isinstance(txid, str):
        tracker.failed("scitt_register", "This submission was never registered.")
        return _response(
            record,
            "failed",
            "This submission was never registered with SCITT. Submit it again.",
            tracker,
            ScittResult(registered=False, url=url),
            has_bundle=False,
        )

    tracker.passed("scitt_register", f"Registered with transaction {txid}.")
    scitt_result = ScittResult(registered=True, txid=txid, url=url)

    if services.store.has_artifact(SUBMISSIONS, record, BUNDLE_FILE):
        bundle = services.store.read_bytes(SUBMISSIONS, record, BUNDLE_FILE)
        tracker.passed("bundle_create", "Reusing the stored bundle.")
    else:
        try:
            bundle = operations.create_bundle(
                services.cli,
                registered_statement=services.store.read_bytes(
                    SUBMISSIONS, record, REGISTERED_FILE
                ),
                transparent_statement=services.store.read_bytes(
                    SUBMISSIONS, record, TRANSPARENT_FILE
                ),
                disclosures=services.store.read_bytes(
                    SUBMISSIONS, record, DISCLOSURES_FILE
                ),
                scitt_url=url,
                txid=txid,
            )
        except (AppError, OSError) as error:
            tracker.failed("bundle_create", _describe(error))
            return _response(
                record,
                "partial",
                (
                    "SCITT registration is intact, but the bundle could not be "
                    "rebuilt."
                ),
                tracker,
                scitt_result,
                has_bundle=False,
            )
        services.store.write_bytes(SUBMISSIONS, record, BUNDLE_FILE, bundle)
        meta["bundle_bytes"] = len(bundle)
        _write_meta(services, record, meta)
        tracker.passed("bundle_create", f"Bundle is {len(bundle)} bytes.")

    try:
        msrc_submission_id = await services.msrc.submit_bundle(
            bundle=bundle,
            title=str(meta.get("title", "")),
            scitt_txid=txid,
            scitt_url=url,
        )
    except (AppError, OSError) as error:
        tracker.failed("msrc_deliver", _describe(error))
        return _response(
            record,
            "partial",
            (
                "SCITT registration is intact, but MSRC delivery failed again. "
                "Download the bundle or retry later."
            ),
            tracker,
            scitt_result,
            has_bundle=True,
        )

    meta["msrc_submission_id"] = msrc_submission_id
    meta["status"] = "complete"
    _write_meta(services, record, meta)
    tracker.passed("msrc_deliver", f"MSRC submission {msrc_submission_id}.")
    return _response(
        record,
        "complete",
        "The stored bundle was delivered to MSRC.",
        tracker,
        scitt_result,
        has_bundle=True,
        msrc_submission_id=msrc_submission_id,
    )


@router.get("/submissions", response_model=SubmissionList)
async def list_submissions(request: Request) -> SubmissionList:
    """Return the researcher submissions stored by this service."""
    services = get_services(request)
    summaries: list[SubmissionSummary] = []
    for record in services.store.list_records(SUBMISSIONS):
        if META_FILE not in record.artifacts:
            continue
        summaries.append(
            _summary(services.store.read_json(SUBMISSIONS, record.record_id, META_FILE))
        )
    return SubmissionList(submissions=summaries)


@router.get("/submissions/{submission_id}/bundle")
async def download_bundle(request: Request, submission_id: str) -> Response:
    """Download the stored proof bundle for recovery or manual delivery."""
    services = get_services(request)
    record = validate_record_id(submission_id)
    if not services.store.has_artifact(SUBMISSIONS, record, BUNDLE_FILE):
        raise NotFoundError("No bundle has been built for this submission yet.")
    payload = services.store.read_bytes(SUBMISSIONS, record, BUNDLE_FILE)
    return artifact_response(
        payload,
        prefix="bundle",
        record_id=record,
        suffix=".cbor",
        media_type="application/cbor",
    )


@router.get("/submissions/{submission_id}/statement")
async def download_statement(request: Request, submission_id: str) -> Response:
    """Download the exact registered statement that was sent to SCITT."""
    services = get_services(request)
    record = validate_record_id(submission_id)
    if not services.store.has_artifact(SUBMISSIONS, record, REGISTERED_FILE):
        raise NotFoundError("No registered statement is stored for this submission.")
    payload = services.store.read_bytes(SUBMISSIONS, record, REGISTERED_FILE)
    return artifact_response(
        payload,
        prefix="registered-statement",
        record_id=record,
        suffix=".cose",
        media_type="application/cose",
    )


@router.get("/submissions/{submission_id}/transparent")
async def download_transparent_statement(
    request: Request, submission_id: str
) -> Response:
    """Download the transparency token returned by SCITT.

    This is the exact transparent statement bytes the transparency service
    produced, kept verbatim so that an independent verifier can check the
    receipt against the registered statement.
    """
    services = get_services(request)
    record = validate_record_id(submission_id)
    if not services.store.has_artifact(SUBMISSIONS, record, TRANSPARENT_FILE):
        raise NotFoundError("No transparency token is stored for this submission yet.")
    payload = services.store.read_bytes(SUBMISSIONS, record, TRANSPARENT_FILE)
    return artifact_response(
        payload,
        prefix="transparent-statement",
        record_id=record,
        suffix=".cose",
        media_type="application/cose",
    )
