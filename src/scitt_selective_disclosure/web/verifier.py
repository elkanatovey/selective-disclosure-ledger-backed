# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Verifier routes: check a bundle against imported trust material."""

from __future__ import annotations

import json
from typing import Final

from fastapi import APIRouter, File, Request, Response, UploadFile

from .. import operations
from ..cli.parsing import parse_stored_report
from ..errors import NotFoundError, RequestError
from ..http_support import get_services, now_text
from ..models import VerificationReport, VerificationResponse
from ..storage import validate_record_id
from ..uploads import (
    BUNDLE_UPLOAD,
    CERTIFICATE_UPLOAD,
    JSON_UPLOAD,
    TRUST_UPLOAD,
    read_upload,
)

router = APIRouter(prefix="/api/verifier", tags=["verifier"])

REPORTS: Final = "reports"
REPORT_FILE: Final = "report.json"
META_FILE: Final = "meta.json"
BUNDLE_FILE: Final = "bundle.cbor"


@router.post("/verify", response_model=VerificationResponse)
async def verify(
    request: Request,
    bundle: UploadFile = File(...),
    msrc_root: UploadFile = File(...),
    scitt_trust: UploadFile = File(...),
) -> VerificationResponse:
    """Verify a bundle and store the report for export."""
    services = get_services(request)
    settings = services.settings
    bundle_bytes = await read_upload(bundle, BUNDLE_UPLOAD, settings.max_bundle_bytes)
    msrc_root_bytes = await read_upload(
        msrc_root, CERTIFICATE_UPLOAD, settings.max_pem_bytes
    )
    scitt_trust_bytes = await read_upload(
        scitt_trust, TRUST_UPLOAD, settings.max_json_bytes
    )

    report = operations.verify_bundle(
        services.cli,
        services.official_verifier,
        bundle=bundle_bytes,
        msrc_root=msrc_root_bytes,
        scitt_trust=scitt_trust_bytes,
        trust_name=scitt_trust.filename or "scitt-keys.cbor",
    )

    report_id = services.store.create_record(REPORTS)
    services.store.write_bytes(REPORTS, report_id, BUNDLE_FILE, bundle_bytes)
    services.store.write_json(
        REPORTS, report_id, REPORT_FILE, report.model_dump(mode="json")
    )
    services.store.write_json(
        REPORTS,
        report_id,
        META_FILE,
        {
            "report_id": report_id,
            "created_at": now_text(),
            "bundle_bytes": len(bundle_bytes),
            "overall": report.overall,
        },
    )
    return VerificationResponse(
        report_id=report_id,
        report=report,
        report_url=f"/api/verifier/reports/{report_id}",
    )


@router.get("/reports/{report_id}", response_model=VerificationReport)
async def export_report(request: Request, report_id: str) -> VerificationReport:
    """Export a stored verification report."""
    services = get_services(request)
    record = validate_record_id(report_id)
    if not services.store.has_artifact(REPORTS, record, REPORT_FILE):
        raise NotFoundError("No verification report exists for this identifier.")
    document = services.store.read_json(REPORTS, record, REPORT_FILE)
    return parse_stored_report(document)


@router.get("/reports/{report_id}/download")
async def download_report(request: Request, report_id: str) -> Response:
    """Download a stored verification report as a JSON attachment."""
    services = get_services(request)
    record = validate_record_id(report_id)
    if not services.store.has_artifact(REPORTS, record, REPORT_FILE):
        raise NotFoundError("No verification report exists for this identifier.")
    payload = services.store.read_bytes(REPORTS, record, REPORT_FILE)
    return Response(
        content=payload,
        media_type="application/json",
        headers={
            "content-disposition": (
                f'attachment; filename="verification-{record}.json"'
            ),
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
    )


@router.post("/reports/import", response_model=VerificationReport)
async def import_report(
    request: Request, report: UploadFile = File(...)
) -> VerificationReport:
    """Re-render a previously exported verification report."""
    services = get_services(request)
    payload = await read_upload(report, JSON_UPLOAD, services.settings.max_json_bytes)
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RequestError(
            "The report file is not valid JSON.", detail=str(error)
        ) from error
    return parse_stored_report(document)
