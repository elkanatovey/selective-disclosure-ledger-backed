# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""MSRC routes: inspect imported or stored bundles and export presentations.

The server never inspects CBOR. Field and body chunk rendering comes from the
command line tool's JSON inspection report, and the browser only returns the
stable indices that report carried.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, File, Request, Response, UploadFile

from .. import operations
from ..errors import NotFoundError
from ..http_support import artifact_response, get_services, now_text
from ..models import (
    InspectionResponse,
    PresentationResponse,
    SelectionRequest,
    StoredSubmissionList,
)
from ..storage import validate_record_id
from ..uploads import BUNDLE_UPLOAD, read_upload

router = APIRouter(prefix="/api/msrc", tags=["msrc"])

IMPORTS: Final = "imports"
PRESENTATIONS: Final = "presentations"
BUNDLE_FILE: Final = "bundle.cbor"
META_FILE: Final = "meta.json"
PRESENTED_FILE: Final = "presented.cbor"
SELECTION_FILE: Final = "selection.json"


def _store_import(
    request: Request, bundle: bytes, source: str, submission_id: str | None
) -> str:
    services = get_services(request)
    bundle_id = services.store.create_record(IMPORTS)
    services.store.write_bytes(IMPORTS, bundle_id, BUNDLE_FILE, bundle)
    services.store.write_json(
        IMPORTS,
        bundle_id,
        META_FILE,
        {
            "bundle_id": bundle_id,
            "created_at": now_text(),
            "source": source,
            "submission_id": submission_id,
            "bundle_bytes": len(bundle),
        },
    )
    return bundle_id


@router.get("/submissions", response_model=StoredSubmissionList)
async def list_submissions(request: Request) -> StoredSubmissionList:
    """List the submissions held by the mock MSRC service."""
    services = get_services(request)
    return StoredSubmissionList(submissions=await services.msrc.list_submissions())


@router.post("/inspect", response_model=InspectionResponse)
async def inspect_upload(
    request: Request, bundle: UploadFile = File(...)
) -> InspectionResponse:
    """Import a bundle file and render its disclosures."""
    services = get_services(request)
    payload = await read_upload(
        bundle, BUNDLE_UPLOAD, services.settings.max_bundle_bytes
    )
    bundle_id = _store_import(request, payload, "upload", None)
    inspection = operations.inspect_bundle(services.cli, payload)
    return InspectionResponse(
        bundle_id=bundle_id,
        bundle_bytes=len(payload),
        source="upload",
        submission_id=None,
        inspection=inspection,
    )


@router.post("/submissions/{submission_id}/inspect", response_model=InspectionResponse)
async def inspect_submission(
    request: Request, submission_id: str
) -> InspectionResponse:
    """Fetch a stored submission from the mock MSRC and render it."""
    services = get_services(request)
    record = validate_record_id(submission_id)
    payload = await services.msrc.fetch_bundle(record)
    bundle_id = _store_import(request, payload, "submission", record)
    inspection = operations.inspect_bundle(services.cli, payload)
    return InspectionResponse(
        bundle_id=bundle_id,
        bundle_bytes=len(payload),
        source="submission",
        submission_id=record,
        inspection=inspection,
    )


@router.post("/imports/{bundle_id}/present", response_model=PresentationResponse)
async def present(
    request: Request, bundle_id: str, selection: SelectionRequest
) -> PresentationResponse:
    """Drop selected field and body chunk disclosures from a bundle."""
    services = get_services(request)
    record = validate_record_id(bundle_id)
    if not services.store.has_artifact(IMPORTS, record, BUNDLE_FILE):
        raise NotFoundError("Import the bundle again before presenting it.")
    payload = services.store.read_bytes(IMPORTS, record, BUNDLE_FILE)
    presented = operations.present_bundle(services.cli, payload, selection)

    presentation_id = services.store.create_record(PRESENTATIONS)
    services.store.write_bytes(
        PRESENTATIONS, presentation_id, PRESENTED_FILE, presented
    )
    services.store.write_json(
        PRESENTATIONS,
        presentation_id,
        SELECTION_FILE,
        selection.to_cli_document(),
    )
    services.store.write_json(
        PRESENTATIONS,
        presentation_id,
        META_FILE,
        {
            "presentation_id": presentation_id,
            "bundle_id": record,
            "created_at": now_text(),
            "bundle_bytes": len(presented),
        },
    )
    return PresentationResponse(
        presentation_id=presentation_id,
        bundle_id=record,
        bundle_bytes=len(presented),
        download_url=f"/api/msrc/presentations/{presentation_id}/bundle",
        redacted_fields=list(selection.redact_fields),
        redacted_body_chunks=list(selection.redact_body_chunks),
    )


@router.get("/presentations/{presentation_id}/bundle")
async def download_presentation(request: Request, presentation_id: str) -> Response:
    """Export the presented bundle for a verifier."""
    services = get_services(request)
    record = validate_record_id(presentation_id)
    if not services.store.has_artifact(PRESENTATIONS, record, PRESENTED_FILE):
        raise NotFoundError("No presented bundle exists for this identifier.")
    payload = services.store.read_bytes(PRESENTATIONS, record, PRESENTED_FILE)
    return artifact_response(
        payload,
        prefix="presented-bundle",
        record_id=record,
        suffix=".cbor",
        media_type="application/cbor",
    )
