# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""MSRC's service: the certificate authority, the intake, and the release desk.

Separate from the researcher because these are separate parties. This process
holds MSRC's CA key and nothing of the researcher's; the key MSRC signs
releases with is not here either, it stays in MSRC's browser and only its
public half is ever published.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

import _native
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from .common import (
    MAX_BUNDLE_B64,
    decode_bundle,
    decode_signature,
    evict,
    templates_for,
)
from .mocks import MockMsrc


class EnrollRequest(BaseModel):
    public_key_pem: str = Field(min_length=1, max_length=4096)
    subject: str = Field(default="Demo researcher", min_length=1, max_length=120)


class DiscloserKeyRequest(BaseModel):
    public_key_pem: str = Field(min_length=1, max_length=4096)


class SubmissionRequest(BaseModel):
    bundle_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)
    title: str = Field(min_length=1, max_length=200)
    txid: str = Field(min_length=1, max_length=120)


class InspectRequest(BaseModel):
    bundle_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)


class ReleaseRequest(BaseModel):
    bundle_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)
    redact_fields: list[str] = Field(default_factory=list, max_length=16)
    redact_body_chunks: list[int] = Field(default_factory=list, max_length=8192)
    public_key_pem: str = Field(min_length=1, max_length=4096)


class SignReleaseRequest(BaseModel):
    release_id: str = Field(min_length=1, max_length=64)
    signature_b64: str = Field(min_length=1, max_length=256)


@dataclass
class PreparedRelease:
    """The presentation, held until MSRC's browser returns its signature."""

    protected_header: bytes
    payload: bytes


def create_app() -> FastAPI:
    app = FastAPI(title="MSRC")
    templates = templates_for(app)

    msrc = MockMsrc()
    pending_releases: dict[str, PreparedRelease] = {}

    @app.get("/", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "msrc.html", {})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # --- the certificate authority -------------------------------------------

    @app.post("/api/enroll")
    async def enroll(body: EnrollRequest) -> dict[str, str]:
        """Endorse a public key. The private half never comes here."""
        try:
            record = msrc.enroll(body.public_key_pem.encode("ascii"), body.subject)
        except (ValueError, UnicodeEncodeError) as error:
            raise HTTPException(400, f"The public key was refused: {error}") from error
        return {
            "enrollment_id": record.enrollment_id,
            "subject": record.subject,
            "issuer_did": msrc.issuer_did,
            "leaf_cert_pem": record.leaf_cert.decode("ascii"),
            "root_cert_pem": msrc.root_cert.decode("ascii"),
        }

    @app.get("/api/root")
    async def root_certificate() -> Response:
        """MSRC's CA certificate, which a reader needs to check any release."""
        return Response(
            content=msrc.root_cert,
            media_type="application/x-pem-file",
            headers={"content-disposition": 'attachment; filename="msrc-root.pem"'},
        )

    # --- the key MSRC signs releases with ------------------------------------

    @app.post("/api/key")
    async def publish_key(body: DiscloserKeyRequest) -> dict[str, str]:
        """Make MSRC's release key known, so statements can name it in cnf."""
        try:
            msrc.publish_disclosure_key(body.public_key_pem.encode("ascii"))
        except UnicodeEncodeError as error:
            raise HTTPException(400, "The public key must be ASCII PEM.") from error
        return {"status": "published"}

    @app.get("/api/disclosure-key")
    async def disclosure_key() -> dict[str, str]:
        """The published half, for a researcher naming it in a statement."""
        return {"public_key_pem": msrc.disclosure_public_key.decode("ascii")}

    # --- intake ---------------------------------------------------------------

    @app.post("/api/submissions")
    async def receive(body: SubmissionRequest) -> dict[str, str]:
        """Accept a bundle a researcher has already checked for itself."""
        bundle = decode_bundle(body.bundle_b64)
        record = msrc.receive(bundle, body.title, body.txid)
        return {"submission_id": record.submission_id}

    @app.get("/api/submissions/{submission_id}")
    async def inspect(submission_id: str) -> dict[str, object]:
        """What MSRC can actually read out of the bundle it received."""
        record = msrc.submissions.get(submission_id)
        if record is None:
            raise HTTPException(404, "No such submission.")
        return {
            "submission_id": record.submission_id,
            "txid": record.txid,
            "inspection": json.loads(_native.inspect_bundle(record.bundle)),
        }

    @app.get("/api/submissions/{submission_id}/bundle")
    async def download(submission_id: str) -> Response:
        """The exact bundle bytes MSRC received, for offline verification."""
        record = msrc.submissions.get(submission_id)
        if record is None:
            raise HTTPException(404, "No such submission.")
        # The id is server-generated hex, so it is safe in a filename.
        return Response(
            content=record.bundle,
            media_type="application/cbor",
            headers={
                "content-disposition": (
                    f'attachment; filename="{record.submission_id}.cbor"'
                )
            },
        )

    # --- the release desk -----------------------------------------------------

    @app.post("/api/inspect")
    async def inspect_loaded(body: InspectRequest) -> dict[str, object]:
        """Read a bundle MSRC holds, so it can choose what to withhold."""
        bundle = decode_bundle(body.bundle_b64)
        try:
            return {"inspection": json.loads(_native.inspect_bundle(bundle))}
        except ValueError as error:
            raise HTTPException(
                400, f"That bundle could not be read: {error}"
            ) from error

    @app.post("/api/release")
    async def release(body: ReleaseRequest) -> dict[str, object]:
        """Drop the selected disclosures, then hand back the bytes to sign."""
        bundle = decode_bundle(body.bundle_b64)
        selection = json.dumps(
            {
                "version": 1,
                "redact_fields": body.redact_fields,
                "redact_body_chunks": body.redact_body_chunks,
            }
        )
        try:
            presented = _native.present_bundle(bundle, selection)
            prepared = _native.prepare_release(
                presented, body.public_key_pem.encode("ascii")
            )
        except (ValueError, UnicodeEncodeError) as error:
            raise HTTPException(400, f"The redaction was refused: {error}") from error

        release_id = secrets.token_hex(8)
        evict(pending_releases)
        pending_releases[release_id] = PreparedRelease(
            protected_header=prepared["protected_header"],
            payload=prepared["payload"],
        )
        return {
            "release_id": release_id,
            "to_be_signed_b64": base64.b64encode(prepared["to_be_signed"]).decode(),
            "presented_bytes": len(presented),
        }

    @app.post("/api/sign")
    async def sign(body: SignReleaseRequest) -> dict[str, object]:
        """Attach MSRC's signature to the presentation it approved."""
        held = pending_releases.pop(body.release_id, None)
        if held is None:
            raise HTTPException(404, "Prepare a release before signing it.")
        signature = decode_signature(body.signature_b64)
        try:
            signed: bytes = _native.attach_signature(
                held.protected_header, held.payload, signature
            )
        except ValueError as error:
            raise HTTPException(400, f"The signature was refused: {error}") from error
        return {
            "release_b64": base64.b64encode(signed).decode(),
            "release_bytes": len(signed),
        }

    return app
