# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Researcher demo.

The browser generates an ephemeral P-256 key, keeps it, and signs exactly one
thing: the bytes this backend hands it. The backend never sees a private key.

One submission runs three ordered steps once the signature arrives: assemble
the registered statement, register it with the mock transparency service, then
send the full bundle (disclosures and receipt) to the mock MSRC.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

import _native
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .mocks import MockMsrc, MockScitt, evict

HERE = Path(__file__).parent
SCITT_URL = "https://transparency.example"
ES256_SIGNATURE_BYTES = 64


class EnrollRequest(BaseModel):
    public_key_pem: str = Field(min_length=1, max_length=4096)
    subject: str = Field(default="Demo researcher", min_length=1, max_length=120)


class PrepareRequest(BaseModel):
    enrollment_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20000)
    component: str = Field(min_length=1, max_length=120)
    severity: str = Field(min_length=1, max_length=120)
    fingerprint: str = Field(default="", max_length=200)
    references: list[str] = Field(default_factory=list, max_length=32)


class SubmitRequest(BaseModel):
    prepare_id: str = Field(min_length=1, max_length=64)
    signature_b64: str = Field(min_length=1, max_length=256)


MAX_BUNDLE_B64 = 8 * 1024 * 1024


class InspectRequest(BaseModel):
    bundle_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)


class ReleaseRequest(BaseModel):
    bundle_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)
    redact_fields: list[str] = Field(default_factory=list, max_length=16)
    redact_body_chunks: list[int] = Field(default_factory=list, max_length=8192)
    public_key_pem: str = Field(min_length=1, max_length=4096)


class DiscloserKeyRequest(BaseModel):
    public_key_pem: str = Field(min_length=1, max_length=4096)


class SignReleaseRequest(BaseModel):
    release_id: str = Field(min_length=1, max_length=64)
    signature_b64: str = Field(min_length=1, max_length=256)


@dataclass
class Prepared:
    """What is held between handing out the bytes and getting the signature."""

    enrollment_id: str
    title: str
    protected_header: bytes
    payload: bytes
    disclosures: bytes


@dataclass
class PreparedRelease:
    """The presentation, held until MSRC's signature comes back."""

    protected_header: bytes
    payload: bytes


def _decode_signature(encoded: str) -> bytes:
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(400, "The signature is not valid base64.") from error
    if len(signature) != ES256_SIGNATURE_BYTES:
        raise HTTPException(400, "The signature must be 64 bytes of raw r||s.")
    return signature


def _decode_bundle(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(400, "The bundle is not valid base64.") from error


def create_app() -> FastAPI:
    app = FastAPI(title="SCITT selective-disclosure researcher demo")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    msrc = MockMsrc()
    scitt = MockScitt()
    pending: dict[str, Prepared] = {}
    pending_releases: dict[str, PreparedRelease] = {}

    @app.get("/", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "researcher.html", {})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/enroll")
    async def enroll(body: EnrollRequest) -> dict[str, str]:
        """Exchange the public half of the browser's key for a leaf cert."""
        try:
            record = msrc.enroll(body.public_key_pem.encode("ascii"), body.subject)
        except (ValueError, UnicodeEncodeError) as error:
            raise HTTPException(400, f"The public key was refused: {error}") from error
        return {
            "enrollment_id": record.enrollment_id,
            "subject": record.subject,
            "issuer_did": msrc.issuer_did,
        }

    @app.post("/api/prepare")
    async def prepare(body: PrepareRequest) -> dict[str, object]:
        """Build the redacted statement and return the bytes to sign."""
        record = msrc.enrollments.get(body.enrollment_id)
        if record is None:
            raise HTTPException(404, "Enroll before preparing a report.")

        report = json.dumps(
            {
                "title": body.title,
                "body": body.body,
                "component": body.component,
                "severity": body.severity,
                "fingerprint": body.fingerprint,
                "references": [r for r in body.references if r.strip()],
            }
        )
        try:
            built = _native.prepare_statement(
                report,
                record.public_key,
                record.leaf_cert,
                msrc.root_cert,
                msrc.disclosure_public_key,
            )
        except ValueError as error:
            raise HTTPException(400, f"The report was refused: {error}") from error

        prepare_id = secrets.token_hex(8)
        evict(pending)
        pending[prepare_id] = Prepared(
            enrollment_id=record.enrollment_id,
            title=body.title,
            protected_header=built["protected_header"],
            payload=built["payload"],
            disclosures=built["disclosures"],
        )
        return {
            "prepare_id": prepare_id,
            "to_be_signed_b64": base64.b64encode(built["to_be_signed"]).decode(),
            "disclosure_count": built["disclosure_count"],
            "body_chunk_count": built["body_chunk_count"],
            "issuer_did": built["issuer_did"],
        }

    @app.post("/api/submit")
    async def submit(body: SubmitRequest) -> dict[str, object]:
        """Attach the signature, register, then deliver the bundle."""
        held = pending.pop(body.prepare_id, None)
        if held is None:
            raise HTTPException(404, "Prepare a report before submitting it.")
        signature = _decode_signature(body.signature_b64)

        stages: list[dict[str, str]] = []
        try:
            statement = _native.attach_signature(
                held.protected_header, held.payload, signature
            )
        except ValueError as error:
            raise HTTPException(400, f"The signature was refused: {error}") from error
        stages.append(
            {
                "name": "sign",
                "detail": f"Registered statement is {len(statement)} bytes.",
            }
        )

        txid, transparent = scitt.register(statement)
        stages.append({"name": "register", "detail": f"Transaction {txid}."})

        bundle = _native.create_bundle(
            statement, transparent, held.disclosures, SCITT_URL, txid
        )
        stages.append({"name": "bundle", "detail": f"Bundle is {len(bundle)} bytes."})

        received = msrc.receive(bundle, held.title, txid)
        stages.append(
            {"name": "deliver", "detail": f"MSRC submission {received.submission_id}."}
        )
        return {
            "submission_id": received.submission_id,
            "txid": txid,
            "scitt_url": SCITT_URL,
            "bundle_bytes": len(bundle),
            "stages": stages,
        }

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

    @app.get("/msrc", response_class=HTMLResponse)
    async def msrc_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "msrc.html", {})

    @app.post("/api/msrc/inspect")
    async def msrc_inspect(body: InspectRequest) -> dict[str, object]:
        """Read a bundle MSRC holds, so it can choose what to withhold."""
        bundle = _decode_bundle(body.bundle_b64)
        try:
            return {"inspection": json.loads(_native.inspect_bundle(bundle))}
        except ValueError as error:
            raise HTTPException(
                400, f"That bundle could not be read: {error}"
            ) from error

    @app.post("/api/msrc/key")
    async def msrc_key(body: DiscloserKeyRequest) -> dict[str, str]:
        """Register the key that future statements will name in cnf."""
        try:
            msrc.register_disclosure_key(body.public_key_pem.encode("ascii"))
        except UnicodeEncodeError as error:
            raise HTTPException(400, "The public key must be ASCII PEM.") from error
        return {"status": "registered"}

    @app.post("/api/msrc/release")
    async def msrc_release(body: ReleaseRequest) -> dict[str, object]:
        """Drop the selected disclosures, then hand back the bytes to sign."""
        bundle = _decode_bundle(body.bundle_b64)
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

    @app.post("/api/msrc/sign")
    async def msrc_sign(body: SignReleaseRequest) -> dict[str, object]:
        """Attach MSRC's signature to the presentation it approved."""
        held = pending_releases.pop(body.release_id, None)
        if held is None:
            raise HTTPException(404, "Prepare a release before signing it.")
        signature = _decode_signature(body.signature_b64)
        try:
            release = _native.attach_signature(
                held.protected_header, held.payload, signature
            )
        except ValueError as error:
            raise HTTPException(400, f"The signature was refused: {error}") from error
        return {
            "release_b64": base64.b64encode(release).decode(),
            "release_bytes": len(release),
        }

    return app
