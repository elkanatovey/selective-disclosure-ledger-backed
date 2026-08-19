# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The researcher's own agent.

It holds no key: the browser generates one, keeps it, and signs exactly the
bytes this process hands over. What this process does hold is the researcher's
interest in the transaction, which is why it checks the receipt itself before
handing anything to MSRC. A transparency service that registered nothing, or an
MSRC that later denied receiving the report, would both be caught here rather
than being taken on trust.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass

import _native
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from .common import decode_signature, evict, templates_for
from .msrc_client import MsrcClient, MsrcError
from .scitt import ScittError, from_environment


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


@dataclass
class Enrolled:
    """The certificate MSRC issued for the key the browser is holding."""

    public_key: bytes
    leaf_cert: bytes
    root_cert: bytes
    issuer_did: str


@dataclass
class Prepared:
    """What is held between handing out the bytes and getting the signature."""

    enrollment_id: str
    title: str
    protected_header: bytes
    payload: bytes
    disclosures: bytes


def create_app() -> FastAPI:
    app = FastAPI(title="Researcher")
    templates = templates_for(app)

    scitt = from_environment()
    msrc = MsrcClient(os.environ.get("MSRC_URL", "http://127.0.0.1:8081"))
    enrolled: dict[str, Enrolled] = {}
    pending: dict[str, Prepared] = {}
    bundles: dict[str, bytes] = {}

    @app.get("/", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "researcher.html", {})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/enroll")
    async def enroll(body: EnrollRequest) -> dict[str, str]:
        """Ask MSRC to certify the public half of the browser's key."""
        try:
            record = msrc.enroll(body.public_key_pem, body.subject)
        except MsrcError as error:
            raise HTTPException(502, str(error)) from error

        evict(enrolled)
        enrolled[record.enrollment_id] = Enrolled(
            public_key=body.public_key_pem.encode("ascii"),
            leaf_cert=record.leaf_cert_pem.encode("ascii"),
            root_cert=record.root_cert_pem.encode("ascii"),
            issuer_did=record.issuer_did,
        )
        return {
            "enrollment_id": record.enrollment_id,
            "subject": record.subject,
            "issuer_did": record.issuer_did,
        }

    @app.post("/api/prepare")
    async def prepare(body: PrepareRequest) -> dict[str, object]:
        """Build the redacted statement and return the bytes to sign."""
        record = enrolled.get(body.enrollment_id)
        if record is None:
            raise HTTPException(404, "Enroll before preparing a report.")

        # The key MSRC will sign releases with, so the statement can name it.
        try:
            disclosure_key = msrc.disclosure_key()
        except MsrcError as error:
            raise HTTPException(502, str(error)) from error

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
                record.root_cert,
                disclosure_key.encode("ascii"),
            )
        except ValueError as error:
            raise HTTPException(400, f"The report was refused: {error}") from error

        prepare_id = secrets.token_hex(8)
        evict(pending)
        pending[prepare_id] = Prepared(
            enrollment_id=body.enrollment_id,
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
        """Register, check the receipt, and only then hand MSRC the bundle."""
        held = pending.pop(body.prepare_id, None)
        if held is None:
            raise HTTPException(404, "Prepare a report before submitting it.")
        record = enrolled.get(held.enrollment_id)
        if record is None:
            raise HTTPException(404, "That enrollment is no longer held.")
        signature = decode_signature(body.signature_b64)

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

        try:
            registration = scitt.register(statement)
        except ScittError as error:
            raise HTTPException(502, str(error)) from error
        stages.append(
            {"name": "register", "detail": f"Transaction {registration.txid}."}
        )

        bundle: bytes = _native.create_bundle(
            statement,
            registration.transparent_statement,
            held.disclosures,
            scitt.url,
            registration.txid,
        )

        # The researcher's own check, before MSRC is told anything. Registration
        # is the service's claim until the receipt has been verified against the
        # service identity, so nothing is sent on until it has been.
        check_receipt(bundle, record.root_cert, scitt.service_identity)
        stages.append(
            {
                "name": "verify",
                "detail": "Receipt verified against the transparency service.",
            }
        )

        try:
            submission_id = msrc.submit(bundle, held.title, registration.txid)
        except MsrcError as error:
            raise HTTPException(502, str(error)) from error
        stages.append(
            {"name": "deliver", "detail": f"MSRC submission {submission_id}."}
        )

        evict(bundles)
        bundles[submission_id] = bundle
        return {
            "submission_id": submission_id,
            "txid": registration.txid,
            "scitt_url": scitt.url,
            "bundle_bytes": len(bundle),
            "stages": stages,
        }

    @app.get("/api/bundle/{submission_id}")
    async def download(submission_id: str) -> Response:
        """The bundle this researcher produced, for keeping or checking."""
        bundle = bundles.get(submission_id)
        if bundle is None:
            raise HTTPException(404, "No such submission.")
        # The id came from MSRC as hex, so it is checked before use in a name.
        if not all(c in "0123456789abcdef" for c in submission_id):
            raise HTTPException(400, "That submission id is malformed.")
        return Response(
            content=bundle,
            media_type="application/cbor",
            headers={
                "content-disposition": f'attachment; filename="{submission_id}.cbor"'
            },
        )

    return app


def check_receipt(bundle: bytes, msrc_root: bytes, service_cert: bytes) -> None:
    """Verify the bundle, and refuse to go further unless the receipt passed.

    `overall` alone is not enough: it is true when the receipt was never
    checked, which is exactly the case this gate exists to catch.
    """
    try:
        report = json.loads(_native.verify_bundle(bundle, msrc_root, service_cert))
    except ValueError as error:
        raise HTTPException(
            502, f"The bundle this service produced does not verify: {error}"
        ) from error

    checks = {check["id"]: check["status"] for check in report["checks"]}
    if report["overall"] != "pass" or checks.get("scitt_receipt") != "pass":
        raise HTTPException(
            502,
            "The transparency service did not return a usable receipt, so the "
            f"report was not sent to MSRC. Checks: {checks}",
        )
