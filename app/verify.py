# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The reader's verifier.

Deliberately knows nothing: no MSRC, no transparency service, no state. Every
trust anchor arrives with the request, because a verifier that fetched its own
anchors from the parties it is checking would establish nothing. It exists as
its own service so that a reader need not run, or trust, either of the others.
"""

from __future__ import annotations

import json

import _native
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .common import MAX_BUNDLE_B64, decode_bundle, templates_for


class VerifyRequest(BaseModel):
    release_b64: str = Field(min_length=1, max_length=MAX_BUNDLE_B64)
    msrc_root_pem: str = Field(min_length=1, max_length=8192)
    scitt_cert_pem: str = Field(default="", max_length=8192)


def create_app() -> FastAPI:
    app = FastAPI(title="Verify")
    templates = templates_for(app)

    @app.get("/", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "verify.html", {})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/verify")
    async def verify(body: VerifyRequest) -> dict[str, object]:
        """Check a signed release against independently supplied anchors."""
        release = decode_bundle(body.release_b64)
        try:
            outcome = _native.verify_release(
                release,
                body.msrc_root_pem.encode("ascii"),
                body.scitt_cert_pem.encode("ascii") or None,
            )
        except (ValueError, UnicodeEncodeError) as error:
            raise HTTPException(400, f"Nothing to check: {error}") from error

        # What the release actually says, shown whether or not it verified:
        # a reader still needs to see which parts were withheld.
        contents: object = None
        try:
            bundle = _native.release_payload(release)
            contents = json.loads(_native.inspect_bundle(bundle))
        except ValueError:
            contents = None

        return {
            "passed": outcome["passed"],
            "attributable": outcome["attributable"],
            "report": json.loads(outcome["report_json"]),
            "contents": contents,
        }

    return app
