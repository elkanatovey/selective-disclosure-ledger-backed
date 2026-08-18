# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Application factory for the role based web control plane."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from ..cli.runner import SubprocessCliRunner
from ..http_support import (
    attach_services,
    get_services,
    install_error_handlers,
    mount_static,
    templates,
)
from ..models import HealthResponse
from ..services import Services, build_services
from . import msrc, researcher, verifier

SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
}

ROLES = (
    ("researcher", "Researcher", "Create, register and deliver a bug report."),
    ("msrc", "MSRC", "Review a report and drop disclosures before sharing."),
    ("verifier", "Verifier", "Check a bundle against independent trust anchors."),
)


def create_app(services: Services | None = None) -> FastAPI:
    """Build the researcher, MSRC and verifier web application."""
    app = FastAPI(
        title="SCITT selective-disclosure demo",
        description=(
            "Demonstration control plane. All cryptographic work is performed by "
            "the C++ selective-disclosure tool."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    attach_services(app, services if services is not None else build_services())
    install_error_handlers(app)
    mount_static(app)

    @app.middleware("http")
    async def _security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz(request: Request) -> HealthResponse:
        services_ = get_services(request)
        runner = services_.cli.runner
        configured = (
            runner.available if isinstance(runner, SubprocessCliRunner) else True
        )
        return HealthResponse(service="web", cli_configured=configured)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        return templates.TemplateResponse(
            request, "index.html", {"roles": ROLES, "active": "index"}
        )

    @app.get("/researcher", response_class=HTMLResponse)
    async def researcher_page(request: Request) -> Response:
        settings = get_services(request).settings
        return templates.TemplateResponse(
            request,
            "researcher.html",
            {
                "active": "researcher",
                "scitt_url": settings.scitt_url,
                "msrc_url": settings.msrc_url,
                "max_text_chars": settings.max_text_chars,
            },
        )

    @app.get("/msrc", response_class=HTMLResponse)
    async def msrc_page(request: Request) -> Response:
        settings = get_services(request).settings
        return templates.TemplateResponse(
            request,
            "msrc.html",
            {
                "active": "msrc",
                "msrc_url": settings.msrc_url,
                "max_bundle_bytes": settings.max_bundle_bytes,
            },
        )

    @app.get("/verifier", response_class=HTMLResponse)
    async def verifier_page(request: Request) -> Response:
        settings = get_services(request).settings
        return templates.TemplateResponse(
            request,
            "verifier.html",
            {
                "active": "verifier",
                "max_bundle_bytes": settings.max_bundle_bytes,
            },
        )

    app.include_router(researcher.router)
    app.include_router(msrc.router)
    app.include_router(verifier.router)
    return app
