# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared FastAPI plumbing: templates, error handling and service lookup."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import cast

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .errors import AppError
from .models import ErrorResponse
from .services import Services
from .uploads import download_file_name

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def now_text() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def attach_services(app: FastAPI, services: Services) -> None:
    """Bind a service container to an application instance."""
    app.state.services = services


def get_services(request: Request) -> Services:
    """Return the service container bound to the running application."""
    return cast(Services, request.app.state.services)


def mount_static(app: FastAPI) -> None:
    """Serve the bundled stylesheet and scripts."""
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def install_error_handlers(app: FastAPI) -> None:
    """Return structured JSON for validation and application errors.

    Unexpected exceptions are deliberately not caught here so that they are
    logged by the server and surfaced as failures rather than silently
    converted into successful looking responses.
    """

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: Exception) -> JSONResponse:
        error = cast(AppError, exc)
        payload = ErrorResponse(
            error=error.code, message=error.message, detail=error.detail
        )
        return JSONResponse(
            status_code=error.status_code, content=payload.model_dump(mode="json")
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
        error = cast(RequestValidationError, exc)
        first = error.errors()[0] if error.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", ()))
        payload = ErrorResponse(
            error="invalid_request",
            message="The request could not be processed.",
            detail=f"{location}: {first.get('msg', 'invalid value')}".strip(": "),
        )
        return JSONResponse(status_code=400, content=payload.model_dump(mode="json"))


def artifact_response(
    payload: bytes, *, prefix: str, record_id: str, suffix: str, media_type: str
) -> Response:
    """Return opaque bytes as a downloadable attachment."""
    name = download_file_name(prefix, record_id, suffix)
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "content-disposition": f'attachment; filename="{name}"',
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
    )
