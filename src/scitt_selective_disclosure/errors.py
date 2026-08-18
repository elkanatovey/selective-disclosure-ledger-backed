# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Application errors mapped to deterministic HTTP responses."""

from __future__ import annotations

MAX_DETAIL_CHARS = 2000


def truncate_detail(text: str, limit: int = MAX_DETAIL_CHARS) -> str:
    """Return a bounded, single-paragraph rendering of diagnostic text."""
    collapsed = text.strip()
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + " [truncated]"


class AppError(Exception):
    """Base class for errors that translate into a structured response."""

    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = truncate_detail(detail) if detail else None


class UploadError(AppError):
    """An uploaded artifact failed validation."""

    status_code = 400
    code = "invalid_upload"


class RequestError(AppError):
    """A request field failed validation."""

    status_code = 400
    code = "invalid_request"


class NotFoundError(AppError):
    """A stored record does not exist."""

    status_code = 404
    code = "not_found"


class ConfigurationError(AppError):
    """The service is missing configuration required for the operation."""

    status_code = 503
    code = "not_configured"


class CapacityError(AppError):
    """A bounded demo store is full."""

    status_code = 507
    code = "store_full"


class CliError(AppError):
    """The selective-disclosure command line tool reported a failure."""

    status_code = 502
    code = "cli_failed"

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        returncode: int | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        self.returncode = returncode


class CliTimeoutError(CliError):
    """The command line tool exceeded its timeout."""

    status_code = 504
    code = "cli_timeout"


class RemoteServiceError(AppError):
    """A remote demo service returned an unusable response."""

    status_code = 502
    code = "remote_failed"


class ScittError(RemoteServiceError):
    """The transparency service did not register the statement."""

    code = "scitt_failed"
