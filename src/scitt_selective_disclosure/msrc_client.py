# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Client for the mock MSRC service used by the web control plane."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings
from .errors import RemoteServiceError
from .models import StoredSubmission
from .scitt import HttpClientFactory
from .storage import validate_record_id

BODY_PREVIEW_CHARS = 200


@dataclass(frozen=True)
class EnrollmentMaterial:
    """Opaque certificate bytes returned by the mock MSRC enrollment."""

    enrollment_id: str
    subject: str
    created_at: str
    leaf_certificate: bytes
    root_certificate: bytes


def _preview(response: httpx.Response) -> str:
    body = response.text[:BODY_PREVIEW_CHARS]
    return f"status={response.status_code} body={body}"


def _decode_b64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RemoteServiceError(f"The mock MSRC service omitted the {label}.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise RemoteServiceError(
            f"The mock MSRC service returned an unusable {label}."
        ) from error


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        document = response.json()
    except ValueError as error:
        raise RemoteServiceError(
            "The mock MSRC service returned a malformed response.",
            detail=_preview(response),
        ) from error
    if not isinstance(document, dict):
        raise RemoteServiceError(
            "The mock MSRC service returned an unexpected response.",
            detail=_preview(response),
        )
    return document


class MsrcClient:
    """Talks to the separate mock MSRC service over HTTP."""

    def __init__(self, base_url: str, client_factory: HttpClientFactory) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_factory = client_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> MsrcClient:
        """Build a client for the configured mock MSRC endpoint."""

        def factory() -> httpx.AsyncClient:
            return httpx.AsyncClient(
                base_url=settings.msrc_url, timeout=settings.msrc_timeout
            )

        return cls(settings.msrc_url, factory)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            async with self._client_factory() as client:
                response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as error:
            raise RemoteServiceError(
                "The mock MSRC service could not be reached.",
                detail=f"{type(error).__name__}: {error}",
            ) from error
        if response.status_code >= 400:
            raise RemoteServiceError(
                "The mock MSRC service returned an error.",
                detail=_preview(response),
            )
        return response

    async def enroll(self, *, public_key: bytes, subject: str) -> EnrollmentMaterial:
        """Exchange a public key for a short-lived leaf certificate."""
        response = await self._request(
            "POST",
            "/enroll",
            files={"public_key": ("public.pem", public_key, "application/x-pem-file")},
            data={"subject": subject},
        )
        document = _json_object(response)
        enrollment_id = document.get("enrollment_id")
        if not isinstance(enrollment_id, str) or not enrollment_id:
            raise RemoteServiceError("The mock MSRC service omitted an enrollment id.")
        return EnrollmentMaterial(
            enrollment_id=enrollment_id,
            subject=str(document.get("subject", subject)),
            created_at=str(document.get("created_at", "")),
            leaf_certificate=_decode_b64(
                document.get("leaf_certificate_b64"), "leaf certificate"
            ),
            root_certificate=_decode_b64(
                document.get("root_certificate_b64"), "root certificate"
            ),
        )

    async def submit_bundle(
        self,
        *,
        bundle: bytes,
        title: str,
        scitt_txid: str,
        scitt_url: str,
    ) -> str:
        """Deliver the proof bundle and return the MSRC submission id."""
        response = await self._request(
            "POST",
            "/submissions",
            files={"bundle": ("bundle.cbor", bundle, "application/cbor")},
            data={"title": title, "scitt_txid": scitt_txid, "scitt_url": scitt_url},
        )
        document = _json_object(response)
        submission_id = document.get("submission_id")
        if not isinstance(submission_id, str) or not submission_id:
            raise RemoteServiceError("The mock MSRC service omitted a submission id.")
        return submission_id

    async def list_submissions(self) -> list[StoredSubmission]:
        """Return the submissions stored by the mock MSRC service."""
        response = await self._request("GET", "/submissions")
        document = _json_object(response)
        raw = document.get("submissions")
        if not isinstance(raw, list):
            raise RemoteServiceError("The mock MSRC service returned no submissions.")
        submissions: list[StoredSubmission] = []
        for item in raw:
            try:
                submissions.append(StoredSubmission.model_validate(item))
            except ValueError as error:
                raise RemoteServiceError(
                    "The mock MSRC service returned an unreadable submission."
                ) from error
        return submissions

    async def fetch_bundle(self, submission_id: str) -> bytes:
        """Download the opaque bundle bytes for a stored submission."""
        safe_id = validate_record_id(submission_id)
        response = await self._request("GET", f"/submissions/{safe_id}/bundle")
        if not response.content:
            raise RemoteServiceError("The mock MSRC service returned an empty bundle.")
        return response.content
