# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Transparency service client that moves opaque COSE bytes only."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from .config import Settings
from .errors import ScittError

CT_APPLICATION_COSE = "application/cose"
CCF_TX_ID_HEADER = "x-ms-ccf-transaction-id"
TXID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REGISTRATION_SUCCESS_STATUSES = frozenset({200, 201, 202})
HISTORICAL_SUCCESS_STATUSES = frozenset({200})
REDIRECT_STATUSES = frozenset({302, 303, 307})
TRANSPARENT_STATEMENT_CONTENT_TYPES = frozenset(
    {"application/cose", "application/scitt-statement+cose"}
)
BODY_PREVIEW_CHARS = 200
HISTORICAL_RETRY_STATUSES = frozenset({202, 429, 503})
HISTORICAL_RETRY_ATTEMPTS = 60
HISTORICAL_RETRY_DELAY = 0.25

HttpClientFactory = Callable[[], httpx.AsyncClient]


@dataclass(frozen=True)
class ScittRegistration:
    """A confirmed registration and the opaque transparent statement bytes."""

    txid: str
    transparent_statement: bytes
    url: str


def _preview(response: httpx.Response) -> str:
    content_type = response.headers.get("content-type", "unknown")
    body = response.content[:BODY_PREVIEW_CHARS].decode("utf-8", errors="replace")
    return f"status={response.status_code} content-type={content_type} body={body}"


def _txid_from_location(location: str) -> str | None:
    if "/entries/" not in location:
        return None
    candidate = location.rsplit("/entries/", 1)[1].split("?", 1)[0].strip("/")
    return candidate or None


def extract_txid(response: httpx.Response) -> str:
    """Return the transaction identifier from a registration response."""
    candidate = response.headers.get(CCF_TX_ID_HEADER, "").strip()
    if not candidate:
        location = response.headers.get("location", "").strip()
        candidate = _txid_from_location(location) or ""
    if not candidate or not TXID_PATTERN.fullmatch(candidate):
        raise ScittError(
            "The transparency service did not return a transaction identifier.",
            detail=_preview(response),
        )
    return str(candidate)


class ScittClient:
    """Registers exact statement bytes with a SCITT transparency service."""

    def __init__(self, base_url: str, client_factory: HttpClientFactory) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_factory = client_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> ScittClient:
        """Build a client using the configured URL and TLS trust settings."""

        def factory() -> httpx.AsyncClient:
            return httpx.AsyncClient(
                base_url=settings.scitt_url,
                timeout=settings.scitt_timeout,
                verify=settings.scitt_verify,
            )

        return cls(settings.scitt_url, factory)

    async def register(self, statement: bytes) -> ScittRegistration:
        """Register the exact registered statement bytes and wait for commit.

        The statement is transmitted verbatim as ``application/cose``. The call
        only succeeds when the service reports success and returns a usable
        transaction identifier.
        """
        try:
            async with self._client_factory() as client:
                response = await client.post(
                    "/entries",
                    params={"waitForCommit": "true"},
                    content=statement,
                    headers={"content-type": CT_APPLICATION_COSE},
                    follow_redirects=False,
                )
                if response.status_code in REDIRECT_STATUSES:
                    txid = extract_txid(response)
                    transparent = await self._fetch_transparent_statement(client, txid)
                    return ScittRegistration(txid, transparent, self.base_url)
                if response.status_code not in REGISTRATION_SUCCESS_STATUSES:
                    raise ScittError(
                        "The transparency service rejected the statement.",
                        detail=_preview(response),
                    )
                txid = extract_txid(response)
                # waitForCommit returns the standalone receipt, not the
                # transparent statement. Fetch the latter from its historical
                # endpoint so the proof bundle carries the original signed
                # statement with receipt header 394 attached.
                transparent = await self._fetch_transparent_statement(client, txid)
                return ScittRegistration(txid, transparent, self.base_url)
        except httpx.HTTPError as error:
            raise ScittError(
                "The transparency service could not be reached.",
                detail=f"{type(error).__name__}: {error}",
            ) from error

    async def _fetch_transparent_statement(
        self, client: httpx.AsyncClient, txid: str
    ) -> bytes:
        """Fetch the committed statement, retrying while history is prepared."""
        response: httpx.Response | None = None
        for attempt in range(HISTORICAL_RETRY_ATTEMPTS):
            response = await client.get(
                f"/entries/{txid}/statement", follow_redirects=True
            )
            if response.status_code not in HISTORICAL_RETRY_STATUSES:
                if (
                    response.status_code in HISTORICAL_SUCCESS_STATUSES
                    and response.content
                ):
                    content_type = response.headers.get("content-type", "")
                    media_type = content_type.partition(";")[0].strip().lower()
                    if media_type not in TRANSPARENT_STATEMENT_CONTENT_TYPES:
                        raise ScittError(
                            "The transparency service returned an unexpected "
                            "statement type.",
                            detail=_preview(response),
                        )
                    return response.content
                break
            if attempt + 1 < HISTORICAL_RETRY_ATTEMPTS:
                await asyncio.sleep(HISTORICAL_RETRY_DELAY)

        if response is None:
            raise ScittError(
                "The transparency service did not return a transparent statement.",
                detail="No historical query was attempted.",
            )
        raise ScittError(
            "The transparency service did not return a transparent statement.",
            detail=_preview(response),
        )
