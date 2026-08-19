# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A client for a real SCITT transparency service (scitt-ccf-ledger).

Registration is asynchronous: a statement is submitted, the service returns an
operation to poll, and the entry identifier appears once the transaction has
committed. Only then can the transparent statement, which is the submitted
statement with a receipt attached, be fetched.

Nothing here parses CBOR or touches a key. The statement goes out as opaque
bytes and the transparent statement comes back as opaque bytes; everything
that reads either of them is in the C++ core.
"""

from __future__ import annotations

import http.client
import os
import ssl
import time
import urllib.parse
from dataclasses import dataclass

# The service can take a moment to commit a transaction and to page a
# historical entry back in. Both are bounded so a stalled ledger surfaces as an
# error rather than a hung request.
POLL_ATTEMPTS = 100
POLL_INTERVAL_SECONDS = 0.1
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ScittError(RuntimeError):
    """The transparency service refused or failed to register a statement."""


@dataclass(frozen=True)
class Registration:
    txid: str
    transparent_statement: bytes


class ScittLedger:
    """Registers statements with a SCITT transparency service over HTTPS."""

    def __init__(self, url: str, tls_cert: bytes, service_identity: bytes) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("the transparency service URL must be https")
        self.url = url.rstrip("/")
        self._host = parsed.hostname
        self._port = parsed.port or 443
        # Two different questions, kept apart because they have different
        # answers in any real deployment: which endpoint to trust to reach the
        # service, and whose signature makes a receipt worth anything. Here the
        # same self-signed certificate happens to answer both.
        self.service_identity = service_identity
        self._context = ssl.create_default_context(cadata=tls_cert.decode("ascii"))

    def _request(
        self, method: str, path: str, body: bytes | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPSConnection(
            self._host, self._port, context=self._context, timeout=30
        )
        try:
            headers = {"content-type": "application/cose"} if body else {}
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return (
                response.status,
                {k.lower(): v for k, v in response.getheaders()},
                response.read(MAX_RESPONSE_BYTES),
            )
        except OSError as error:
            raise ScittError(
                f"the transparency service could not be reached: {error}"
            ) from error
        finally:
            connection.close()

    def register(self, statement: bytes) -> Registration:
        """Submit a statement and return it with its receipt attached."""
        status, headers, body = self._request("POST", "/app/entries", statement)
        if status >= 300:
            raise ScittError(_refusal(status, body))

        operation = headers.get("location")
        if not operation:
            raise ScittError("the transparency service returned no operation")

        txid = self._await_entry(_app_path(operation))
        return Registration(txid, self._statement(txid))

    def _await_entry(self, operation: str) -> str:
        for _ in range(POLL_ATTEMPTS):
            status, headers, body = self._request("GET", operation)
            entry = headers.get("location", "")
            if "/entries/" in entry:
                return entry.rstrip("/").rsplit("/", 1)[-1]
            if status >= 300:
                raise ScittError(_refusal(status, body))
            time.sleep(POLL_INTERVAL_SECONDS)
        raise ScittError("the transparency service did not commit the statement")

    def _statement(self, txid: str) -> bytes:
        path = f"/app/entries/{urllib.parse.quote(txid)}/statement"
        for _ in range(POLL_ATTEMPTS):
            status, _, body = self._request("GET", path)
            if status == 200:
                return body
            # The entry is committed but not yet paged back into the historical
            # cache, which is a wait rather than a failure.
            if status != 503:
                raise ScittError(_refusal(status, body))
            time.sleep(POLL_INTERVAL_SECONDS)
        raise ScittError("the transparency service did not return the statement")


def _app_path(location: str) -> str:
    """The service reports absolute URLs without its own application prefix."""
    path = urllib.parse.urlparse(location).path
    return path if path.startswith("/app/") else "/app" + path


def _refusal(status: int, body: bytes) -> str:
    # Errors come back as CBOR problem details. Only the printable run is
    # shown: this text reaches a browser, and the body is service-controlled.
    printable = "".join(chr(b) if 0x20 <= b < 0x7F else " " for b in body[:200]).strip()
    return f"the transparency service refused the statement ({status}): {printable}"


def from_environment() -> ScittLedger:
    """The service named by SCITT_URL.

    SCITT_SERVICE_CERT is the TLS anchor. SCITT_SERVICE_IDENTITY is the
    certificate receipts are checked against, and defaults to the same file
    because a CCF sandbox serves TLS under its own service identity.
    """
    url = os.environ.get("SCITT_URL")
    cert_path = os.environ.get("SCITT_SERVICE_CERT")
    if not url or not cert_path:
        raise ScittError(
            "set SCITT_URL and SCITT_SERVICE_CERT to the transparency service "
            "this demo registers with"
        )
    identity_path = os.environ.get("SCITT_SERVICE_IDENTITY", cert_path)
    with open(cert_path, "rb") as handle:
        tls_cert = handle.read(MAX_RESPONSE_BYTES)
    with open(identity_path, "rb") as handle:
        identity = handle.read(MAX_RESPONSE_BYTES)
    return ScittLedger(url, tls_cert, identity)
