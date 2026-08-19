# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The researcher's client for MSRC.

MSRC is a separate service, so everything the researcher needs from it travels
over HTTP: the certificate for the key the browser holds, the key MSRC will
sign releases with, and the bundle once the researcher is satisfied with it.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class MsrcError(RuntimeError):
    """MSRC refused a request or could not be reached."""


@dataclass(frozen=True)
class Enrollment:
    enrollment_id: str
    subject: str
    issuer_did: str
    leaf_cert_pem: str
    root_cert_pem: str


class MsrcClient:
    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("the MSRC URL must be http or https")
        self.url = url.rstrip("/")

    def _call(
        self, path: str, body: dict[str, object] | None = None
    ) -> dict[str, object]:
        request = urllib.request.Request(
            self.url + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={} if body is None else {"content-type": "application/json"},
            method="GET" if body is None else "POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                decoded = json.loads(response.read(MAX_RESPONSE_BYTES))
        except urllib.error.HTTPError as error:
            raise MsrcError(f"MSRC refused the request ({error.code})") from error
        except (OSError, ValueError) as error:
            raise MsrcError(f"MSRC could not be reached: {error}") from error
        if not isinstance(decoded, dict):
            raise MsrcError("MSRC returned an unexpected document")
        return decoded

    def enroll(self, public_key_pem: str, subject: str) -> Enrollment:
        record = self._call(
            "/api/enroll", {"public_key_pem": public_key_pem, "subject": subject}
        )
        fields = {}
        for name in Enrollment.__dataclass_fields__:
            value = record.get(name)
            if not isinstance(value, str):
                raise MsrcError("MSRC returned an incomplete enrollment")
            fields[name] = value
        return Enrollment(**fields)

    def disclosure_key(self) -> str:
        key = self._call("/api/disclosure-key").get("public_key_pem")
        if not isinstance(key, str):
            raise MsrcError("MSRC returned no disclosure key")
        return key

    def submit(self, bundle: bytes, title: str, txid: str) -> str:
        record = self._call(
            "/api/submissions",
            {
                "bundle_b64": base64.b64encode(bundle).decode(),
                "title": title,
                "txid": txid,
            },
        )
        submission_id = record.get("submission_id")
        if not isinstance(submission_id, str):
            raise MsrcError("MSRC did not return a submission id")
        return submission_id
