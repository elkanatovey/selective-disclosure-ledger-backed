# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared fixtures for the control plane tests.

The tests never build the C++ core and never start Docker. A deterministic
fake executable stands in for the selective-disclosure tool, the mock MSRC
service runs in-process behind an ASGI transport, and the transparency service
is a scripted httpx transport.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from scitt_selective_disclosure.config import Settings
from scitt_selective_disclosure.mock_msrc.app import create_app as create_mock_app
from scitt_selective_disclosure.msrc_client import MsrcClient
from scitt_selective_disclosure.scitt import ScittClient
from scitt_selective_disclosure.services import Services, build_services
from scitt_selective_disclosure.storage import Store
from scitt_selective_disclosure.web.app import create_app as create_web_app

PRIVATE_KEY = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"SECRET-MATERIAL-DO-NOT-SEND\n"
    b"-----END PRIVATE KEY-----\n"
)
ROOT_KEY = b"-----BEGIN PRIVATE KEY-----\nDEMO-ROOT-KEY\n-----END PRIVATE KEY-----\n"
ROOT_CERT = b"-----BEGIN CERTIFICATE-----\nDEMO-ROOT\n-----END CERTIFICATE-----\n"
SCITT_TRUST = b"\xa1\x01DEMO-COSE-KEY-SET\xff"
DEFAULT_TXID = "2.42"
DEFAULT_RECEIPT = b"\xd2\x84\xa1RECEIPT\x00\xff"
SCITT_BASE_URL = "https://scitt.demo.invalid"
MSRC_BASE_URL = "http://msrc.demo.invalid"


@dataclass
class RecordedRequest:
    """A request captured on the way out of the control plane."""

    method: str
    path: str
    query: str
    content: bytes
    headers: dict[str, str]


@dataclass
class ScittStub:
    """Scripted transparency service used by the researcher tests."""

    call_log: list[str] = field(default_factory=list)
    requests: list[RecordedRequest] = field(default_factory=list)
    txid: str = DEFAULT_TXID
    receipt: bytes = DEFAULT_RECEIPT
    status_code: int = 200
    omit_txid: bool = False
    empty_body: bool = False
    unreachable: bool = False
    historical_unavailable_count: int = 0
    historical_accepted_count: int = 0
    historical_status_code: int = 200
    historical_content_type: str = "application/scitt-statement+cose"

    @property
    def registrations(self) -> list[RecordedRequest]:
        """Return only the registration attempts."""
        return [item for item in self.requests if item.path == "/entries"]

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Serve a registration or entry read."""
        self.call_log.append(f"scitt:{request.method} {request.url.path}")
        self.requests.append(
            RecordedRequest(
                method=request.method,
                path=request.url.path,
                query=request.url.query.decode("ascii"),
                content=request.content,
                headers={key.lower(): value for key, value in request.headers.items()},
            )
        )
        if self.unreachable:
            raise httpx.ConnectError("connection refused", request=request)
        if request.method == "POST" and request.url.path == "/entries":
            if self.status_code >= 400:
                return httpx.Response(
                    self.status_code, json={"error": "registration refused"}
                )
            headers = {} if self.omit_txid else {"x-ms-ccf-transaction-id": self.txid}
            body = b"" if self.empty_body else self.receipt
            return httpx.Response(self.status_code, content=body, headers=headers)
        if request.method == "GET" and request.url.path.endswith("/statement"):
            if self.historical_unavailable_count > 0:
                self.historical_unavailable_count -= 1
                return httpx.Response(503, content=b"history is being prepared")
            if self.historical_accepted_count > 0:
                self.historical_accepted_count -= 1
                return httpx.Response(
                    202,
                    content=b"history is being prepared",
                    headers={"content-type": "text/plain"},
                )
            return httpx.Response(
                self.historical_status_code,
                content=self.receipt,
                headers={"content-type": self.historical_content_type},
            )
        return httpx.Response(404, json={"error": "not found"})


class RecordingTransport(httpx.AsyncBaseTransport):
    """Captures outbound mock MSRC traffic and can fail selected paths."""

    def __init__(
        self, inner: httpx.AsyncBaseTransport, call_log: list[str] | None = None
    ) -> None:
        self.inner = inner
        self.call_log: list[str] = [] if call_log is None else call_log
        self.requests: list[RecordedRequest] = []
        self.failing_paths: set[str] = set()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Record the request, then delegate unless the path is failing."""
        content = await request.aread()
        self.call_log.append(f"msrc:{request.method} {request.url.path}")
        self.requests.append(
            RecordedRequest(
                method=request.method,
                path=request.url.path,
                query=request.url.query.decode("ascii"),
                content=content,
                headers={key.lower(): value for key, value in request.headers.items()},
            )
        )
        if request.url.path in self.failing_paths:
            return httpx.Response(503, json={"detail": "mock MSRC unavailable"})
        return await self.inner.handle_async_request(request)


@dataclass
class OfficialVerifierStub:
    """Controls and observes the fake official SCITT verifier."""

    log_path: Path

    def set_result(self, outcome: str) -> None:
        """Choose the outcome the next invocation reports."""
        os.environ["FAKE_OFFICIAL_RESULT"] = outcome

    @property
    def calls(self) -> list[dict[str, Any]]:
        """Return every recorded invocation, in order."""
        if not self.log_path.is_file():
            return []
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


@dataclass
class Harness:
    """Everything a control plane test needs."""

    web: TestClient
    mock: TestClient
    web_app: FastAPI
    mock_app: FastAPI
    services: Services
    mock_services: Services
    settings: Settings
    store: Store
    scitt: ScittStub
    msrc_transport: RecordingTransport
    official: OfficialVerifierStub
    call_log: list[str]
    scratch: Path
    root_cert: Path
    root_key: Path

    def enroll(self, file_name: str = "researcher.pem") -> str:
        """Run the enrollment handshake and return the enrollment id."""
        response = self.web.post(
            "/api/researcher/enroll",
            data={"subject": "Demo researcher"},
            files={"private_key": (file_name, PRIVATE_KEY, "application/x-pem-file")},
        )
        assert response.status_code == 200, response.text
        identifier: str = response.json()["enrollment_id"]
        return identifier

    def submit(
        self,
        enrollment_id: str,
        *,
        title: str = "Heap overflow in parser",
        body: str = "abcdefghijklmnopqrstuvwx",
        component: str = "parser",
        severity: str = "high",
        fingerprint: str = "fp-1234",
        references: str = "https://example.invalid/1",
    ) -> httpx.Response:
        """Run the one click submission pipeline."""
        return self.web.post(
            "/api/researcher/submit",
            data={
                "enrollment_id": enrollment_id,
                "title": title,
                "body": body,
                "component": component,
                "severity": severity,
                "fingerprint": fingerprint,
                "references": references,
            },
            files={
                "private_key": (
                    "researcher.pem",
                    PRIVATE_KEY,
                    "application/x-pem-file",
                )
            },
        )

    def stored_bundle(self, submission_id: str) -> bytes:
        """Download the bundle stored for a researcher submission."""
        response = self.web.get(f"/api/researcher/submissions/{submission_id}/bundle")
        assert response.status_code == 200, response.text
        return response.content

    def mock_submissions(self) -> list[dict[str, Any]]:
        """Return the submissions held by the mock MSRC service."""
        response = self.mock.get("/submissions")
        assert response.status_code == 200, response.text
        items: list[dict[str, Any]] = response.json()["submissions"]
        return items

    def verify(
        self,
        bundle: bytes,
        *,
        msrc_root: bytes = ROOT_CERT,
        scitt_trust: bytes = SCITT_TRUST,
        trust_name: str = "scitt-keys.cbor",
    ) -> httpx.Response:
        """Run the verifier route against imported trust material."""
        return self.web.post(
            "/api/verifier/verify",
            files={
                "bundle": ("bundle.cbor", bundle, "application/cbor"),
                "msrc_root": (
                    "msrc-root.pem",
                    msrc_root,
                    "application/x-pem-file",
                ),
                "scitt_trust": (trust_name, scitt_trust, "application/cbor"),
            },
        )


@pytest.fixture(scope="session")
def scratch_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point every temporary workspace at a directory the tests can inspect."""
    directory = tmp_path_factory.mktemp("scratch")
    previous = tempfile.tempdir
    tempfile.tempdir = str(directory)
    try:
        yield directory
    finally:
        tempfile.tempdir = previous


@pytest.fixture(scope="session")
def fake_cli(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install the fake selective-disclosure tool as an executable."""
    source = Path(__file__).parent / "fake_cli.py"
    target = tmp_path_factory.mktemp("cli") / "scitt-sd"
    shutil.copyfile(source, target)
    target.chmod(0o755)
    return target


@pytest.fixture
def official_verifier(tmp_path: Path) -> Iterator[OfficialVerifierStub]:
    """Install the fake official verifier and reset its controls."""
    log_path = tmp_path / "official-calls.jsonl"
    previous = os.environ.get("FAKE_OFFICIAL_RESULT")
    os.environ["FAKE_OFFICIAL_LOG"] = str(log_path)
    os.environ["FAKE_OFFICIAL_RESULT"] = "pass"
    try:
        yield OfficialVerifierStub(log_path=log_path)
    finally:
        os.environ.pop("FAKE_OFFICIAL_LOG", None)
        if previous is None:
            os.environ.pop("FAKE_OFFICIAL_RESULT", None)
        else:
            os.environ["FAKE_OFFICIAL_RESULT"] = previous


@pytest.fixture
def demo_ca(tmp_path: Path) -> tuple[Path, Path]:
    """Write demo certificate authority material for the mock service."""
    root_key = tmp_path / "ca" / "root.key"
    root_cert = tmp_path / "ca" / "root.pem"
    root_key.parent.mkdir(parents=True, exist_ok=True)
    root_key.write_bytes(ROOT_KEY)
    root_cert.write_bytes(ROOT_CERT)
    return root_key, root_cert


@pytest.fixture
def mock_settings(
    tmp_path: Path, fake_cli: Path, demo_ca: tuple[Path, Path]
) -> Settings:
    """Settings for the in-process mock MSRC service."""
    root_key, root_cert = demo_ca
    return Settings.from_env(
        {
            "SDC_CLI": str(fake_cli),
            "SDC_CLI_TIMEOUT": "20",
            "SDC_DATA_DIR": str(tmp_path / "msrc-data"),
            "SDC_MSRC_ROOT_KEY": str(root_key),
            "SDC_MSRC_ROOT_CERT": str(root_cert),
        }
    )


@pytest.fixture
def web_settings(tmp_path: Path, fake_cli: Path) -> Settings:
    """Settings for the researcher, MSRC and verifier control plane."""
    wrapper = Path(__file__).parent / "fake_official_verify.py"
    return Settings.from_env(
        {
            "SDC_CLI": str(fake_cli),
            "SDC_CLI_TIMEOUT": "20",
            "SDC_DATA_DIR": str(tmp_path / "web-data"),
            "SDC_SCITT_URL": SCITT_BASE_URL,
            "SDC_MSRC_URL": MSRC_BASE_URL,
            "SDC_SCITT_VERIFIER_PYTHON": sys.executable,
            "SDC_SCITT_VERIFIER_WRAPPER": str(wrapper),
            "SDC_SCITT_VERIFIER_TIMEOUT": "20",
        }
    )


@pytest.fixture
def harness(
    web_settings: Settings,
    mock_settings: Settings,
    demo_ca: tuple[Path, Path],
    official_verifier: OfficialVerifierStub,
    scratch_dir: Path,
) -> Iterator[Harness]:
    """Wire the web app to an in-process mock MSRC and a scripted SCITT."""
    root_key, root_cert = demo_ca
    mock_services = build_services(mock_settings)
    mock_app = create_mock_app(mock_services)

    call_log: list[str] = []
    msrc_transport = RecordingTransport(
        httpx.ASGITransport(app=mock_app), call_log=call_log
    )
    scitt_stub = ScittStub(call_log=call_log)

    def msrc_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=msrc_transport, base_url=MSRC_BASE_URL)

    def scitt_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(scitt_stub.handler),
            base_url=SCITT_BASE_URL,
        )

    services = build_services(
        web_settings,
        scitt=ScittClient(SCITT_BASE_URL, scitt_factory),
        msrc=MsrcClient(MSRC_BASE_URL, msrc_factory),
    )
    web_app = create_web_app(services)

    with TestClient(web_app) as web, TestClient(mock_app) as mock:
        yield Harness(
            web=web,
            mock=mock,
            web_app=web_app,
            mock_app=mock_app,
            services=services,
            mock_services=mock_services,
            settings=web_settings,
            store=services.store,
            scitt=scitt_stub,
            msrc_transport=msrc_transport,
            official=official_verifier,
            call_log=call_log,
            scratch=scratch_dir,
            root_cert=root_cert,
            root_key=root_key,
        )
