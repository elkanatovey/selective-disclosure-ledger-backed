# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Page and asset tests: markup, accessibility affordances and no crypto JS."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import Harness

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "scitt_selective_disclosure"
STATIC = PACKAGE / "static"
TEMPLATES = PACKAGE / "templates"

# Browser and library entry points that would mean the page is doing crypto.
FORBIDDEN_JS = (
    "crypto.subtle",
    "window.crypto",
    "SubtleCrypto",
    "getRandomValues",
    "cbor",
    "cose",
    "pycose",
    "jose",
    "jsrsasign",
    "forge",
    "sign(",
    "verifySignature",
    "atob(",
    "btoa(",
)

PAGES = ("/", "/researcher", "/msrc", "/verifier")


@pytest.mark.parametrize("path", PAGES)
def test_pages_render(harness: Harness, path: str) -> None:
    """Every role page is served as HTML."""
    response = harness.web.get(path)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in response.text.lower()


@pytest.mark.parametrize("path", PAGES)
def test_pages_set_security_headers(harness: Harness, path: str) -> None:
    """A strict policy is applied, and no inline script is allowed."""
    response = harness.web.get(path)
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", PAGES)
def test_pages_have_no_inline_script_or_handlers(harness: Harness, path: str) -> None:
    """Markup carries no inline JavaScript, matching the policy."""
    body = harness.web.get(path).text
    assert not re.search(r"<script(?![^>]*\bsrc=)", body)
    assert not re.search(r"\son[a-z]+\s*=", body)
    assert "javascript:" not in body


@pytest.mark.parametrize("path", PAGES)
def test_pages_are_navigable(harness: Harness, path: str) -> None:
    """Shared landmarks and the skip link are present on every page."""
    body = harness.web.get(path).text
    assert 'lang="en"' in body
    assert 'class="skip-link" href="#main"' in body
    assert '<main id="main">' in body
    assert 'aria-label="Roles"' in body
    assert "Demonstration only" in body


@pytest.mark.parametrize("path", PAGES)
def test_pages_declare_a_title(harness: Harness, path: str) -> None:
    """Each page has a distinct, non-empty document title."""
    body = harness.web.get(path).text
    match = re.search(r"<title>(.*?)</title>", body, re.S)
    assert match is not None
    assert match.group(1).strip()


def test_every_input_has_a_label() -> None:
    """No form control is left without an associated label."""
    for template in TEMPLATES.glob("*.html"):
        markup = template.read_text(encoding="utf-8")
        control_ids = re.findall(
            r"<(?:input|select|textarea)\b[^>]*\bid=\"([^\"]+)\"", markup
        )
        label_targets = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', markup))
        for control_id in control_ids:
            assert control_id in label_targets, f"{template.name}: {control_id}"


def test_tables_have_captions_and_scoped_headers() -> None:
    """Data tables are announced properly by assistive technology."""
    for template in TEMPLATES.glob("*.html"):
        markup = template.read_text(encoding="utf-8")
        tables = re.findall(r"<table\b.*?</table>", markup, re.S)
        for table in tables:
            assert "<caption>" in table, template.name
            for header in re.findall(r"<th\b[^>]*>", table):
                assert 'scope="col"' in header or 'scope="row"' in header


def test_live_regions_are_polite() -> None:
    """Status output is announced without interrupting the user."""
    for template in TEMPLATES.glob("*.html"):
        markup = template.read_text(encoding="utf-8")
        for element in re.findall(r"<output\b[^>]*>", markup):
            assert 'aria-live="polite"' in element, template.name


@pytest.mark.parametrize(
    "script", sorted(path.name for path in (STATIC / "js").glob("*.js"))
)
def test_scripts_contain_no_cryptography(script: str) -> None:
    """The browser never performs or reimplements cryptographic work."""
    source = (STATIC / "js" / script).read_text(encoding="utf-8")
    lowered = source.lower()
    for marker in FORBIDDEN_JS:
        assert marker.lower() not in lowered, f"{script}: {marker}"


@pytest.mark.parametrize(
    "script", sorted(path.name for path in (STATIC / "js").glob("*.js"))
)
def test_scripts_are_ascii_and_strict(script: str) -> None:
    """Scripts stay ASCII only and opt into strict mode."""
    raw = (STATIC / "js" / script).read_bytes()
    raw.decode("ascii")
    assert '"use strict";' in raw.decode("ascii")


@pytest.mark.parametrize(
    "asset",
    sorted(
        str(path.relative_to(STATIC)) for path in STATIC.rglob("*") if path.is_file()
    ),
)
def test_static_assets_are_served(harness: Harness, asset: str) -> None:
    """Every shipped asset is reachable at the path the templates use."""
    response = harness.web.get(f"/static/{asset}")
    assert response.status_code == 200
    assert response.content


def test_templates_reference_only_shipped_assets() -> None:
    """No page links to an asset that does not exist."""
    for template in TEMPLATES.glob("*.html"):
        markup = template.read_text(encoding="utf-8")
        for reference in re.findall(r'(?:href|src)="/static/([^"]+)"', markup):
            assert (STATIC / reference).is_file(), f"{template.name}: {reference}"


def test_templates_are_ascii_only() -> None:
    """Markup stays ASCII so that it renders identically everywhere."""
    for template in TEMPLATES.glob("*.html"):
        template.read_bytes().decode("ascii")


def test_verifier_page_reports_both_engines(harness: Harness) -> None:
    """The verifier page shows the two engines separately."""
    body = harness.web.get("/verifier").text
    assert 'id="source-table"' in body
    assert 'id="check-table"' in body
    assert "pyscitt" in body
    assert "scitt-keys" in body


def test_researcher_page_offers_every_download(harness: Harness) -> None:
    """The recovery panel exposes the bundle, statement and token."""
    body = harness.web.get("/researcher").text
    assert 'id="bundle-link"' in body
    assert 'id="statement-link"' in body
    assert 'id="transparent-link"' in body
    assert 'id="retry-button"' in body


def test_msrc_page_offers_selection_controls(harness: Harness) -> None:
    """The MSRC page exposes whole field controls and chunk controls."""
    body = harness.web.get("/msrc").text
    assert 'id="field-list"' in body
    assert 'id="body-chunks"' in body
    assert 'id="redact-selection"' in body
    assert 'id="restore-selection"' in body
    assert 'id="clear-selection"' in body
    assert 'role="group"' in body


def test_healthz_reports_the_tool(harness: Harness) -> None:
    """The health endpoint reports whether the tool is present."""
    response = harness.web.get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "web"
    assert payload["cli_configured"] is True


def test_mock_healthz_reports_configuration(harness: Harness) -> None:
    """The mock service reports whether demo issuance material exists."""
    response = harness.mock.get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "mock-msrc"
    assert payload["cli_configured"] is True
    assert payload["demo_only"] is True


def test_unknown_page_is_not_found(harness: Harness) -> None:
    """No catch-all route hides mistakes."""
    assert harness.web.get("/nope").status_code == 404
