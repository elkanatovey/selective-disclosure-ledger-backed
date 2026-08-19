# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The whole demo, driven through the three services' own HTTP APIs.

This exercises the path a browser takes: enrol a key with MSRC, sign the bytes
the researcher's agent prepares, register with a real transparency service,
withhold part of the report at MSRC, sign the release, then verify it against
trust material supplied out of band.

It also checks the two ways a verifier could be vacuous: that the receipt is
reported as unchecked when no service certificate is given, and that a tampered
release is refused.

The signing here stands in for WebCrypto. It is the only place in this
repository where Python touches a key, and it exists because CI has no browser;
the applications themselves never see one.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

RESEARCHER = os.environ.get("RESEARCHER_URL", "http://127.0.0.1:8090").rstrip("/")
MSRC = os.environ.get("MSRC_URL", "http://127.0.0.1:8091").rstrip("/")
VERIFY = os.environ.get("VERIFY_URL", "http://127.0.0.1:8092").rstrip("/")
TIMEOUT = 120


class Failed(SystemExit):
    def __init__(self, why: str) -> None:
        super().__init__(f"FAIL: {why}")


def post(base: str, path: str, body: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        result: dict[str, object] = json.load(response)
        return result


def get(base: str, path: str) -> bytes:
    with urllib.request.urlopen(base + path, timeout=TIMEOUT) as response:
        return bytes(response.read())


def new_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, public.decode()


def sign(key: ec.EllipticCurvePrivateKey, to_be_signed_b64: str) -> str:
    """What WebCrypto's ECDSA does: hash, sign, emit raw r||s."""
    der = key.sign(base64.b64decode(to_be_signed_b64), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def statuses(report: dict[str, object]) -> dict[str, str]:
    checks = report["checks"]
    assert isinstance(checks, list)
    return {str(c["id"]): str(c["status"]) for c in checks}


def main() -> None:
    msrc_key, msrc_public = new_key()
    post(MSRC, "/api/key", {"public_key_pem": msrc_public})

    researcher, researcher_public = new_key()
    enrolled = post(
        RESEARCHER,
        "/api/enroll",
        {"public_key_pem": researcher_public, "subject": "CI researcher"},
    )
    print(f"enrolled with {enrolled['issuer_did']}")

    prepared = post(
        RESEARCHER,
        "/api/prepare",
        {
            "enrollment_id": enrolled["enrollment_id"],
            "title": "Heap overflow in the parser",
            "body": "The length field is trusted. A crafted record overruns it.",
            "component": "contoso-parser",
            "severity": "critical",
            "fingerprint": "abc123",
            "references": ["CVE-2024-0001"],
        },
    )

    # The researcher's agent registers, checks the receipt itself, and only
    # then hands the bundle to MSRC. A bad receipt fails here, not later.
    submitted = post(
        RESEARCHER,
        "/api/submit",
        {
            "prepare_id": prepared["prepare_id"],
            "signature_b64": sign(researcher, str(prepared["to_be_signed_b64"])),
        },
    )
    txid = str(submitted["txid"])
    reported = submitted["stages"]
    assert isinstance(reported, list)
    stages = [str(stage["name"]) for stage in reported]
    if "verify" not in stages or stages.index("verify") > stages.index("deliver"):
        raise Failed(f"the receipt was not checked before delivery: {stages}")
    print(f"registered as {txid}, receipt checked before delivery, stages {stages}")

    bundle = get(RESEARCHER, f"/api/bundle/{submitted['submission_id']}")
    release = post(
        MSRC,
        "/api/release",
        {
            "bundle_b64": base64.b64encode(bundle).decode(),
            "redact_fields": ["body"],
            "redact_body_chunks": [],
            "public_key_pem": msrc_public,
        },
    )
    signed = post(
        MSRC,
        "/api/sign",
        {
            "release_id": release["release_id"],
            "signature_b64": sign(msrc_key, str(release["to_be_signed_b64"])),
        },
    )
    release_b64 = str(signed["release_b64"])
    print(f"released {signed['release_bytes']} bytes with the body withheld")

    root_pem = get(MSRC, "/api/root").decode()
    service_pem = open(os.environ["SCITT_SERVICE_CERT"], encoding="ascii").read()

    # 1. Everything verifies, receipt included.
    verified = post(
        VERIFY,
        "/api/verify",
        {
            "release_b64": release_b64,
            "msrc_root_pem": root_pem,
            "scitt_cert_pem": service_pem,
        },
    )
    report = verified["report"]
    assert isinstance(report, dict)
    got = statuses(report)
    print("checks:", json.dumps(got))

    if not verified["passed"]:
        raise Failed(f"verification failed: {verified.get('reason')}")
    failed = [name for name, status in got.items() if status != "pass"]
    if failed:
        raise Failed(f"these checks did not pass: {failed}")
    if got.get("scitt_receipt") != "pass":
        raise Failed("the transparency service receipt was not verified")

    # 2. Without the service certificate the receipt must be reported unchecked,
    #    never quietly passed.
    without = post(
        VERIFY,
        "/api/verify",
        {
            "release_b64": release_b64,
            "msrc_root_pem": root_pem,
            "scitt_cert_pem": "",
        },
    )
    report = without["report"]
    assert isinstance(report, dict)
    if statuses(report).get("scitt_receipt") != "skipped":
        raise Failed("the receipt was not reported as unchecked")

    # 3. A tampered release must be refused, or none of the above means anything.
    raw = bytearray(base64.b64decode(release_b64))
    raw[-1] ^= 0xFF
    tampered = post(
        VERIFY,
        "/api/verify",
        {
            "release_b64": base64.b64encode(raw).decode(),
            "msrc_root_pem": root_pem,
            "scitt_cert_pem": service_pem,
        },
    )
    if tampered["passed"]:
        raise Failed("a tampered release verified")

    # 4. A researcher that cannot verify the receipt must not deliver at all.
    #    UNTRUSTING_RESEARCHER_URL is the same service configured with the wrong
    #    receipt anchor; the demo harness starts it alongside the real one.
    untrusting = os.environ.get("UNTRUSTING_RESEARCHER_URL")
    if untrusting:
        check_refuses_to_deliver(untrusting.rstrip("/"))
        print("a researcher that cannot verify the receipt refused to deliver")

    print("PASS: full flow verified against a real transparency service")


def check_refuses_to_deliver(base: str) -> None:
    key, public = new_key()
    enrolled = post(
        base, "/api/enroll", {"public_key_pem": public, "subject": "CI researcher"}
    )
    prepared = post(
        base,
        "/api/prepare",
        {
            "enrollment_id": enrolled["enrollment_id"],
            "title": "Heap overflow in the parser",
            "body": "The length field is trusted. A crafted record overruns it.",
            "component": "contoso-parser",
            "severity": "critical",
            "fingerprint": "abc123",
            "references": [],
        },
    )
    try:
        post(
            base,
            "/api/submit",
            {
                "prepare_id": prepared["prepare_id"],
                "signature_b64": sign(key, str(prepared["to_be_signed_b64"])),
            },
        )
    except urllib.error.HTTPError as error:
        if error.code != 502:
            raise Failed(f"expected 502 when the receipt fails, got {error.code}")
        return
    raise Failed("a report was delivered even though its receipt did not verify")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        sys.exit(f"FAIL: {error.url} -> {error.code}: {error.read()[:400]!r}")
