# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""The extension module, exercised through the interpreter it was built for.

Importing ``_native`` and running the operations a caller can reach without a
transparency service is what proves the binding itself: the argument and
result conversions, the byte handling and the exception translation, none of
which the C++ tests can see.

What this cannot cover here: a proof bundle needs the transparent statement a
transparency service returns, which is the registered statement with a receipt
attached. Producing one means editing COSE, and this test refuses to hand-build
CBOR to fake it, so the bundle flow (create, inspect, present, extract and a
passing verification) is pinned in C++ instead, in tests/native/api_test.cpp,
where the same CBOR library the core uses attaches the receipt. What is
exercised below is every operation that stands on its own, plus the refusals
and the failed-verification report, which need no bundle to be well formed.

Nothing here imports cbor2, pycose or cryptography: the module is the only
component that understands COSE, CBOR and X.509, and a test that reached for a
Python implementation of any of them would no longer be testing that.
"""

from __future__ import annotations

import json
import sys
import unittest

import _native

REPORT = json.dumps(
    {
        "title": "Heap overflow in parser",
        "body": "Twelve chars",
        "component": "parser",
        "severity": "high",
        "fingerprint": "abc123",
        "references": ["CVE-2024-0001", "internal-1234"],
    }
)


def issue_everything() -> dict[str, object]:
    """Run every step an operator performs before a bundle exists."""
    root = _native.create_root_identity()
    private_key = _native.generate_private_key()
    public_key = _native.derive_public_key(private_key)
    leaf_cert = _native.issue_certificate(
        root["private_key"], root["certificate"], public_key
    )
    statement = _native.issue_statement(
        REPORT, private_key, leaf_cert, root["certificate"]
    )
    return {
        "root": root,
        "private_key": private_key,
        "public_key": public_key,
        "leaf_cert": leaf_cert,
        "statement": statement,
    }


class ModuleTest(unittest.TestCase):
    """What the module is, before what it does."""

    def test_reports_its_version(self) -> None:
        self.assertIsInstance(_native.__version__, str)
        self.assertTrue(_native.__version__)
        self.assertTrue(_native.__doc__)

    def test_needs_no_python_cryptography(self) -> None:
        # The module is the only component that understands COSE, CBOR and
        # X.509. Importing it must not pull a Python implementation of any of
        # them into the process.
        for name in ("cbor2", "pycose", "cryptography"):
            self.assertNotIn(name, sys.modules)


class KeyTest(unittest.TestCase):
    """Key generation and public derivation."""

    def test_generates_a_distinct_pem_private_key_every_time(self) -> None:
        first = _native.generate_private_key()
        second = _native.generate_private_key()
        self.assertIsInstance(first, bytes)
        self.assertTrue(first.startswith(b"-----BEGIN "))
        self.assertNotEqual(first, second)

    def test_derives_the_public_half(self) -> None:
        private_key = _native.generate_private_key()
        public_key = _native.derive_public_key(private_key)
        self.assertIsInstance(public_key, bytes)
        self.assertTrue(public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))
        # The same key always derives the same public half, and a different
        # key never does.
        self.assertEqual(public_key, _native.derive_public_key(private_key))
        self.assertNotEqual(
            public_key, _native.derive_public_key(_native.generate_private_key())
        )

    def test_refuses_something_that_is_not_a_private_key(self) -> None:
        with self.assertRaises(ValueError):
            _native.derive_public_key(b"not a key")
        # A public key is a PEM document, and still not a private key.
        public_key = _native.derive_public_key(_native.generate_private_key())
        with self.assertRaises(ValueError):
            _native.derive_public_key(public_key)

    def test_is_byte_oriented(self) -> None:
        # Text is not key material: the binding refuses it rather than
        # guessing an encoding.
        with self.assertRaises(TypeError):
            _native.derive_public_key("-----BEGIN PRIVATE KEY-----")


class RootIdentityTest(unittest.TestCase):
    """The demo trust anchor."""

    def test_describes_the_certificate_it_produced(self) -> None:
        identity = _native.create_root_identity()
        self.assertEqual(
            set(identity),
            {"private_key", "certificate", "issuer_json", "issuer_did"},
        )
        self.assertTrue(identity["private_key"].startswith(b"-----BEGIN "))
        self.assertTrue(
            identity["certificate"].startswith(b"-----BEGIN CERTIFICATE-----")
        )
        self.assertTrue(identity["issuer_did"].startswith("did:x509:0:sha256:"))

        issuer = json.loads(identity["issuer_json"])
        self.assertEqual(issuer["version"], 1)
        self.assertEqual(issuer["issuer_did"], identity["issuer_did"])
        self.assertEqual(issuer["ca_fingerprint_alg"], "sha256")
        self.assertIn("MSRC", issuer["certificate_subject"])
        self.assertTrue(issuer["report_subject"])

    def test_every_root_is_distinct(self) -> None:
        first = _native.create_root_identity()
        second = _native.create_root_identity()
        self.assertNotEqual(first["private_key"], second["private_key"])
        self.assertNotEqual(first["certificate"], second["certificate"])
        self.assertNotEqual(first["issuer_did"], second["issuer_did"])


class CertificateTest(unittest.TestCase):
    """Endorsing a reporter public key."""

    def test_endorses_a_public_key(self) -> None:
        root = _native.create_root_identity()
        public_key = _native.derive_public_key(_native.generate_private_key())
        certificate = _native.issue_certificate(
            root["private_key"], root["certificate"], public_key
        )
        self.assertIsInstance(certificate, bytes)
        self.assertTrue(certificate.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertNotEqual(certificate, root["certificate"])

    def test_refuses_a_private_key_in_place_of_a_public_one(self) -> None:
        root = _native.create_root_identity()
        private_key = _native.generate_private_key()
        with self.assertRaises(ValueError):
            _native.issue_certificate(
                root["private_key"], root["certificate"], private_key
            )

    def test_refuses_malformed_material(self) -> None:
        root = _native.create_root_identity()
        public_key = _native.derive_public_key(_native.generate_private_key())
        with self.assertRaises(ValueError):
            _native.issue_certificate(b"not a key", root["certificate"], public_key)
        with self.assertRaises(ValueError):
            _native.issue_certificate(root["private_key"], b"not a cert", public_key)


class StatementTest(unittest.TestCase):
    """Issuing a report as a redacted SD-CWT."""

    def test_hides_every_content_claim(self) -> None:
        issued = issue_everything()
        statement = issued["statement"]
        self.assertEqual(
            set(statement),
            {
                "registered_statement",
                "disclosures",
                "disclosure_count",
                "body_chunk_count",
                "reference_count",
                "issuer_did",
            },
        )
        registered = statement["registered_statement"]
        self.assertIsInstance(registered, bytes)
        # A COSE_Sign1, tagged 18.
        self.assertEqual(registered[0], 0xD2)
        self.assertIsInstance(statement["disclosures"], bytes)
        self.assertTrue(statement["disclosures"])
        self.assertEqual(statement["issuer_did"], issued["root"]["issuer_did"])
        self.assertEqual(statement["body_chunk_count"], 2)
        self.assertEqual(statement["reference_count"], 2)
        # The six content claims, the body's two chunks and both references.
        self.assertEqual(statement["disclosure_count"], 10)

        # Nothing the report said is in the bytes a transparency service sees.
        for secret in (b"Heap overflow in parser", b"Twelve chars", b"CVE-2024-0001"):
            self.assertNotIn(secret, registered)

    def test_refuses_a_key_the_certificate_does_not_certify(self) -> None:
        issued = issue_everything()
        with self.assertRaises(ValueError):
            _native.issue_statement(
                REPORT,
                _native.generate_private_key(),
                issued["leaf_cert"],
                issued["root"]["certificate"],
            )

    def test_refuses_a_malformed_report(self) -> None:
        issued = issue_everything()
        for document in ('{"title": "only a title"}', "{", "[]", '{"unknown": 1}'):
            with self.assertRaises(ValueError):
                _native.issue_statement(
                    document,
                    issued["private_key"],
                    issued["leaf_cert"],
                    issued["root"]["certificate"],
                )


class BundleInputTest(unittest.TestCase):
    """What the bundle operations refuse.

    A bundle that can be built needs the transparent statement a transparency
    service returns, so only the refusals are reachable here; the C++ tests own
    the rest.
    """

    def test_refuses_a_statement_that_is_not_there(self) -> None:
        issued = issue_everything()
        statement = issued["statement"]
        with self.assertRaisesRegex(ValueError, "transparent statement"):
            _native.create_bundle(
                statement["registered_statement"],
                b"",
                statement["disclosures"],
                "https://transparency.example",
                "2.14",
            )

    def test_refuses_a_disclosure_set_it_cannot_read(self) -> None:
        issued = issue_everything()
        statement = issued["statement"]
        # The disclosure set is read before the statements are encoded, so
        # this is the refusal that fires, not the empty statement below it.
        with self.assertRaisesRegex(ValueError, "disclosure set"):
            _native.create_bundle(
                statement["registered_statement"],
                b"",
                b"\x01\x02\x03",
                "https://transparency.example",
                "2.14",
            )

    def test_refuses_something_that_is_not_a_bundle(self) -> None:
        with self.assertRaises(ValueError):
            _native.inspect_bundle(b"\x01\x02")
        with self.assertRaises(ValueError):
            _native.extract_statements(b"\x01\x02")
        with self.assertRaises(ValueError):
            _native.present_bundle(b"\x01\x02", json.dumps({"version": 1}))

    def test_refuses_a_selection_it_does_not_understand(self) -> None:
        # The selection is refused before the bundle is even looked at.
        for selection in (
            json.dumps({"version": 2}),
            json.dumps({"redact_fields": ["nonesuch"]}),
            json.dumps({"unknown": 1}),
            "not json",
        ):
            with self.assertRaises(ValueError):
                _native.present_bundle(b"\x01\x02", selection)


class VerifyTest(unittest.TestCase):
    """A failed verification is an outcome, not an error."""

    def test_reports_a_failure_rather_than_raising(self) -> None:
        root = _native.create_root_identity()
        report = json.loads(_native.verify_bundle(b"\x01\x02", root["certificate"]))
        self.assertEqual(report["overall"], "fail")

        checks = {check["id"]: check for check in report["checks"]}
        self.assertEqual(
            set(checks),
            {
                "statement_binding",
                "msrc_chain",
                "issuer_signature",
                "disclosures",
                "scitt_receipt",
            },
        )
        # The receipt is never this module's to check, whatever happened.
        self.assertEqual(checks["scitt_receipt"]["status"], "skipped")
        self.assertNotEqual(checks["statement_binding"]["status"], "pass")

    def test_refuses_trust_material_that_is_not_there(self) -> None:
        root = _native.create_root_identity()
        # Passing nothing is how a caller says it holds no trust material;
        # passing something empty is a caller that believes it does.
        with self.assertRaises(ValueError):
            _native.verify_bundle(b"\x01\x02", root["certificate"], b"")
        report = json.loads(
            _native.verify_bundle(b"\x01\x02", root["certificate"], None)
        )
        self.assertEqual(report["overall"], "fail")


if __name__ == "__main__":
    unittest.main()
