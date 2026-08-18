// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The Python extension module: an in-process binding to the in-memory API.
//
// A caller that already holds the bytes can reach the API through this module
// instead of writing them into temporary files and spawning a tool to read
// them back, so that a private key travels from an upload straight into the
// API and never reaches a disk. The demo's web control plane does not: it runs
// the command line tool, and this module is an option open to it and to any
// other Python caller.
//
// Nothing here decides anything: every function is a translation of Python
// values into native/api.h and of its results back.
//
// The module exposes no class and holds no state, so two calls can never share
// anything, and the interpreter lock is released around each one: the API is
// pure computation over borrowed buffers.

#include "native/api.h"

#include <cstdint>
#include <exception>
#include <optional>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <span>
#include <string>
#include <utility>
#include <vector>

#ifndef SCITT_SD_VERSION
#  define SCITT_SD_VERSION "0.0.0-dev"
#endif

namespace py = pybind11;

namespace
{
  using scitt_sd::native::Bytes;

  // Borrow the buffer of a `bytes` argument. The object is alive for the whole
  // call (this frame holds a reference to it) and its contents are immutable,
  // so a span over it is valid until the call returns, and nothing is copied
  // on the way in.
  std::span<const uint8_t> as_span(const py::bytes& value)
  {
    char* data = nullptr;
    Py_ssize_t size = 0;
    if (PyBytes_AsStringAndSize(value.ptr(), &data, &size) != 0)
    {
      throw py::error_already_set();
    }
    return {reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(size)};
  }

  py::bytes to_bytes(const Bytes& bytes)
  {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
  }

  // Run one API call with the interpreter lock released. Everything Python
  // touched has already been borrowed or copied by the time this is reached,
  // and the result is turned back into Python objects by the caller, with the
  // lock held again.
  template <typename Fn>
  auto without_gil(Fn&& call) -> decltype(call())
  {
    const py::gil_scoped_release released;
    return call();
  }
}

PYBIND11_MODULE(_native, module)
{
  namespace native = scitt_sd::native;

  module.doc() =
    "Selective-disclosure operations, in process.\n\n"
    "Byte oriented bindings to the C++ API that issues, bundles, presents and "
    "checks selectively disclosable reports. Every argument named below is "
    "`bytes` unless it is documented as text, and nothing here reads or "
    "writes a file: private keys stay in memory for exactly as long as the "
    "call that was given them.\n\n"
    "An input this module refuses raises ValueError; a failure that is not "
    "the caller's doing raises RuntimeError. A failed verification is neither: "
    "verify_bundle returns a report saying so.";
  module.attr("__version__") = SCITT_SD_VERSION;

  // InvalidInput and OperationFailed both derive from std::runtime_error,
  // which pybind11 would otherwise report as RuntimeError alike. The
  // distinction is the point: one of them is the caller's to fix.
  py::register_exception_translator([](std::exception_ptr error) {
    try
    {
      if (error)
      {
        std::rethrow_exception(error);
      }
    }
    catch (const native::InvalidInput& e)
    {
      PyErr_SetString(PyExc_ValueError, e.what());
    }
    catch (const native::OperationFailed& e)
    {
      PyErr_SetString(PyExc_RuntimeError, e.what());
    }
  });

  module.def(
    "generate_private_key",
    []() {
      const auto key =
        without_gil([] { return native::generate_private_key(); });
      return to_bytes(key);
    },
    "Create a fresh P-256 signing key.\n\n"
    "Returns the private key as PEM bytes. It is the caller's only copy: "
    "nothing here retains it.");

  module.def(
    "derive_public_key",
    [](const py::bytes& private_key) {
      const auto span = as_span(private_key);
      const auto public_key =
        without_gil([&span] { return native::derive_public_key(span); });
      return to_bytes(public_key);
    },
    py::arg("private_key"),
    "Derive the public half of a PEM private key.\n\n"
    "Returns PEM bytes. This is what is sent to be certified, so that a "
    "private key never leaves the machine that made it.");

  module.def(
    "create_root_identity",
    []() {
      auto identity =
        without_gil([] { return native::create_root_identity(); });
      py::dict result;
      result["private_key"] = to_bytes(identity.private_key);
      result["certificate"] = to_bytes(identity.certificate);
      result["issuer_json"] = std::move(identity.issuer_json);
      result["issuer_did"] = std::move(identity.issuer_did);
      return result;
    },
    "Create the demo trust anchor.\n\n"
    "Returns {'private_key': bytes, 'certificate': bytes, 'issuer_json': str, "
    "'issuer_did': str}: the CA private key as PEM, the self-signed CA "
    "certificate as PEM, the issuer identity that CA endorses as a JSON "
    "document, and the issuer did:x509 that document carries.");

  module.def(
    "issue_certificate",
    [](
      const py::bytes& root_key,
      const py::bytes& root_cert,
      const py::bytes& public_key) {
      const auto key_span = as_span(root_key);
      const auto cert_span = as_span(root_cert);
      const auto public_span = as_span(public_key);
      const auto certificate = without_gil([&] {
        return native::issue_certificate(key_span, cert_span, public_span);
      });
      return to_bytes(certificate);
    },
    py::arg("root_key"),
    py::arg("root_cert"),
    py::arg("public_key"),
    "Endorse a reporter public key with the demo CA.\n\n"
    "Returns the leaf certificate as PEM bytes. The CA never sees the "
    "reporter's private key.");

  module.def(
    "issue_statement",
    [](
      const std::string& report_json,
      const py::bytes& private_key,
      const py::bytes& leaf_cert,
      const py::bytes& root_cert) {
      const auto key_span = as_span(private_key);
      const auto leaf_span = as_span(leaf_cert);
      const auto root_span = as_span(root_cert);
      auto issued = without_gil([&] {
        return native::issue_statement(
          report_json, key_span, leaf_span, root_span);
      });
      py::dict result;
      result["registered_statement"] = to_bytes(issued.registered_statement);
      result["disclosures"] = to_bytes(issued.disclosure_set);
      result["disclosure_count"] = issued.disclosure_count;
      result["body_chunk_count"] = issued.body_chunk_count;
      result["reference_count"] = issued.reference_count;
      result["issuer_did"] = std::move(issued.issuer_did);
      return result;
    },
    py::arg("report_json"),
    py::arg("private_key"),
    py::arg("leaf_cert"),
    py::arg("root_cert"),
    "Issue a report as a redacted SD-CWT.\n\n"
    "`report_json` is the report document, as text. Returns "
    "{'registered_statement': bytes, 'disclosures': bytes, "
    "'disclosure_count': int, 'body_chunk_count': int, 'reference_count': "
    "int, 'issuer_did': str}: the exact bytes a transparency service "
    "registers, and the disclosure set that can reopen them.");

  module.def(
    "prepare_statement",
    [](
      const std::string& report_json,
      const py::bytes& public_key,
      const py::bytes& leaf_cert,
      const py::bytes& root_cert) {
      const auto key_span = as_span(public_key);
      const auto leaf_span = as_span(leaf_cert);
      const auto root_span = as_span(root_cert);
      auto prepared = without_gil([&] {
        return native::prepare_statement(
          report_json, key_span, leaf_span, root_span);
      });
      py::dict result;
      result["to_be_signed"] = to_bytes(prepared.to_be_signed);
      result["protected_header"] = to_bytes(prepared.protected_header);
      result["payload"] = to_bytes(prepared.payload);
      result["disclosures"] = to_bytes(prepared.disclosure_set);
      result["disclosure_count"] = prepared.disclosure_count;
      result["body_chunk_count"] = prepared.body_chunk_count;
      result["reference_count"] = prepared.reference_count;
      result["issuer_did"] = std::move(prepared.issuer_did);
      return result;
    },
    py::arg("report_json"),
    py::arg("public_key"),
    py::arg("leaf_cert"),
    py::arg("root_cert"),
    "Build a redacted SD-CWT for a holder that keeps its own key.\n\n"
    "Takes the holder's certified public key, never a private key. Returns "
    "{'to_be_signed': bytes, 'protected_header': bytes, 'payload': bytes, "
    "'disclosures': bytes, 'disclosure_count': int, 'body_chunk_count': int, "
    "'reference_count': int, 'issuer_did': str}. The holder signs "
    "'to_be_signed' and nothing else; pass the result to attach_signature.");

  module.def(
    "attach_signature",
    [](
      const py::bytes& protected_header,
      const py::bytes& payload,
      const py::bytes& signature) {
      const auto header_span = as_span(protected_header);
      const auto payload_span = as_span(payload);
      const auto signature_span = as_span(signature);
      const auto statement = without_gil([&] {
        return native::attach_signature(
          header_span, payload_span, signature_span);
      });
      return to_bytes(statement);
    },
    py::arg("protected_header"),
    py::arg("payload"),
    py::arg("signature"),
    "Combine a prepared statement with the holder's signature.\n\n"
    "`signature` is raw r||s, which is what WebCrypto's ECDSA produces. "
    "Returns the exact bytes a transparency service registers.");

  module.def(
    "mock_register_statement",
    [](const py::bytes& registered_statement, const py::bytes& ledger_key) {
      const auto statement_span = as_span(registered_statement);
      const auto key_span = as_span(ledger_key);
      auto registration = without_gil([&] {
        return native::mock_register_statement(statement_span, key_span);
      });
      py::dict result;
      result["transparent_statement"] =
        to_bytes(registration.transparent_statement);
      result["receipt"] = to_bytes(registration.receipt);
      return result;
    },
    py::arg("registered_statement"),
    py::arg("ledger_key"),
    "Register a statement with the demo's stand-in transparency service.\n\n"
    "Signs a receipt over the exact statement bytes and attaches it at "
    "unprotected header 394. Returns {'transparent_statement': bytes, "
    "'receipt': bytes}. This is not a transparency service: there is no log "
    "and no inclusion proof, so the receipt proves only that this key saw "
    "these bytes.");

  module.def(
    "create_bundle",
    [](
      const py::bytes& registered_statement,
      const py::bytes& transparent_statement,
      const py::bytes& disclosures,
      const std::string& scitt_url,
      const std::string& txid,
      std::optional<int64_t> timestamp) {
      const auto registered_span = as_span(registered_statement);
      const auto transparent_span = as_span(transparent_statement);
      const auto disclosures_span = as_span(disclosures);
      const auto created = without_gil([&] {
        return native::create_bundle(
          registered_span,
          transparent_span,
          disclosures_span,
          scitt_url,
          txid,
          timestamp);
      });
      return to_bytes(created.bundle);
    },
    py::arg("registered_statement"),
    py::arg("transparent_statement"),
    py::arg("disclosures"),
    py::arg("scitt_url"),
    py::arg("txid"),
    py::arg("timestamp") = py::none(),
    "Combine the statements and the disclosure set into a proof bundle.\n\n"
    "`scitt_url` and `txid` are text. `timestamp` is seconds since the epoch "
    "and defaults to now. Returns the bundle as bytes.");

  module.def(
    "inspect_bundle",
    [](const py::bytes& bundle) {
      const auto span = as_span(bundle);
      return without_gil([&span] { return native::inspect_bundle(span); });
    },
    py::arg("bundle"),
    "Describe what a bundle currently reveals.\n\n"
    "Returns a JSON document, as text: the profile's fields, the body chunk "
    "by chunk, the transparency service reference and the notes a viewer "
    "shows. The issuer signature and the disclosures are checked so that only "
    "authentic content is described; no trust anchor is consulted and no "
    "receipt is verified.");

  module.def(
    "extract_statements",
    [](const py::bytes& bundle) {
      const auto span = as_span(bundle);
      const auto statements =
        without_gil([&span] { return native::extract_statements(span); });
      return py::make_tuple(
        to_bytes(statements.registered_statement),
        to_bytes(statements.transparent_statement));
    },
    py::arg("bundle"),
    "Copy the exact statement bytes out of a bundle.\n\n"
    "Returns (registered_statement, transparent_statement) as bytes, "
    "unchanged: they are what the official SCITT verifier has to be given, "
    "and what a receipt is bound to.");

  module.def(
    "present_bundle",
    [](const py::bytes& bundle, const std::string& selection_json) {
      const auto span = as_span(bundle);
      const auto presented = without_gil(
        [&] { return native::present_bundle(span, selection_json); });
      return to_bytes(presented.bundle);
    },
    py::arg("bundle"),
    py::arg("selection_json"),
    "Drop the selected disclosures from a bundle.\n\n"
    "`selection_json` is the selection document, as text: {'version': 1, "
    "'redact_fields': [...], 'redact_body_chunks': [...]}. Returns the "
    "presented bundle as bytes; its statements are carried over byte for "
    "byte.");

  module.def(
    "verify_bundle",
    [](
      const py::bytes& bundle,
      const py::bytes& msrc_root,
      const std::optional<py::bytes>& scitt_trust) {
      const auto bundle_span = as_span(bundle);
      const auto root_span = as_span(msrc_root);
      std::optional<std::span<const uint8_t>> trust_span;
      if (scitt_trust.has_value())
      {
        trust_span = as_span(*scitt_trust);
      }
      auto outcome = without_gil([&] {
        return native::verify_bundle(bundle_span, root_span, trust_span);
      });
      return outcome.report_json;
    },
    py::arg("bundle"),
    py::arg("msrc_root"),
    py::arg("scitt_trust") = py::none(),
    "Check the four things this API owns.\n\n"
    "The registered/transparent binding, the MSRC certificate chain and "
    "did:x509, the issuer signature and the disclosures, against the "
    "separately supplied MSRC root. Returns the report as a JSON document, as "
    "text, whether verification passed or failed; its 'overall' member says "
    "which.\n\n"
    "The SCITT receipt is NOT checked and is always reported as skipped: the "
    "official SCITT verifier owns it. `scitt_trust` is accepted for callers "
    "that hold that trust material and is deliberately never parsed; only its "
    "presence is checked.");
}
