// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// The selective-disclosure operations, in memory.
//
// Everything the demo does to a report, a statement or a proof bundle lives
// here: bytes in, bytes out. Nothing in this API opens, creates or removes a
// file, and nothing here logs. The command line tool is a file adapter over
// it, and the Python extension module is an in-process binding to it; neither
// re-implements any of the logic below.
//
// CBOR and COSE go exclusively through ccf::cbor, CCF's EverCBOR backed
// API: the statements and receipts through the core, and the disclosure set
// this library owns through core/cbor_value.h. Nothing here writes CBOR by
// hand. Cryptography goes exclusively through the CCF crypto APIs.

#include "native/errors.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace scitt_sd::native
{
  using Bytes = std::vector<uint8_t>;

  // Size ceilings for untrusted input. They bound the work an oversized
  // document can cost before anything parses it, and they are what the file
  // adapter applies to a file before it reads it, so that neither side can be
  // made to accept something the other would refuse.
  namespace limits
  {
    inline constexpr size_t MAX_PEM_BYTES = 64UL * 1024UL;
    inline constexpr size_t MAX_JSON_BYTES = 1024UL * 1024UL;
    inline constexpr size_t MAX_BUNDLE_BYTES = 4UL * 1024UL * 1024UL;
    inline constexpr size_t MAX_STATEMENT_BYTES = 4UL * 1024UL * 1024UL;
    inline constexpr size_t MAX_DISCLOSURE_SET_BYTES = 4UL * 1024UL * 1024UL;
    inline constexpr size_t MAX_TRUST_MATERIAL_BYTES = 4UL * 1024UL * 1024UL;
  }

  // --- keys and identities ---------------------------------------------------

  // A fresh P-256 signing key, PEM encoded. The same curve every other key in
  // the demo uses: a statement signed with ES256 has to be verifiable by the
  // profile's single algorithm.
  //
  // The returned bytes are private key material and are the caller's only
  // copy; nothing here retains or writes them.
  Bytes generate_private_key();

  // The public half of a private key, PEM encoded. This is what is sent to be
  // certified, so that a private key never leaves the machine that made it.
  //
  // Throws InvalidInput if the PEM is not an EC private key.
  Bytes derive_public_key(std::span<const uint8_t> private_key_pem);

  // The demo's trust anchor.
  struct RootIdentity
  {
    Bytes private_key; // PEM, private key material
    Bytes certificate; // PEM, the self-signed CA certificate
    // The issuer identity the CA endorses, as a JSON object: the profile's
    // subjects, the CA fingerprint, the issuer did:x509 and the validity the
    // certificates were minted with.
    std::string issuer_json;
    std::string issuer_did; // also carried in issuer_json
  };

  // Create a P-256 key, the self-signed CA certificate it holds, and the
  // identity that CA endorses.
  //
  // Throws OperationFailed if the key or certificate cannot be created.
  RootIdentity create_root_identity();

  // Endorse a reporter's public key with the demo CA, returning the leaf
  // certificate as PEM. The CA never sees the reporter's private key.
  //
  // Throws InvalidInput if any PEM is malformed, if the public key is not a
  // public key, or if the CA cannot endorse it.
  Bytes issue_certificate(
    std::span<const uint8_t> root_key_pem,
    std::span<const uint8_t> root_cert_pem,
    std::span<const uint8_t> public_key_pem);

  // --- statements ------------------------------------------------------------

  struct IssuedStatement
  {
    // The exact bytes a transparency service registers: a COSE_Sign1 with
    // every content claim redacted and no disclosures attached.
    Bytes registered_statement;
    // Every disclosure the statement commits to, each with the path that says
    // what it discloses. Opaque to a caller; it is handed back to
    // create_bundle unchanged.
    Bytes disclosure_set;
    size_t disclosure_count = 0;
    size_t body_chunk_count = 0;
    size_t reference_count = 0;
    std::string issuer_did;
  };

  // Issue a report as a redacted SD-CWT. `report_json` is the report document
  // parse_report_json accepts. The CWT `iat` claim is the current time.
  //
  // Throws InvalidInput for a malformed report, a malformed key or
  // certificate, or a leaf certificate that does not certify the key.
  IssuedStatement issue_statement(
    std::string_view report_json,
    std::span<const uint8_t> private_key_pem,
    std::span<const uint8_t> leaf_cert_pem,
    std::span<const uint8_t> root_cert_pem);

  // A statement built for a signer whose private key this process never sees.
  struct PreparedStatement
  {
    // Exactly the bytes the holder signs, and the only thing it is asked to
    // sign: the RFC 9052 Sig_structure for the statement below.
    Bytes to_be_signed;
    // The two halves of the statement, held until the signature returns and
    // then handed back to attach_signature unchanged.
    Bytes protected_header;
    Bytes payload;
    // As for issue_statement: opaque, and handed to create_bundle unchanged.
    Bytes disclosure_set;
    size_t disclosure_count = 0;
    size_t body_chunk_count = 0;
    size_t reference_count = 0;
    std::string issuer_did;
  };

  // Build a report's redacted SD-CWT for a holder that keeps its own key.
  // Only the holder's certified public key is needed, so no private key
  // reaches this process at all.
  //
  // `confirmation_key_pem` is the EC public key of the party that will later
  // release the disclosures. It is published in the clear as the `cnf` claim,
  // so that a release signed by the matching private key is attributable to
  // that party. Empty omits the claim.
  //
  // Throws InvalidInput for a malformed report, a malformed public key or
  // certificate, a leaf certificate that does not certify the public key, or
  // a key on a curve this profile cannot use.
  PreparedStatement prepare_statement(
    std::string_view report_json,
    std::span<const uint8_t> public_key_pem,
    std::span<const uint8_t> leaf_cert_pem,
    std::span<const uint8_t> root_cert_pem,
    std::span<const uint8_t> confirmation_key_pem = {});

  // Combine a prepared statement with the holder's signature over its
  // `to_be_signed` bytes, producing the exact bytes a transparency service
  // registers. `signature` must be raw r||s (IEEE P1363), which is what
  // WebCrypto's ECDSA produces.
  //
  // Throws InvalidInput if a part is missing or the signature is not the
  // right length.
  Bytes attach_signature(
    std::span<const uint8_t> protected_header,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature);

  // --- demo transparency service ---------------------------------------------

  struct MockRegistration
  {
    Bytes transparent_statement; // the statement with its receipt attached
    Bytes receipt; // the receipt on its own
  };

  // Register a statement with the demo's stand-in for a transparency service:
  // sign a receipt over the exact registered statement bytes and attach it to
  // that statement's unprotected header (394), leaving the issuer's signature
  // intact.
  //
  // This is NOT a transparency service. There is no append-only log, no
  // inclusion proof and no consistency proof, so a receipt from here proves
  // only that this key saw these bytes. It exists so the demo can run the
  // whole submission shape without a ledger.
  //
  // Throws InvalidInput if the statement is empty or oversized, if the key is
  // not usable, or if the receipt cannot be attached.
  MockRegistration mock_register_statement(
    std::span<const uint8_t> registered_statement,
    std::span<const uint8_t> ledger_key_pem);

  // --- proof bundles ---------------------------------------------------------

  struct CreatedBundle
  {
    Bytes bundle;
    size_t disclosure_count = 0;
  };

  // Combine the registered statement, the transparent statement the
  // transparency service returned and the disclosure set into one bundle.
  // `timestamp` defaults to the current time.
  //
  // Throws InvalidInput if a statement is empty or oversized, if the
  // disclosure set cannot be read, or if the bundle cannot be encoded.
  CreatedBundle create_bundle(
    std::span<const uint8_t> registered_statement,
    std::span<const uint8_t> transparent_statement,
    std::span<const uint8_t> disclosures,
    std::string_view scitt_url,
    std::string_view txid,
    std::optional<int64_t> timestamp = std::nullopt);

  // What a bundle currently reveals, as a JSON object: the profile's fields,
  // the body chunk by chunk, the transparency service reference and the notes
  // a viewer shows.
  //
  // This checks the issuer's own signature and the disclosures so that nothing
  // meaningless is rendered; it makes NO trust decision, consults no trust
  // anchor and does not look at the receipt.
  //
  // Throws InvalidInput if the bundle cannot be decoded or displayed.
  std::string inspect_bundle(std::span<const uint8_t> bundle_bytes);

  struct Statements
  {
    Bytes registered_statement;
    Bytes transparent_statement;
  };

  // The exact statement bytes a bundle carries, unchanged: they are what the
  // official SCITT verifier has to be given, and what a receipt is bound to.
  //
  // Throws InvalidInput if the bundle cannot be decoded.
  Statements extract_statements(std::span<const uint8_t> bundle_bytes);

  struct PresentedBundle
  {
    Bytes bundle;
    size_t dropped = 0;
    size_t total = 0;
  };

  // Drop the selected disclosures from a bundle. The statements are carried
  // over byte for byte: redaction removes disclosures and nothing else.
  //
  // `selection_json` is a JSON object:
  //
  //   {"version": 1, "redact_fields": [str, ...],
  //    "redact_body_chunks": [uint, ...]}
  //
  // Every member is optional; an unknown member, an unknown field name or an
  // unsupported version is refused.
  //
  // Throws InvalidInput for a malformed selection, a bundle that cannot be
  // decoded, or a presentation that would not be readable.
  PresentedBundle present_bundle(
    std::span<const uint8_t> bundle_bytes, std::string_view selection_json);

  struct VerificationOutcome
  {
    // Whether the four checks this API owns all passed. The SCITT receipt is
    // not one of them, so a pass says nothing about transparency.
    bool passed = false;
    // The report, as a JSON object, whether verification passed or failed.
    std::string report_json;
    // Why verification failed, empty when it passed.
    std::string reason;
  };

  // Check the four things this API owns: the registered/transparent binding,
  // the MSRC certificate chain and did:x509, the issuer's signature and the
  // disclosures. The SCITT receipt is NOT checked here and is always reported
  // as skipped; the official SCITT verifier owns it.
  //
  // A failed check is an outcome, not an error: the report describes it and
  // `passed` is false. InvalidInput is thrown only when there was nothing to
  // check, so a caller can never mistake one for the other.
  //
  // `scitt_trust` is accepted for callers that hold the SCITT trust material,
  // and deliberately not parsed: no receipt is verified here. Only its
  // presence is checked, so a caller that believes it supplied trust material
  // is told when it did not.
  VerificationOutcome verify_bundle(
    std::span<const uint8_t> bundle_bytes,
    std::span<const uint8_t> msrc_root_pem,
    const std::optional<std::span<const uint8_t>>& scitt_trust = std::nullopt);
}
