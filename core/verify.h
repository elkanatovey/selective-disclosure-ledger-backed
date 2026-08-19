// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/bundle.h"
#include "core/profile.h"
#include "core/sd_cwt.h"

#include <ccf/crypto/pem.h>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace scitt_sd::verify
{
  // The independent checks a proof bundle goes through, in the order they are
  // performed. A failure names the check it belongs to, so a caller can report
  // the checks separately instead of collapsing them into a single verdict.
  enum class Check : uint8_t
  {
    // The bundle itself: its version, its two COSE_Sign1 statements, and the
    // requirement that the transparent statement is the registered statement
    // plus unprotected headers (a receipt among them).
    StatementBinding,
    // The SCITT X.509 profile header, the chain to the separately trusted
    // root, and the issuer's did:x509.
    MsrcChain,
    // The issuer's COSE signature under the leaf public key.
    IssuerSignature,
    // The redacted payload and every presented disclosure.
    Disclosures,
    // Receipt verification, when a ReceiptVerifier is supplied.
    Receipt,
  };

  // Any failed check. Carries no attacker-controlled data beyond a short
  // description of the check that failed. `check()` says which check that was;
  // a failure raised before any later check is reached belongs to the bundle's
  // statements, hence the default.
  class VerificationError : public std::runtime_error
  {
  public:
    explicit VerificationError(
      const std::string& what, Check check = Check::StatementBinding) :
      std::runtime_error("verification failed: " + what),
      why(what),
      failed_check(check)
    {}

    // The description without the "verification failed: " prefix.
    [[nodiscard]] const std::string& reason() const noexcept
    {
      return why;
    }

    [[nodiscard]] Check check() const noexcept
    {
      return failed_check;
    }

  private:
    std::string why;
    Check failed_check;
  };

  // The payload of a COSE_Sign1, copied out. Opens a signed release without
  // saying anything about its signature.
  //
  // Throws VerificationError if the bytes are not a COSE_Sign1.
  std::vector<uint8_t> cose_payload(std::span<const uint8_t> signed_bytes);

  // The confirmation key a registered statement names in its `cnf` claim,
  // rendered as a PEM public key. Empty when the statement carries no cnf: a
  // release for such a statement cannot be attributed to anyone, which is a
  // different answer from a release that fails to verify.
  //
  // Throws VerificationError if the statement or its cnf is malformed.
  std::string confirmation_key_pem(
    std::span<const uint8_t> registered_statement);

  // What a receipt verifier could establish about a receipt.
  struct ReceiptInfo
  {
    std::string txid; // transparency service transaction id, if known
    std::string issuer; // receipt issuer (CWT iss), if known
  };

  // Verifies one SCITT receipt against the EXACT registered statement bytes.
  //
  // The transparency service's identity (its service key, its endorsement
  // chain, or whatever else it publishes) is a property of the implementation,
  // not of this interface, so a caller chooses its own trust anchor. A test
  // may substitute a fake to prove that the exact registered statement bytes
  // reach the receipt check.
  //
  // Implementations MUST throw on any failure; returning normally means the
  // receipt is valid for those statement bytes.
  class ReceiptVerifier
  {
  public:
    ReceiptVerifier() = default;
    ReceiptVerifier(const ReceiptVerifier&) = delete;
    ReceiptVerifier& operator=(const ReceiptVerifier&) = delete;
    ReceiptVerifier(ReceiptVerifier&&) = delete;
    ReceiptVerifier& operator=(ReceiptVerifier&&) = delete;
    virtual ~ReceiptVerifier() = default;

    virtual ReceiptInfo verify(
      std::span<const uint8_t> receipt,
      std::span<const uint8_t> registered_statement) const = 0;
  };

  struct Params
  {
    // The separately trusted root: obtained out of band, NOT from the bundle.
    // The statement's x5chain must end at exactly this certificate.
    ccf::crypto::Pem trusted_root;
    // The EKU OID the issuer's did:x509 must pin, and the leaf certificate
    // must therefore carry. Empty disables the check.
    std::string required_eku{CODE_SIGNING_EKU_OID};
    // Skip X.509 validity-period checks. For tests with fixed fixtures only.
    bool ignore_certificate_time = false;
  };

  // Report content recovered from the presented disclosures. A field is
  // present only when its disclosure was supplied (and, for a chunk or
  // element, when its parent was disclosed too).
  struct DisclosedReport
  {
    std::optional<std::string> title;
    std::optional<std::string> component;
    std::optional<std::string> severity;
    std::optional<std::vector<uint8_t>> fingerprint;

    bool body_disclosed = false;
    size_t body_chunk_count = 0; // chunks that exist, once the body is shown
    std::map<size_t, std::string> body_chunks;

    bool references_disclosed = false;
    size_t reference_count = 0;
    std::map<size_t, std::string> references;
  };

  struct Result
  {
    std::string issuer_did; // CWT iss from the protected header
    std::string subject; // CWT sub from the protected header
    int64_t issued_at = 0; // CWT iat from the clear payload
    std::string leaf_subject; // X.509 subject of the signing leaf
    std::vector<ReceiptInfo> receipts;
    DisclosedReport disclosed;
    // The path each presented disclosure resolved to, positionally matching
    // the bundle's disclosure list: {1001} for a whole claim, {1002, 3} for a
    // body chunk, {1006, 1} for a reference element, empty for a decoy. A
    // presenter uses these to decide which disclosure bytes to drop, rather
    // than re-deriving what each byte string means.
    std::vector<sdcwt::Path> disclosure_paths;
  };

  // Verify a proof bundle end to end:
  //   1. the transparent statement's protected header, payload and signature
  //      are byte-identical to the registered statement's;
  //   2. the registered statement carries no disclosures;
  //   3. the protected header conforms to the SCITT X.509 profile;
  //   4. the x5chain ends at the separately trusted root, and the leaf chains
  //      to it and is within its validity period (CCF X.509 APIs);
  //   5. the issuer's did:x509 pins that same root, and its policies (EKU
  //      included) hold for the chain;
  //   6. the issuer's COSE signature verifies under the leaf public key;
  //   7. the payload conforms to the report profile (only iat in the clear);
  //   8. every presented disclosure is committed to by the payload, with
  //      ancestors resolved before their children;
  //   9. every receipt on the transparent statement verifies against the
  //      exact registered statement bytes.
  //
  // Throws VerificationError if any check fails.
  Result verify_bundle(
    const bundle::ProofBundle& bundle,
    const Params& params,
    const ReceiptVerifier& receipt_verifier);

  // Steps 1 to 8 only: no receipt is examined, so a successful return says
  // nothing whatsoever about transparency. The transparent statement must
  // still CARRY a receipt (step 1), but whether that receipt is valid is left
  // to a SCITT receipt verifier, which a caller must run separately before
  // claiming anything about registration or ordering.
  //
  // Throws VerificationError if any check fails.
  Result verify_bundle(const bundle::ProofBundle& bundle, const Params& params);

  // Steps 1, 2, 3, 6, 7 and 8: what a bundle contains, with the issuer's own
  // signature and the disclosures checked, and NO trust decision at all. No
  // trust anchor is consulted, so the certificate chain, the issuer's did:x509
  // and the receipt are all left unchecked: the leaf key is taken from the
  // bundle's own x5chain. This is enough to DISPLAY a bundle and no more; it
  // establishes neither who the issuer is nor that anything was registered.
  //
  // Throws VerificationError if any check fails.
  Result inspect_bundle(const bundle::ProofBundle& bundle);
}
