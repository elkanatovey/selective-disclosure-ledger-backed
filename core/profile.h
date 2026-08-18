// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/cose.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace scitt_sd
{
  // COSE / CWT header labels used by the SCITT X.509 profile. The IANA values
  // are taken from CCF (ccf::cose::header::iana, ccf::cwt::header::iana) where
  // CCF defines them; the two labels below are defined by SCITT and SD-CWT.
  namespace label
  {
    // Receipts on a transparent statement (draft-ietf-scitt-architecture),
    // carried in the COSE unprotected header.
    inline constexpr int64_t SCITT_RECEIPTS = 394;
    // Disclosures on an SD-CWT (draft-ietf-spice-sd-cwt), unprotected header.
    inline constexpr int64_t SD_CLAIMS = 17;
  }

  // The X.509 Extended Key Usage OID an issuing leaf certificate must carry
  // for this profile: id-kp-codeSigning (RFC 5280).
  inline constexpr std::string_view CODE_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.3";

  // Everything the issuer contributes to a statement's protected header.
  struct IssuerIdentity
  {
    // CWT `iss` (claim 1): did:x509:0:sha256:<root fingerprint>::eku:<oid>.
    std::string issuer_did;
    // CWT `sub` (claim 2): the subject the report is about.
    std::string subject;
    // x5chain (header 33), leaf first, trust anchor last. At least two
    // certificates: the signing leaf and the root the DID pins.
    std::vector<std::vector<uint8_t>> x5chain_der;
  };

  // Individual policies of a did:x509 identifier, e.g. {"eku", "1.3..."}.
  struct DidX509Policy
  {
    std::string name;
    std::vector<std::string> args;
  };

  struct DidX509
  {
    std::string fingerprint_alg; // "sha256"
    std::string fingerprint; // base64url(SHA-256(root DER)), unpadded
    std::vector<DidX509Policy> policies;
  };

  // base64url(SHA-256(root DER)), unpadded: the CA fingerprint a did:x509
  // pins. Uses the CCF digest and base64url implementations.
  std::string did_x509_ca_fingerprint(std::span<const uint8_t> root_der);

  // Compose did:x509:0:sha256:<fingerprint>::eku:<oid> for a trust anchor.
  std::string make_did_x509(
    std::span<const uint8_t> root_der,
    std::string_view eku_oid = CODE_SIGNING_EKU_OID);

  // Parse a did:x509 identifier. Only version 0 is accepted, and at least one
  // policy is required. Throws std::invalid_argument for anything else.
  DidX509 parse_did_x509(std::string_view did);

  // Extra protected-header entries for the SCITT X.509 profile:
  //   2   crit      = [15, 33]
  //   15  CWT claims= {1: <issuer did:x509>, 2: <subject>}
  //   33  x5chain   = [leaf DER, ..., root DER]
  // alg (1), typ (16) = 293 and sd_alg (170) are added by the SD-CWT layer, so
  // the full profile header is
  //   {1: alg, 2: crit, 15: cwt claims, 16: typ, 33: x5chain, 170: sd_alg}
  // emitted in CDE order.
  //
  // Throws std::invalid_argument if the DID or subject is empty, the DID is
  // not a valid did:x509, or the chain has fewer than two certificates.
  sdcwt::HeaderEntries scitt_x509_header_entries(const IssuerIdentity& issuer);
}
