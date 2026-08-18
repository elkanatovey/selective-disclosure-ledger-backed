// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/profile.h"
#include "core/sd_cwt.h"
#include "core/text_chunks.h"

#include <array>
#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace scitt_sd::report
{
  // Report profile claim labels. The content claims are all selectively
  // disclosable; only `iat` is issued in the clear.
  namespace label
  {
    inline constexpr int64_t IAT = sdcwt::CWT_IAT; // 6, clear
    inline constexpr int64_t TITLE = 1001;
    inline constexpr int64_t BODY = 1002;
    inline constexpr int64_t COMPONENT = 1003;
    inline constexpr int64_t SEVERITY = 1004;
    inline constexpr int64_t FINGERPRINT = 1005;
    inline constexpr int64_t REFERENCES = 1006;
  }

  // The profile's content claims, in ascending label order.
  inline constexpr std::array<int64_t, 6> CONTENT_LABELS = {
    label::TITLE,
    label::BODY,
    label::COMPONENT,
    label::SEVERITY,
    label::FINGERPRINT,
    label::REFERENCES};

  // A report to be issued. Text fields must be well-formed UTF-8; the body is
  // split into TEXT_CHUNK_SIZE code-point chunks, each individually
  // disclosable.
  struct ReportInput
  {
    int64_t issued_at = 0; // CWT iat, seconds since the epoch
    std::string title;
    std::string body;
    std::string component;
    std::string severity;
    std::vector<uint8_t> fingerprint; // opaque report fingerprint
    std::vector<std::string> references;
  };

  struct IssuedReport
  {
    // The registered statement: a signed COSE_Sign1 with every content claim
    // redacted and NO disclosures attached. These exact bytes are what a
    // transparency service registers.
    std::vector<uint8_t> statement;
    // Every disclosure produced for the report, including the body/references
    // parents and each of their children.
    std::vector<sdcwt::Disclosure> disclosures;
    size_t body_chunk_count = 0;
    size_t reference_count = 0;
  };

  // Issue a report as a redacted SD-CWT carrying the SCITT X.509 profile
  // headers. Salts come from the CCF CSPRNG.
  //
  // Throws std::invalid_argument for malformed UTF-8, a negative issued_at, a
  // malformed issuer identity or an unsupported signing curve.
  IssuedReport issue(
    const ReportInput& input,
    const IssuerIdentity& issuer,
    const ccf::crypto::ECKeyPair& key,
    sdcwt::HashAlg sd_alg = sdcwt::HashAlg::SHA_256);

  // What a presenter chooses to reveal. Ancestors are added automatically: a
  // body chunk implies the body claim, a reference element implies the
  // references claim.
  struct Selection
  {
    // Whole content claims, e.g. {label::TITLE, label::SEVERITY}. Selecting
    // label::BODY or label::REFERENCES on its own reveals only their redacted
    // shape (how many chunks/elements exist).
    std::vector<int64_t> fields;
    std::vector<size_t> body_chunks; // stable chunk indices
    std::vector<size_t> references; // element indices
  };

  // Resolve a selection to disclosure bytes, ancestors included, in a stable
  // (parent-before-child) order.
  //
  // Throws std::invalid_argument for an unknown field label and
  // std::out_of_range for a chunk/element index the report does not have.
  std::vector<std::vector<uint8_t>> select_disclosures(
    const IssuedReport& issued, const Selection& selection);

  // Build a presentation from a transparent statement (a registered statement
  // with its receipts attached): sets the disclosures header (17) to
  // `selected` and preserves every other unprotected header entry, including
  // the SCITT receipts header (394). Neither the payload nor the signature is
  // touched.
  std::vector<uint8_t> present(
    std::span<const uint8_t> transparent_statement,
    const std::vector<std::vector<uint8_t>>& selected);

  // "title", "body", ... for a content label; empty for an unknown label.
  std::string field_name(int64_t claim_label);

  // Human-readable disclosure path, e.g. "title", "body[3]", "references[1]".
  std::string describe_path(const sdcwt::Path& path);
}
