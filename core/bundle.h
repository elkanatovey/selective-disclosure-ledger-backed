// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace scitt_sd::bundle
{
  // Everything a verifier needs, offline, to check a selectively disclosed
  // report: the exact bytes that were registered, the transparent statement
  // returned by the transparency service, and the disclosures being revealed.
  //
  // Encoded as a CBOR map with integer labels, using ccf::cbor only.

  inline constexpr int64_t VERSION = 1;

  namespace label
  {
    inline constexpr int64_t VERSION = 1; // uint, bundle format version
    inline constexpr int64_t REGISTERED_STATEMENT = 2; // bstr, exact bytes
    inline constexpr int64_t TRANSPARENT_STATEMENT = 3; // bstr, with receipts
    inline constexpr int64_t DISCLOSURES = 4; // [* bstr]
    inline constexpr int64_t SCITT_URL = 5; // tstr
    inline constexpr int64_t TXID = 6; // tstr, e.g. "2.14"
    inline constexpr int64_t TIMESTAMP = 7; // uint, seconds since the epoch
  }

  inline constexpr size_t ENTRY_COUNT = 7;

  // Decode limits. A bundle arrives from an untrusted source, so every
  // decoded item is bounded before it is copied out.
  inline constexpr size_t MAX_STATEMENT_BYTES = 4U * 1024U * 1024U;
  inline constexpr size_t MAX_DISCLOSURES = 4096;
  inline constexpr size_t MAX_DISCLOSURE_BYTES = 256U * 1024U;
  inline constexpr size_t MAX_URL_CHARS = 2048;
  inline constexpr size_t MAX_TXID_CHARS = 128;

  struct ProofBundle
  {
    int64_t version = VERSION;
    std::vector<uint8_t> registered_statement;
    std::vector<uint8_t> transparent_statement;
    std::vector<std::vector<uint8_t>> disclosures;
    std::string scitt_url;
    std::string txid;
    int64_t timestamp = 0;
  };

  // Encode a bundle. The statement and disclosure bytes are carried verbatim.
  // Throws std::invalid_argument if a field is empty, oversized or the version
  // is not VERSION.
  std::vector<uint8_t> encode(const ProofBundle& bundle);

  // Decode and strictly validate a bundle: it must be a CBOR map with exactly
  // ENTRY_COUNT entries, no duplicate and no unknown labels, each of the
  // expected type, within the size limits above, and of a supported version.
  //
  // Throws std::invalid_argument (structure, type, size or version) or
  // std::runtime_error (malformed CBOR).
  ProofBundle decode(std::span<const uint8_t> encoded);
}
