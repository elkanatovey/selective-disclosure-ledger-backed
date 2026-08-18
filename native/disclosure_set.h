// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/sd_cwt.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace scitt_sd::cli
{
  // The disclosure set an issuer hands to the holder alongside the registered
  // statement: every disclosure the statement commits to, each with the path
  // that says what it discloses.
  //
  // This is a private artifact of this tool, not a wire format: it is what
  // lets a holder build a bundle without having to re-derive which byte string
  // is the title and which is body chunk 7. It is versioned so that an older
  // file is refused rather than misread, and encoded as a CBOR map with
  // integer labels using ccf::cbor, like every other artifact here.
  //
  //   {1: version, 2: [{1: [path element, ...], 2: encoded disclosure}, ...]}
  //
  // The disclosure bytes are carried verbatim: they are what the statement
  // commits to, so re-encoding them would break the commitment.
  namespace disclosure_set
  {
    inline constexpr int64_t VERSION = 1;

    namespace label
    {
      inline constexpr int64_t VERSION = 1; // uint
      inline constexpr int64_t DISCLOSURES = 2; // [* entry]
      inline constexpr int64_t PATH = 1; // [* (int / tstr)]
      inline constexpr int64_t ENCODED = 2; // bstr, verbatim
    }

    inline constexpr size_t ENTRY_COUNT = 2;
    inline constexpr size_t ITEM_ENTRY_COUNT = 2;

    // Decode limits, matching the bundle the disclosures end up in.
    inline constexpr size_t MAX_DISCLOSURES = 4096;
    inline constexpr size_t MAX_DISCLOSURE_BYTES = 256U * 1024U;
    inline constexpr size_t MAX_PATH_DEPTH = 8;
    inline constexpr size_t MAX_PATH_ELEMENT_CHARS = 256;

    struct Entry
    {
      sdcwt::Path path;
      std::vector<uint8_t> encoded;
    };

    // Throws std::invalid_argument if there are too many entries, an entry is
    // empty or oversized, or a path is empty or too deep.
    std::vector<uint8_t> encode(const std::vector<Entry>& entries);

    // Decode and strictly validate a disclosure set: exactly the expected
    // entries, no duplicate and no unknown labels, each of the expected type
    // and within the size limits, and of a supported version.
    //
    // Throws std::invalid_argument (structure, type, size or version) or
    // std::runtime_error (malformed CBOR).
    std::vector<Entry> decode(std::span<const uint8_t> encoded);
  }
}
