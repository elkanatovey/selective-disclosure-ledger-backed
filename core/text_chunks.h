// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace scitt_sd::text
{
  // Number of Unicode code points per selectively-disclosable text chunk.
  // Chunking is deliberately fine-grained so a presenter can reveal a short
  // span of a report body without revealing the rest.
  inline constexpr size_t TEXT_CHUNK_SIZE = 6;

  // Strict UTF-8 validation. Rejects continuation bytes in a lead position,
  // truncated sequences, invalid continuation bytes, overlong encodings,
  // UTF-16 surrogate code points (U+D800..U+DFFF) and anything above
  // U+10FFFF. Throws std::invalid_argument naming the offending byte offset.
  void validate_utf8(std::string_view utf8);

  // Number of Unicode code points in a UTF-8 string (NOT the byte count).
  // Throws std::invalid_argument for malformed UTF-8.
  size_t count_code_points(std::string_view utf8);

  // Split a UTF-8 string into consecutive chunks of at most `chunk_size`
  // Unicode code points, never splitting a code point. Chunk boundaries are
  // code-point boundaries, not byte or grapheme-cluster boundaries, so a
  // combining sequence may straddle two chunks; this is safe because a
  // verifier only ever reassembles chunks in index order.
  //
  // An empty input yields a single empty chunk, so that an empty text field
  // still has exactly one disclosable chunk.
  //
  // Throws std::invalid_argument for malformed UTF-8 or a zero chunk_size.
  std::vector<std::string> chunk_text(
    std::string_view utf8, size_t chunk_size = TEXT_CHUNK_SIZE);
}
