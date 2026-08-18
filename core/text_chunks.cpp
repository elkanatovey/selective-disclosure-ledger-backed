// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/text_chunks.h"

#include <cstdint>
#include <stdexcept>

namespace scitt_sd::text
{
  namespace
  {
    [[noreturn]] void reject(size_t offset, const char* why)
    {
      throw std::invalid_argument(
        "malformed UTF-8 at byte offset " + std::to_string(offset) + ": " +
        why);
    }

    uint8_t byte_at(std::string_view utf8, size_t index)
    {
      return static_cast<uint8_t>(utf8[index]);
    }

    bool is_continuation(uint8_t byte)
    {
      return (byte & 0xC0U) == 0x80U;
    }

    // Length in bytes of the well-formed UTF-8 sequence starting at `offset`.
    // Implements the Unicode 15 well-formed byte-sequence table (D92): the
    // second-byte range is narrowed per lead byte so overlong encodings,
    // surrogates and out-of-range code points are all rejected here rather
    // than after decoding.
    size_t code_point_length(std::string_view utf8, size_t offset)
    {
      const uint8_t lead = byte_at(utf8, offset);

      size_t length = 0;
      uint8_t min_second = 0x80;
      uint8_t max_second = 0xBF;

      if (lead <= 0x7FU)
      {
        return 1;
      }
      if (lead <= 0xBFU)
      {
        reject(offset, "continuation byte in lead position");
      }
      else if (lead <= 0xC1U)
      {
        reject(offset, "overlong two-byte sequence");
      }
      else if (lead <= 0xDFU)
      {
        length = 2;
      }
      else if (lead <= 0xEFU)
      {
        length = 3;
        if (lead == 0xE0U)
        {
          min_second = 0xA0; // reject overlong three-byte sequences
        }
        else if (lead == 0xEDU)
        {
          max_second = 0x9F; // reject UTF-16 surrogates U+D800..U+DFFF
        }
      }
      else if (lead <= 0xF4U)
      {
        length = 4;
        if (lead == 0xF0U)
        {
          min_second = 0x90; // reject overlong four-byte sequences
        }
        else if (lead == 0xF4U)
        {
          max_second = 0x8F; // reject code points above U+10FFFF
        }
      }
      else
      {
        reject(offset, "lead byte above U+10FFFF range");
      }

      if (offset + length > utf8.size())
      {
        reject(offset, "truncated multi-byte sequence");
      }

      const uint8_t second = byte_at(utf8, offset + 1);
      if (second < min_second || second > max_second)
      {
        reject(offset + 1, "invalid second byte for this lead byte");
      }
      for (size_t i = 2; i < length; ++i)
      {
        if (!is_continuation(byte_at(utf8, offset + i)))
        {
          reject(offset + i, "invalid continuation byte");
        }
      }
      return length;
    }
  }

  void validate_utf8(std::string_view utf8)
  {
    size_t offset = 0;
    while (offset < utf8.size())
    {
      offset += code_point_length(utf8, offset);
    }
  }

  size_t count_code_points(std::string_view utf8)
  {
    size_t offset = 0;
    size_t count = 0;
    while (offset < utf8.size())
    {
      offset += code_point_length(utf8, offset);
      ++count;
    }
    return count;
  }

  std::vector<std::string> chunk_text(std::string_view utf8, size_t chunk_size)
  {
    if (chunk_size == 0)
    {
      throw std::invalid_argument("chunk_size must be non-zero");
    }

    std::vector<std::string> chunks;
    size_t offset = 0;
    while (offset < utf8.size())
    {
      const size_t start = offset;
      for (size_t taken = 0; taken < chunk_size && offset < utf8.size();
           ++taken)
      {
        offset += code_point_length(utf8, offset);
      }
      chunks.emplace_back(utf8.substr(start, offset - start));
    }
    if (chunks.empty())
    {
      chunks.emplace_back();
    }
    return chunks;
  }
}
