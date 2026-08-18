// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/text_chunks.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <stdexcept>
#include <string>

namespace
{
  using namespace scitt_sd::text;

  // Build a string from raw bytes, so malformed sequences can be expressed
  // without relying on escape parsing.
  std::string raw(std::initializer_list<uint8_t> bytes)
  {
    std::string out;
    for (const auto byte : bytes)
    {
      out.push_back(static_cast<char>(byte));
    }
    return out;
  }

  TEST(TextChunks, ChunkSizeIsSixCodePoints)
  {
    EXPECT_EQ(TEXT_CHUNK_SIZE, 6U);
  }

  TEST(TextChunks, AsciiSplitsEverySixCodePoints)
  {
    const auto chunks = chunk_text("abcdefghijklm");
    ASSERT_EQ(chunks.size(), 3U);
    EXPECT_EQ(chunks[0], "abcdef");
    EXPECT_EQ(chunks[1], "ghijkl");
    EXPECT_EQ(chunks[2], "m");
    EXPECT_EQ(chunks[0] + chunks[1] + chunks[2], "abcdefghijklm");
  }

  // Chunks are counted in code points, never in bytes: a chunk of six
  // multi-byte code points is longer than six bytes and no code point is ever
  // split across a boundary.
  TEST(TextChunks, MultiByteCodePointsAreNotSplit)
  {
    // e-acute (2 bytes), euro sign (3 bytes), grinning face (4 bytes).
    const std::string text =
      "\u00e9\u20ac\U0001F600\u00e9\u20ac\U0001F600" // 6 code points
      "\u00e9\u20ac\U0001F600"; // 3 more
    ASSERT_EQ(count_code_points(text), 9U);

    const auto chunks = chunk_text(text);
    ASSERT_EQ(chunks.size(), 2U);
    EXPECT_EQ(count_code_points(chunks[0]), 6U);
    EXPECT_EQ(count_code_points(chunks[1]), 3U);
    EXPECT_EQ(chunks[0].size(), 18U); // 2 + 3 + 4, twice
    EXPECT_EQ(chunks[1].size(), 9U);
    EXPECT_EQ(chunks[0] + chunks[1], text);
    EXPECT_NO_THROW(validate_utf8(chunks[0]));
    EXPECT_NO_THROW(validate_utf8(chunks[1]));
  }

  TEST(TextChunks, ExactMultipleProducesNoEmptyTail)
  {
    const auto chunks = chunk_text("abcdefghijkl");
    ASSERT_EQ(chunks.size(), 2U);
    EXPECT_EQ(chunks[1], "ghijkl");
  }

  // An empty field still has exactly one disclosable chunk, so "the body is
  // empty" is itself something a presenter can prove.
  TEST(TextChunks, EmptyInputYieldsOneEmptyChunk)
  {
    const auto chunks = chunk_text("");
    ASSERT_EQ(chunks.size(), 1U);
    EXPECT_TRUE(chunks[0].empty());
    EXPECT_EQ(count_code_points(""), 0U);
  }

  TEST(TextChunks, ZeroChunkSizeRejected)
  {
    EXPECT_THROW(chunk_text("abc", 0), std::invalid_argument);
  }

  TEST(TextChunks, ValidUtf8Accepted)
  {
    EXPECT_NO_THROW(validate_utf8(""));
    EXPECT_NO_THROW(validate_utf8("plain ASCII"));
    EXPECT_NO_THROW(validate_utf8(raw({0x00, 0x7F}))); // NUL and DEL
    EXPECT_NO_THROW(validate_utf8(raw({0xC2, 0x80}))); // U+0080, shortest form
    EXPECT_NO_THROW(validate_utf8(raw({0xE0, 0xA0, 0x80}))); // U+0800
    EXPECT_NO_THROW(validate_utf8(raw({0xED, 0x9F, 0xBF}))); // U+D7FF
    EXPECT_NO_THROW(validate_utf8(raw({0xEE, 0x80, 0x80}))); // U+E000
    EXPECT_NO_THROW(validate_utf8(raw({0xF4, 0x8F, 0xBF, 0xBF}))); // U+10FFFF
  }

  TEST(TextChunks, ContinuationByteInLeadPositionRejected)
  {
    EXPECT_THROW(validate_utf8(raw({0x80})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xBF})), std::invalid_argument);
  }

  TEST(TextChunks, TruncatedSequenceRejected)
  {
    EXPECT_THROW(validate_utf8(raw({0xC2})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xE2, 0x82})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xF0, 0x9F, 0x98})), std::invalid_argument);
  }

  TEST(TextChunks, InvalidContinuationByteRejected)
  {
    EXPECT_THROW(validate_utf8(raw({0xE2, 0x82, 0x41})), std::invalid_argument);
    EXPECT_THROW(
      validate_utf8(raw({0xF0, 0x9F, 0x98, 0x41})), std::invalid_argument);
  }

  // Overlong encodings are a classic filter bypass: the same code point with a
  // longer, non-canonical encoding.
  TEST(TextChunks, OverlongEncodingRejected)
  {
    EXPECT_THROW(validate_utf8(raw({0xC0, 0xAF})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xC1, 0xBF})), std::invalid_argument);
    EXPECT_THROW(
      validate_utf8(raw({0xE0, 0x9F, 0xBF})), std::invalid_argument); // U+07FF
    EXPECT_THROW(
      validate_utf8(raw({0xF0, 0x8F, 0xBF, 0xBF})),
      std::invalid_argument); // U+FFFF
  }

  TEST(TextChunks, SurrogatesRejected)
  {
    EXPECT_THROW(
      validate_utf8(raw({0xED, 0xA0, 0x80})), std::invalid_argument); // U+D800
    EXPECT_THROW(
      validate_utf8(raw({0xED, 0xBF, 0xBF})), std::invalid_argument); // U+DFFF
  }

  TEST(TextChunks, AboveMaxCodePointRejected)
  {
    EXPECT_THROW(
      validate_utf8(raw({0xF4, 0x90, 0x80, 0x80})),
      std::invalid_argument); // U+110000
    EXPECT_THROW(
      validate_utf8(raw({0xF5, 0x80, 0x80, 0x80})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xFE})), std::invalid_argument);
    EXPECT_THROW(validate_utf8(raw({0xFF})), std::invalid_argument);
  }

  TEST(TextChunks, MalformedInputIsRejectedByEveryEntryPoint)
  {
    const auto bad = raw({0x41, 0xC3, 0x28});
    EXPECT_THROW(validate_utf8(bad), std::invalid_argument);
    EXPECT_THROW(count_code_points(bad), std::invalid_argument);
    EXPECT_THROW(chunk_text(bad), std::invalid_argument);
  }

  TEST(TextChunks, ErrorNamesTheOffendingOffset)
  {
    try
    {
      validate_utf8(raw({0x41, 0x42, 0x80}));
      FAIL() << "expected a rejection";
    }
    catch (const std::invalid_argument& e)
    {
      EXPECT_NE(std::string(e.what()).find("offset 2"), std::string::npos);
    }
  }
}
