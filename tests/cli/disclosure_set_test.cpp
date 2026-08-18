// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The disclosure set is the tool's own artifact: it is what lets a holder
// build a bundle without re-deriving which byte string discloses what. It
// carries disclosure bytes verbatim and refuses anything it cannot read back
// exactly, so both properties are pinned here.

#include "cli/disclosure_set.h"

#include "core/cbor_value.h"

#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

using namespace scitt_sd::cli;
using sdcwt::CborValue;

namespace
{
  std::vector<uint8_t> bytes(std::initializer_list<int> values)
  {
    std::vector<uint8_t> out;
    out.reserve(values.size());
    for (const auto value : values)
    {
      out.push_back(static_cast<uint8_t>(value));
    }
    return out;
  }

  std::vector<disclosure_set::Entry> sample_entries()
  {
    return {
      {{int64_t{1001}}, bytes({0x83, 0x41, 0x00, 0x01, 0x02})},
      {{int64_t{1002}, int64_t{3}}, bytes({0x83, 0x41, 0x01, 0x03, 0x04})},
      {{std::string("named")}, bytes({0x83, 0x41, 0x02, 0x05, 0x06})}};
  }
}

TEST(DisclosureSet, RoundTripsPathsAndBytes)
{
  const auto entries = sample_entries();
  const auto decoded = disclosure_set::decode(disclosure_set::encode(entries));

  ASSERT_EQ(decoded.size(), entries.size());
  for (size_t i = 0; i < entries.size(); ++i)
  {
    EXPECT_EQ(decoded.at(i).path, entries.at(i).path) << "entry " << i;
    EXPECT_EQ(decoded.at(i).encoded, entries.at(i).encoded) << "entry " << i;
  }
}

TEST(DisclosureSet, CarriesDisclosureBytesVerbatim)
{
  // The statement commits to these exact bytes: re-encoding them would break
  // the commitment, so they must survive a round trip unchanged.
  const std::vector<disclosure_set::Entry> entries = {
    {{int64_t{1001}}, bytes({0xD9, 0x01, 0x02, 0x83, 0x41, 0xFF, 0x00})}};
  const auto decoded = disclosure_set::decode(disclosure_set::encode(entries));
  ASSERT_EQ(decoded.size(), 1U);
  EXPECT_EQ(decoded.at(0).encoded, entries.at(0).encoded);
}

TEST(DisclosureSet, RoundTripsAnEmptySet)
{
  const auto decoded = disclosure_set::decode(disclosure_set::encode({}));
  EXPECT_TRUE(decoded.empty());
}

TEST(DisclosureSet, RefusesAnEmptyDisclosure)
{
  const std::vector<disclosure_set::Entry> entries = {{{int64_t{1}}, {}}};
  EXPECT_THROW((void)disclosure_set::encode(entries), std::invalid_argument);
}

TEST(DisclosureSet, RefusesAnEmptyPath)
{
  const std::vector<disclosure_set::Entry> entries = {{{}, bytes({0x01})}};
  EXPECT_THROW((void)disclosure_set::encode(entries), std::invalid_argument);
}

TEST(DisclosureSet, RefusesAnOverDeepPath)
{
  sdcwt::Path path;
  for (size_t i = 0; i <= disclosure_set::MAX_PATH_DEPTH; ++i)
  {
    path.emplace_back(static_cast<int64_t>(i));
  }
  const std::vector<disclosure_set::Entry> entries = {{path, bytes({0x01})}};
  EXPECT_THROW((void)disclosure_set::encode(entries), std::invalid_argument);
}

TEST(DisclosureSet, RefusesAnEmptyPathElement)
{
  const std::vector<disclosure_set::Entry> entries = {
    {{std::string()}, bytes({0x01})}};
  EXPECT_THROW((void)disclosure_set::encode(entries), std::invalid_argument);
}

TEST(DisclosureSet, RefusesMalformedCbor)
{
  EXPECT_THROW(
    (void)disclosure_set::decode(bytes({0xA1, 0x01})), std::runtime_error);
}

TEST(DisclosureSet, RefusesANonMap)
{
  // An array, not a map.
  EXPECT_THROW(
    (void)disclosure_set::decode(bytes({0x82, 0x01, 0x02})),
    std::invalid_argument);
}

TEST(DisclosureSet, RefusesAnUnsupportedVersion)
{
  const auto encoded = sdcwt::encode_value(CborValue::Map(
    {{disclosure_set::label::VERSION, CborValue::Int(99)},
     {disclosure_set::label::DISCLOSURES, CborValue::Array({})}}));
  EXPECT_THROW((void)disclosure_set::decode(encoded), std::invalid_argument);
}

TEST(DisclosureSet, RefusesAMissingLabel)
{
  const auto encoded = sdcwt::encode_value(CborValue::Map(
    {{disclosure_set::label::VERSION, CborValue::Int(disclosure_set::VERSION)},
     {99, CborValue::Array({})}}));
  EXPECT_THROW((void)disclosure_set::decode(encoded), std::invalid_argument);
}

TEST(DisclosureSet, RefusesAnEntryOfTheWrongType)
{
  const auto encoded = sdcwt::encode_value(CborValue::Map(
    {{disclosure_set::label::VERSION, CborValue::Int(disclosure_set::VERSION)},
     {disclosure_set::label::DISCLOSURES, CborValue::Int(0)}}));
  EXPECT_THROW((void)disclosure_set::decode(encoded), std::invalid_argument);
}

TEST(DisclosureSet, RefusesADisclosureThatIsNotAByteString)
{
  const auto encoded = sdcwt::encode_value(CborValue::Map(
    {{disclosure_set::label::VERSION, CborValue::Int(disclosure_set::VERSION)},
     {disclosure_set::label::DISCLOSURES,
      CborValue::Array({CborValue::Map(
        {{disclosure_set::label::PATH,
          CborValue::Array({CborValue::Int(1001)})},
         {disclosure_set::label::ENCODED, CborValue::Text("not bytes")}})})}}));
  EXPECT_THROW((void)disclosure_set::decode(encoded), std::invalid_argument);
}

TEST(DisclosureSet, RefusesTrailingBytes)
{
  auto encoded = disclosure_set::encode(sample_entries());
  encoded.push_back(0x00);
  EXPECT_ANY_THROW((void)disclosure_set::decode(encoded));
}
