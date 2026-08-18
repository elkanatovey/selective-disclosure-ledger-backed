// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/cbor_value.h"

#include "tests/core/test_support.h"

#include <gtest/gtest.h>

using namespace scitt_sd::testing;

namespace
{
  // CDE (RFC 8949 section 4.2) map-key ordering is load-bearing: ccf::cbor
  // preserves insertion order rather than sorting, so cbor_value.cpp owns the
  // sort, and every party has to agree on the bytes.
  TEST(CborValue, CdeOrdersMapKeysAndPutsSimple59Last)
  {
    auto map = sdcwt::CborValue::Map(
      {{std::string("zz"), sdcwt::value::integer(1)},
       {int64_t{1002}, sdcwt::value::integer(2)},
       {std::string("a"), sdcwt::value::integer(3)},
       {int64_t{1}, sdcwt::value::integer(4)}});
    map.redacted_hashes.push_back({0x01});

    const auto encoded = sdcwt::encode_value(map);
    // {1: 4, 1002: 2, "a": 3, "zz": 1, simple(59): [h'01']}
    EXPECT_EQ(to_hex(encoded), "a501041903ea02616103627a7a01f83b814101");
  }

  // The redacted-claim-keys entry must sort last, which only holds because
  // every integer and text key encodes below 0xf8 (simple(59)).
  TEST(CborValue, RedactedHashesAreEmittedLastUnderSimple59)
  {
    auto map = sdcwt::CborValue::Map({{int64_t{1}, sdcwt::value::integer(0)}});
    map.redacted_hashes.push_back({0x01, 0x01});
    map.redacted_hashes.push_back({0x02, 0x02});

    const auto encoded = sdcwt::encode_value(map);
    EXPECT_EQ(to_hex(encoded), "a20100f83b82420101420202");
  }

  // A redacted array element is a tag(60) wrapping its Redacted Claim Hash.
  TEST(CborValue, RedactedElementIsTag60)
  {
    const auto array = sdcwt::CborValue::Array(
      {sdcwt::value::text("kept"), sdcwt::CborValue::RedactedElem({0xAB})});
    const auto encoded = sdcwt::encode_value(array);
    EXPECT_EQ(to_hex(encoded), "82646b657074d83c41ab");
  }

  // make_bytes rejects a null data pointer, so an empty byte string needs the
  // bytes_value() anchor rather than an empty vector's data().
  TEST(CborValue, EmptyByteStringEncodes)
  {
    const std::vector<uint8_t> empty;
    EXPECT_EQ(to_hex(ccf::cbor::serialize(sdcwt::bytes_value(empty))), "40");
    EXPECT_EQ(to_hex(sdcwt::encode_value(sdcwt::value::bytes(empty))), "40");
  }

  TEST(CborValue, TextArrayRoundTrips)
  {
    const auto value = sdcwt::value::text_array({"a", "bb"});
    EXPECT_EQ(to_hex(sdcwt::encode_value(value)), "826161626262");
  }

  // ccf::cbor holds integers as int64_t, so negative claim labels are exact.
  TEST(CborValue, NegativeIntegersEncode)
  {
    EXPECT_EQ(to_hex(sdcwt::encode_value(sdcwt::value::integer(-16))), "2f");
    EXPECT_EQ(to_hex(sdcwt::encode_value(sdcwt::value::integer(-44))), "382b");
  }
}
