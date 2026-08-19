// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/bundle.h"

#include "core/cbor_value.h"
#include "tests/core/test_support.h"

#include <ccf/_private/crypto/cbor.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

using namespace scitt_sd;
using namespace scitt_sd::testing;

namespace
{
  namespace cbor = ccf::cbor;

  bundle::ProofBundle sample_bundle()
  {
    bundle::ProofBundle out;
    out.version = bundle::VERSION;
    out.registered_statement = {0xD2, 0x84, 0x40};
    out.transparent_statement = {0xD2, 0x84, 0x41, 0x00};
    out.disclosures = {{0x81, 0x40}, {0x82, 0x40, 0x40}};
    out.scitt_url = "https://transparency.example";
    out.txid = "2.14";
    out.timestamp = 1700000000;
    return out;
  }

  // Build a bundle map from raw entries, so a test can express shapes encode()
  // would never produce.
  std::vector<uint8_t> raw_bundle(std::vector<cbor::MapItem> items)
  {
    return cbor::serialize(cbor::make_map(std::move(items)));
  }

  std::vector<cbor::MapItem> valid_items(const bundle::ProofBundle& source)
  {
    std::vector<cbor::Value> disclosures;
    for (const auto& disclosure : source.disclosures)
    {
      disclosures.push_back(sdcwt::bytes_value(disclosure));
    }
    return {
      {cbor::make_signed(bundle::label::VERSION),
       cbor::make_signed(source.version)},
      {cbor::make_signed(bundle::label::REGISTERED_STATEMENT),
       sdcwt::bytes_value(source.registered_statement)},
      {cbor::make_signed(bundle::label::TRANSPARENT_STATEMENT),
       sdcwt::bytes_value(source.transparent_statement)},
      {cbor::make_signed(bundle::label::DISCLOSURES),
       cbor::make_array(std::move(disclosures))},
      {cbor::make_signed(bundle::label::SCITT_URL),
       cbor::make_string(source.scitt_url)},
      {cbor::make_signed(bundle::label::TXID), cbor::make_string(source.txid)},
      {cbor::make_signed(bundle::label::TIMESTAMP),
       cbor::make_signed(source.timestamp)}};
  }

  TEST(Bundle, RoundTripsExactly)
  {
    const auto original = sample_bundle();
    const auto decoded = bundle::decode(bundle::encode(original));

    EXPECT_EQ(decoded.version, original.version);
    EXPECT_EQ(decoded.registered_statement, original.registered_statement);
    EXPECT_EQ(decoded.transparent_statement, original.transparent_statement);
    EXPECT_EQ(decoded.disclosures, original.disclosures);
    EXPECT_EQ(decoded.scitt_url, original.scitt_url);
    EXPECT_EQ(decoded.txid, original.txid);
    EXPECT_EQ(decoded.timestamp, original.timestamp);
  }

  TEST(Bundle, EmptyDisclosureListIsLegal)
  {
    auto original = sample_bundle();
    original.disclosures.clear();
    EXPECT_TRUE(bundle::decode(bundle::encode(original)).disclosures.empty());
  }

  TEST(Bundle, EncodeRejectsIncompleteBundles)
  {
    auto missing_statement = sample_bundle();
    missing_statement.registered_statement.clear();
    EXPECT_THROW(bundle::encode(missing_statement), std::invalid_argument);

    auto missing_url = sample_bundle();
    missing_url.scitt_url.clear();
    EXPECT_THROW(bundle::encode(missing_url), std::invalid_argument);

    auto missing_txid = sample_bundle();
    missing_txid.txid.clear();
    EXPECT_THROW(bundle::encode(missing_txid), std::invalid_argument);

    auto bad_version = sample_bundle();
    bad_version.version = bundle::VERSION + 1;
    EXPECT_THROW(bundle::encode(bad_version), std::invalid_argument);

    auto negative_time = sample_bundle();
    negative_time.timestamp = -1;
    EXPECT_THROW(bundle::encode(negative_time), std::invalid_argument);

    auto empty_disclosure = sample_bundle();
    empty_disclosure.disclosures.emplace_back();
    EXPECT_THROW(bundle::encode(empty_disclosure), std::invalid_argument);
  }

  TEST(Bundle, DecodeRejectsMalformedCbor)
  {
    const std::vector<uint8_t> garbage = {0xFF, 0xFF, 0xFF};
    EXPECT_THROW(bundle::decode(garbage), std::runtime_error);
    // A well-formed non-map is still not a bundle.
    EXPECT_THROW(
      bundle::decode(cbor::serialize(cbor::make_signed(1))),
      std::invalid_argument);
  }

  TEST(Bundle, DecodeRejectsAnUnknownLabel)
  {
    auto items = valid_items(sample_bundle());
    items.pop_back();
    items.emplace_back(cbor::make_signed(99), cbor::make_signed(0));
    EXPECT_THROW(
      bundle::decode(raw_bundle(std::move(items))), std::invalid_argument);
  }

  // A duplicate label would otherwise let a sender show one value to a parser
  // that takes the first match and another to one that takes the last.
  // ccf::cbor's encoder refuses to emit a map with a repeated key, so the map
  // header (one byte for seven pairs) is written directly here while every key
  // and value is still encoded by ccf::cbor. ccf::cbor's parser then rejects
  // the repeated key outright; decode()'s own per-label duplicate check stays
  // as defence in depth, so the layer that rejects it is not asserted.
  TEST(Bundle, DecodeRejectsADuplicateLabel)
  {
    auto items = valid_items(sample_bundle());
    items.back().first = cbor::make_signed(bundle::label::TXID);

    std::vector<uint8_t> raw{0xA7};
    for (const auto& [key, value] : items)
    {
      const auto key_bytes = cbor::serialize(key);
      raw.insert(raw.end(), key_bytes.begin(), key_bytes.end());
      const auto value_bytes = cbor::serialize(value);
      raw.insert(raw.end(), value_bytes.begin(), value_bytes.end());
    }

    try
    {
      (void)bundle::decode(raw);
      FAIL() << "a bundle with a duplicate label was accepted";
    }
    catch (const std::exception& e)
    {
      EXPECT_NE(std::string(e.what()).find("proof bundle"), std::string::npos)
        << e.what();
    }
  }

  TEST(Bundle, DecodeRejectsAWrongEntryCount)
  {
    auto too_few = valid_items(sample_bundle());
    too_few.pop_back();
    EXPECT_THROW(
      bundle::decode(raw_bundle(std::move(too_few))), std::invalid_argument);

    auto too_many = valid_items(sample_bundle());
    too_many.emplace_back(cbor::make_signed(8), cbor::make_signed(0));
    EXPECT_THROW(
      bundle::decode(raw_bundle(std::move(too_many))), std::invalid_argument);
  }

  TEST(Bundle, DecodeRejectsWrongTypes)
  {
    const auto source = sample_bundle();

    const auto replace = [&source](int64_t target, cbor::Value value) {
      auto items = valid_items(source);
      for (auto& item : items)
      {
        if (item.first->as_signed() == target)
        {
          item.second = std::move(value);
          break;
        }
      }
      return raw_bundle(std::move(items));
    };

    EXPECT_THROW(
      bundle::decode(replace(
        bundle::label::REGISTERED_STATEMENT, cbor::make_string("nope"))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(
        replace(bundle::label::TRANSPARENT_STATEMENT, cbor::make_signed(1))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(
        replace(bundle::label::DISCLOSURES, cbor::make_string("nope"))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(replace(
        bundle::label::DISCLOSURES,
        cbor::make_array({cbor::make_string("nope")}))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(replace(bundle::label::SCITT_URL, cbor::make_signed(1))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(replace(bundle::label::TXID, cbor::make_signed(1))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(
        replace(bundle::label::TIMESTAMP, cbor::make_string("now"))),
      std::invalid_argument);
    EXPECT_THROW(
      bundle::decode(replace(bundle::label::TIMESTAMP, cbor::make_signed(-1))),
      std::invalid_argument);
    // A text key is not an integer label, so the map is incomplete.
    auto text_key = valid_items(source);
    text_key.pop_back();
    text_key.emplace_back(cbor::make_string("timestamp"), cbor::make_signed(0));
    EXPECT_THROW(
      bundle::decode(raw_bundle(std::move(text_key))), std::invalid_argument);
  }

  TEST(Bundle, DecodeRejectsAnUnsupportedVersion)
  {
    auto source = sample_bundle();
    source.version = 2;
    auto items = valid_items(source);
    EXPECT_THROW(
      bundle::decode(raw_bundle(std::move(items))), std::invalid_argument);

    source.version = 0;
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);
  }

  // Every decoded item is bounded before it is copied out, because a bundle
  // arrives from an untrusted source.
  TEST(Bundle, DecodeEnforcesSizeLimits)
  {
    auto source = sample_bundle();
    source.registered_statement.assign(bundle::MAX_STATEMENT_BYTES + 1, 0x01);
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);

    source = sample_bundle();
    source.disclosures.assign(
      1, std::vector<uint8_t>(bundle::MAX_DISCLOSURE_BYTES + 1, 0x01));
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);

    source = sample_bundle();
    source.scitt_url.assign(bundle::MAX_URL_CHARS + 1, 'a');
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);

    source = sample_bundle();
    source.txid.assign(bundle::MAX_TXID_CHARS + 1, 'a');
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);

    source = sample_bundle();
    source.disclosures.assign(
      bundle::MAX_DISCLOSURES + 1, std::vector<uint8_t>{0x40});
    EXPECT_THROW(
      bundle::decode(raw_bundle(valid_items(source))), std::invalid_argument);
  }

  // Statement bytes are carried verbatim: a bundle must not re-encode what it
  // transports, or the receipt would no longer cover it.
  TEST(Bundle, StatementBytesAreCarriedVerbatim)
  {
    const auto scenario = make_eku_scenario();
    const auto encoded = bundle::encode(scenario.proof);
    const auto decoded = bundle::decode(encoded);

    EXPECT_EQ(decoded.registered_statement, scenario.issued.statement);
    EXPECT_EQ(
      decoded.transparent_statement, scenario.proof.transparent_statement);
    EXPECT_TRUE(contains(encoded, scenario.issued.statement));
  }
}
