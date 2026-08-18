// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/sd_cwt.h"

#include "core/sd_cwt_internal.h"
#include "tests/core/test_support.h"

#include <gtest/gtest.h>
#include <set>
#include <stdexcept>

using namespace scitt_sd::testing;

namespace
{
  ccf::crypto::ECKeyPairPtr test_key()
  {
    return ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  }

  // The Redacted Claim Hash rule: sd_alg over `bstr .cbor salted-entry`. This
  // vector (salt 0x00..0f, value "heap overflow", key 1002) is the one the
  // prototype pinned against its Python reference implementation.
  TEST(SdCwt, DisclosureDigestIsPinned)
  {
    std::vector<uint8_t> salt(sdcwt::SALT_LEN);
    for (uint8_t i = 0; i < sdcwt::SALT_LEN; ++i)
    {
      salt[i] = i;
    }

    const auto value = sdcwt::value::text("heap overflow");
    const auto encoded = ccf::cbor::serialize(ccf::cbor::make_array(
      {ccf::cbor::make_bytes(salt),
       sdcwt::to_ccf_cbor(value),
       ccf::cbor::make_signed(1002)}));

    EXPECT_EQ(
      to_hex(encoded),
      "8350000102030405060708090a0b0c0d0e0f6d68656170206f766572666c6f771903ea");
    EXPECT_EQ(
      to_hex(sdcwt::disclosure_digest(encoded)),
      "dc679dce1b7b429c355edbdcf54c9c576485026c84962a93a1dac9b55def2818");
  }

  TEST(SdCwt, RedactedClaimIsHiddenAndDisclosed)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://issuer.example")},
      {1002, sdcwt::value::text("secret body")}};

    const auto issued = sdcwt::issue(claims, {{int64_t{1002}}}, *key);

    EXPECT_FALSE(contains(issued.token, "secret body"));
    ASSERT_EQ(issued.disclosures.size(), 1U);
    ASSERT_EQ(issued.disclosures[0].path.size(), 1U);
    EXPECT_EQ(std::get<int64_t>(issued.disclosures[0].path[0]), 1002);
    EXPECT_EQ(issued.disclosures[0].salt.size(), sdcwt::SALT_LEN);
    EXPECT_EQ(
      issued.disclosures[0].digest,
      sdcwt::disclosure_digest(issued.disclosures[0].encoded));
    // The unredacted claim is still there in the clear.
    EXPECT_TRUE(contains(issued.token, "https://issuer.example"));
  }

  TEST(SdCwt, RedactionHashAgilitySha384)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("iss")}, {1002, sdcwt::value::text("secret")}};

    const auto issued =
      sdcwt::issue(claims, {{int64_t{1002}}}, *key, sdcwt::HashAlg::SHA_384);

    ASSERT_EQ(issued.disclosures.size(), 1U);
    EXPECT_EQ(issued.disclosures[0].digest.size(), 48U);
    EXPECT_EQ(
      issued.disclosures[0].digest,
      sdcwt::disclosure_digest(
        issued.disclosures[0].encoded, sdcwt::HashAlg::SHA_384));

    const auto expected = sdcwt::encode_sdcwt_protected_header(
      sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_384);
    EXPECT_EQ(parse_sign1(issued.token).protected_header, expected);
  }

  // Salts are drawn per disclosure and never reused, and a decoy consumes one
  // of its own.
  TEST(SdCwt, SaltsAreFullLengthAndNeverReused)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1001, sdcwt::value::text("a")},
      {1002, sdcwt::value::text("b")},
      {1003, sdcwt::value::text("c")}};
    const std::vector<sdcwt::Path> paths = {
      {int64_t{1001}}, {int64_t{1002}}, {int64_t{1003}}};

    const auto issued =
      sdcwt::issue(claims, paths, *key, sdcwt::HashAlg::SHA_256, /*pad_to=*/6);

    ASSERT_EQ(issued.disclosures.size(), 6U);
    std::set<std::vector<uint8_t>> salts;
    for (const auto& disclosure : issued.disclosures)
    {
      EXPECT_EQ(disclosure.salt.size(), sdcwt::SALT_LEN);
      EXPECT_TRUE(salts.insert(disclosure.salt).second) << "salt reused";
    }
  }

  // The injectable randomness source makes issuance reproducible byte for
  // byte, which is what lets these tests pin encodings at all.
  TEST(SdCwt, InjectedRandomSourceIsDeterministic)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {{1002, sdcwt::value::text("secret")}};

    const auto first = sdcwt::detail::issue(
      claims,
      {{int64_t{1002}}},
      *key,
      sdcwt::HashAlg::SHA_256,
      counting_random_source(7));
    const auto second = sdcwt::detail::issue(
      claims,
      {{int64_t{1002}}},
      *key,
      sdcwt::HashAlg::SHA_256,
      counting_random_source(7));

    ASSERT_EQ(first.disclosures.size(), 1U);
    EXPECT_EQ(first.disclosures[0].salt, second.disclosures[0].salt);
    EXPECT_EQ(first.disclosures[0].encoded, second.disclosures[0].encoded);
    EXPECT_EQ(first.disclosures[0].digest, second.disclosures[0].digest);
    // The payload (and so the redacted hash it commits to) is identical; only
    // the ECDSA signature differs, since it is randomised.
    EXPECT_EQ(
      parse_sign1(first.token).payload, parse_sign1(second.token).payload);

    std::vector<uint8_t> expected_salt(sdcwt::SALT_LEN);
    for (size_t i = 0; i < expected_salt.size(); ++i)
    {
      expected_salt[i] = static_cast<uint8_t>(7 + i);
    }
    EXPECT_EQ(first.disclosures[0].salt, expected_salt);
  }

  TEST(SdCwt, DecoyPaddingHidesTheRedactedClaimCount)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("iss")}, {1002, sdcwt::value::text("secret")}};

    const auto issued = sdcwt::issue(
      claims, {{int64_t{1002}}}, *key, sdcwt::HashAlg::SHA_256, /*pad_to=*/4);

    ASSERT_EQ(issued.disclosures.size(), 4U);
    size_t decoys = 0;
    for (const auto& disclosure : issued.disclosures)
    {
      if (disclosure.path.empty())
      {
        ++decoys;
        // A decoy is [salt] only: 1 + 17 bytes.
        EXPECT_EQ(disclosure.encoded.size(), 18U);
      }
    }
    EXPECT_EQ(decoys, 3U);
  }

  TEST(SdCwt, UnmatchedRedactPathRejected)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {{1002, sdcwt::value::text("x")}};
    EXPECT_THROW(
      sdcwt::issue(claims, {{int64_t{9999}}}, *key), std::invalid_argument);
    // Descending into a non-container is equally rejected.
    EXPECT_THROW(
      sdcwt::issue(claims, {{int64_t{1002}, int64_t{0}}}, *key),
      std::invalid_argument);
  }

  TEST(SdCwt, ArrayElementRedaction)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1006, sdcwt::value::text_array({"KEEP", "HIDE"})}};

    const auto issued =
      sdcwt::issue(claims, {{int64_t{1006}, int64_t{1}}}, *key);

    ASSERT_EQ(issued.disclosures.size(), 1U);
    EXPECT_TRUE(contains(issued.token, "KEEP"));
    EXPECT_FALSE(contains(issued.token, "HIDE"));
    // An array-element disclosure is [salt, value]: no key.
    EXPECT_TRUE(contains(issued.disclosures[0].encoded, "HIDE"));
    EXPECT_EQ(issued.disclosures[0].encoded[0], 0x82);
  }

  TEST(SdCwt, NestedMapRedaction)
  {
    const auto key = test_key();
    auto nested = sdcwt::CborValue::Map(
      {{std::string("keep"), sdcwt::value::text("KEEP")},
       {std::string("hide"), sdcwt::value::text("HIDE")}});
    std::vector<sdcwt::Claim> claims = {{700, std::move(nested)}};

    const auto issued =
      sdcwt::issue(claims, {{int64_t{700}, std::string("hide")}}, *key);

    ASSERT_EQ(issued.disclosures.size(), 1U);
    EXPECT_TRUE(contains(issued.token, "KEEP"));
    EXPECT_FALSE(contains(issued.token, "HIDE"));
    // A map-entry disclosure is [salt, value, key].
    EXPECT_EQ(issued.disclosures[0].encoded[0], 0x83);
  }

  // The ancestor-disclosure rule: disclosing a redacted parent must not reveal
  // a child that was redacted within it.
  TEST(SdCwt, NestedAncestorDisclosureKeepsTheChildHidden)
  {
    const auto key = test_key();
    auto grandchild = sdcwt::CborValue::Map(
      {{std::string("b"), sdcwt::value::text("SECRET_CHILD")},
       {std::string("c"), sdcwt::value::text("KEEP_SIBLING")}});
    auto child =
      sdcwt::CborValue::Map({{std::string("a"), std::move(grandchild)}});
    std::vector<sdcwt::Claim> claims = {{700, std::move(child)}};
    const std::vector<sdcwt::Path> paths = {
      {int64_t{700}, std::string("a")},
      {int64_t{700}, std::string("a"), std::string("b")}};

    const auto issued = sdcwt::issue(claims, paths, *key);

    ASSERT_EQ(issued.disclosures.size(), 2U);
    EXPECT_FALSE(contains(issued.token, "SECRET_CHILD"));
    EXPECT_FALSE(contains(issued.token, "KEEP_SIBLING"));

    const sdcwt::Disclosure* parent = nullptr;
    for (const auto& disclosure : issued.disclosures)
    {
      if (disclosure.path.size() == 2)
      {
        parent = &disclosure;
      }
    }
    ASSERT_NE(parent, nullptr);
    EXPECT_TRUE(contains(parent->encoded, "KEEP_SIBLING"));
    EXPECT_FALSE(contains(parent->encoded, "SECRET_CHILD"));
  }

  TEST(SdCwt, PresentAttachesAndReplacesDisclosures)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {
      {1001, sdcwt::value::text("first")},
      {1002, sdcwt::value::text("second")}};
    const auto issued =
      sdcwt::issue(claims, {{int64_t{1001}}, {int64_t{1002}}}, *key);
    ASSERT_EQ(issued.disclosures.size(), 2U);

    const auto& one = issued.disclosures[0].encoded;
    const auto& two = issued.disclosures[1].encoded;

    EXPECT_FALSE(contains(issued.token, one));
    const auto presented = sdcwt::present(issued.token, {one});
    EXPECT_TRUE(contains(presented, one));
    EXPECT_FALSE(contains(presented, two));

    // Presenting again REPLACES the selection rather than accumulating it: a
    // stale entry surviving here would over-disclose.
    const auto again = sdcwt::present(presented, {two});
    EXPECT_FALSE(contains(again, one));
    EXPECT_TRUE(contains(again, two));

    // An empty selection drops the header entirely.
    const auto none = sdcwt::present(presented, {});
    EXPECT_TRUE(unprotected_bstr_array(none, sdcwt::SD_CLAIMS_LABEL).empty());
  }

  // The signed parts must survive presentation untouched: present() never
  // re-signs.
  TEST(SdCwt, PresentLeavesTheSignedPartsUntouched)
  {
    const auto key = test_key();
    std::vector<sdcwt::Claim> claims = {{1002, sdcwt::value::text("secret")}};
    const auto issued = sdcwt::issue(claims, {{int64_t{1002}}}, *key);

    const auto before = parse_sign1(issued.token);
    const auto after = parse_sign1(
      sdcwt::present(issued.token, {issued.disclosures[0].encoded}));

    EXPECT_EQ(before.protected_header, after.protected_header);
    EXPECT_EQ(before.payload, after.payload);
    EXPECT_EQ(before.signature, after.signature);
  }

  TEST(SdCwt, PresentRejectsMalformedTokens)
  {
    const std::vector<uint8_t> garbage = {0xFF, 0xFF};
    EXPECT_THROW(sdcwt::present(garbage, {}), std::runtime_error);
    // A bare (untagged) array is not a COSE_Sign1 either.
    const auto untagged = ccf::cbor::serialize(ccf::cbor::make_array({}));
    EXPECT_THROW(sdcwt::present(untagged, {}), std::runtime_error);
  }
}
