// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/cose.h"

#include "core/sd_cwt.h"
#include "tests/core/test_support.h"

#include <ccf/crypto/cose_verifier.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace scitt_sd::testing;

namespace
{
  TEST(Cose, AlgorithmFollowsCurve)
  {
    EXPECT_EQ(
      sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::SECP256R1),
      sdcwt::COSE_ALG_ES256);
    EXPECT_EQ(
      sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::SECP384R1),
      sdcwt::COSE_ALG_ES384);
    EXPECT_THROW(
      sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::NONE),
      std::invalid_argument);
  }

  TEST(Cose, ProtectedHeaderIsCdeOrdered)
  {
    // {1: -7} then {1: -7, 2: [15]}: alg first, crit second.
    EXPECT_EQ(
      to_hex(sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES256)), "a10126");

    const sdcwt::HeaderEntries extra = {
      {int64_t{2}, sdcwt::CborValue::Array({sdcwt::value::integer(15)})}};
    EXPECT_EQ(
      to_hex(sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES256, extra)),
      "a2012602"
      "810f");
  }

  // A caller must not be able to override a label the framework already set.
  TEST(Cose, DuplicateProtectedHeaderLabelRejected)
  {
    const sdcwt::HeaderEntries clash = {
      {int64_t{sdcwt::COSE_HEADER_ALG}, sdcwt::value::integer(-7)}};
    EXPECT_THROW(
      sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES256, clash),
      std::invalid_argument);

    const sdcwt::HeaderEntries sd_alg_clash = {
      {int64_t{sdcwt::SD_ALG_LABEL}, sdcwt::value::integer(-16)}};
    EXPECT_THROW(
      sdcwt::encode_sdcwt_protected_header(
        sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_256, sd_alg_clash),
      std::invalid_argument);
  }

  TEST(Cose, SdCwtProtectedHeaderCarriesTypAndSdAlg)
  {
    // {1: -7, 16: 293, 170: -16}
    EXPECT_EQ(
      to_hex(sdcwt::encode_sdcwt_protected_header(
        sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_256)),
      "a3012610190125"
      "18aa2f");
    // sd_alg agility: SHA-384 is -43.
    EXPECT_EQ(
      to_hex(sdcwt::encode_sdcwt_protected_header(
        sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_384)),
      "a301261019012518aa382a");
  }

  // The signature must verify through CCF's COSE verifier, which is what
  // core/verify.cpp uses: this pins the Sig_structure the two agree on.
  TEST(Cose, SignedStatementVerifiesUnderCcfCoseVerifier)
  {
    const auto chain = make_ccf_chain();
    const auto phdr = sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES256);
    const std::vector<uint8_t> payload = {0xA0}; // {}

    const auto token = sdcwt::sign_cose_sign1(*chain.leaf_key, phdr, payload);

    auto verifier =
      ccf::crypto::make_cose_verifier_from_der_cert(chain.leaf_der);
    EXPECT_TRUE(verifier->verify_decomposed(
      phdr, payload, extract_signature(token), sdcwt::COSE_ALG_ES256));

    // A single flipped payload byte must break it.
    const std::vector<uint8_t> tampered = {0xA1};
    EXPECT_FALSE(verifier->verify_decomposed(
      phdr, tampered, extract_signature(token), sdcwt::COSE_ALG_ES256));
  }

  TEST(Cose, ExternalAadIsBoundIntoTheSignature)
  {
    const auto chain = make_ccf_chain();
    const auto phdr = sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES256);
    const std::vector<uint8_t> payload = {0xA0};
    const std::vector<uint8_t> aad = {0x01, 0x02};

    const auto with_aad =
      sdcwt::sign_cose_sign1(*chain.leaf_key, phdr, payload, aad);
    auto verifier =
      ccf::crypto::make_cose_verifier_from_der_cert(chain.leaf_der);
    // verify_decomposed uses an empty external_aad, so a bound aad must fail.
    EXPECT_FALSE(verifier->verify_decomposed(
      phdr, payload, extract_signature(with_aad), sdcwt::COSE_ALG_ES256));
  }
}
