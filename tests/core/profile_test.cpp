// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/profile.h"

#include "tests/core/test_support.h"

#include <ccf/crypto/base64.h>
#include <ccf/crypto/sha256.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace scitt_sd;
using namespace scitt_sd::testing;

namespace
{
  TEST(Profile, LabelsMatchTheProfile)
  {
    EXPECT_EQ(label::SCITT_RECEIPTS, 394);
    EXPECT_EQ(label::SD_CLAIMS, 17);
    EXPECT_EQ(sdcwt::SD_CLAIMS_LABEL, label::SD_CLAIMS);
    EXPECT_EQ(CODE_SIGNING_EKU_OID, "1.3.6.1.5.5.7.3.3");
  }

  // The fingerprint is unpadded base64url of SHA-256 over the root's DER, as
  // did:x509 requires.
  TEST(Profile, CaFingerprintIsUnpaddedBase64UrlSha256)
  {
    const auto chain = make_ccf_chain();
    const auto fingerprint = did_x509_ca_fingerprint(chain.root_der);

    const auto expected = ccf::crypto::b64url_from_raw(
      ccf::crypto::sha256(chain.root_der), /*with_padding=*/false);
    EXPECT_EQ(fingerprint, expected);
    EXPECT_EQ(fingerprint.find('='), std::string::npos);
    EXPECT_EQ(fingerprint.find('+'), std::string::npos);
    EXPECT_EQ(fingerprint.find('/'), std::string::npos);

    EXPECT_THROW(did_x509_ca_fingerprint({}), std::invalid_argument);
  }

  TEST(Profile, MakeAndParseDidX509RoundTrip)
  {
    const auto chain = make_ccf_chain();
    const auto did = make_did_x509(chain.root_der);
    EXPECT_EQ(
      did,
      "did:x509:0:sha256:" + did_x509_ca_fingerprint(chain.root_der) +
        "::eku:1.3.6.1.5.5.7.3.3");

    const auto parsed = parse_did_x509(did);
    EXPECT_EQ(parsed.fingerprint_alg, "sha256");
    EXPECT_EQ(parsed.fingerprint, did_x509_ca_fingerprint(chain.root_der));
    ASSERT_EQ(parsed.policies.size(), 1U);
    EXPECT_EQ(parsed.policies[0].name, "eku");
    ASSERT_EQ(parsed.policies[0].args.size(), 1U);
    EXPECT_EQ(parsed.policies[0].args[0], CODE_SIGNING_EKU_OID);

    EXPECT_THROW(make_did_x509(chain.root_der, ""), std::invalid_argument);
  }

  TEST(Profile, ParseDidX509RejectsMalformedIdentifiers)
  {
    EXPECT_THROW(parse_did_x509(""), std::invalid_argument);
    EXPECT_THROW(parse_did_x509("did:web:example.com"), std::invalid_argument);
    // No policy at all.
    EXPECT_THROW(
      parse_did_x509("did:x509:0:sha256:abc"), std::invalid_argument);
    // Unsupported version.
    EXPECT_THROW(
      parse_did_x509("did:x509:1:sha256:abc::eku:1.2"), std::invalid_argument);
    // Empty fingerprint.
    EXPECT_THROW(
      parse_did_x509("did:x509:0:sha256:::eku:1.2"), std::invalid_argument);
    // Policy without an argument.
    EXPECT_THROW(
      parse_did_x509("did:x509:0:sha256:abc::eku"), std::invalid_argument);
  }

  TEST(Profile, ParseDidX509KeepsEveryPolicy)
  {
    const auto parsed = parse_did_x509(
      "did:x509:0:sha256:abc::eku:1.3.6.1.5.5.7.3.3::subject:CN:issuer");
    ASSERT_EQ(parsed.policies.size(), 2U);
    EXPECT_EQ(parsed.policies[0].name, "eku");
    EXPECT_EQ(parsed.policies[1].name, "subject");
    ASSERT_EQ(parsed.policies[1].args.size(), 2U);
    EXPECT_EQ(parsed.policies[1].args[0], "CN");
    EXPECT_EQ(parsed.policies[1].args[1], "issuer");
  }

  TEST(Profile, HeaderEntriesCarryCritCwtClaimsAndChain)
  {
    const auto chain = make_ccf_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    const auto entries = scitt_x509_header_entries(issuer);
    ASSERT_EQ(entries.size(), 3U);
    EXPECT_EQ(std::get<int64_t>(entries[0].first), 2); // crit
    EXPECT_EQ(std::get<int64_t>(entries[1].first), 15); // CWT claims
    EXPECT_EQ(std::get<int64_t>(entries[2].first), 33); // x5chain

    // crit = [15, 33]
    const auto& crit = entries[0].second;
    ASSERT_EQ(crit.array_v.size(), 2U);
    EXPECT_EQ(crit.array_v[0].int_v, 15);
    EXPECT_EQ(crit.array_v[1].int_v, 33);

    // CWT claims = {1: iss, 2: sub}
    const auto& claims = entries[1].second;
    ASSERT_EQ(claims.map_keys.size(), 2U);
    EXPECT_EQ(std::get<int64_t>(claims.map_keys[0]), 1);
    EXPECT_EQ(claims.map_vals[0].text_v, issuer.issuer_did);
    EXPECT_EQ(std::get<int64_t>(claims.map_keys[1]), 2);
    EXPECT_EQ(claims.map_vals[1].text_v, "bug-report");

    // x5chain = [leaf, root], leaf first.
    const auto& x5chain = entries[2].second;
    ASSERT_EQ(x5chain.array_v.size(), 2U);
    EXPECT_EQ(x5chain.array_v[0].bytes_v, chain.leaf_der);
    EXPECT_EQ(x5chain.array_v[1].bytes_v, chain.root_der);
  }

  TEST(Profile, HeaderEntriesRejectMalformedIdentities)
  {
    const auto chain = make_ccf_chain();
    const auto did = make_did_x509(chain.root_der);

    EXPECT_THROW(
      scitt_x509_header_entries({did, "", chain.x5chain()}),
      std::invalid_argument);
    EXPECT_THROW(
      scitt_x509_header_entries({"not-a-did", "sub", chain.x5chain()}),
      std::invalid_argument);
    // A chain of one is a leaf with no trust anchor.
    EXPECT_THROW(
      scitt_x509_header_entries({did, "sub", {chain.leaf_der}}),
      std::invalid_argument);
    // An empty certificate cannot be a chain member.
    EXPECT_THROW(
      scitt_x509_header_entries({did, "sub", {chain.leaf_der, {}}}),
      std::invalid_argument);
    // Only SHA-256 CA fingerprints are supported.
    EXPECT_THROW(
      scitt_x509_header_entries(
        {"did:x509:0:sha512:abc::eku:1.2", "sub", chain.x5chain()}),
      std::invalid_argument);
  }
}
