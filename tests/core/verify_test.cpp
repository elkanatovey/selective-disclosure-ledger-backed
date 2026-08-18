// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/verify.h"

#include "core/report_internal.h"
#include "core/sd_cwt_internal.h"
#include "tests/core/test_support.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <string>

using namespace scitt_sd;
using namespace scitt_sd::testing;

namespace
{
  namespace cbor = ccf::cbor;

  const report::Selection EVERYTHING{
    {report::label::TITLE,
     report::label::COMPONENT,
     report::label::SEVERITY,
     report::label::FINGERPRINT},
    {1},
    {0}};

  // Rebuild a COSE_Sign1 with individual parts replaced, so a test can express
  // a statement no honest issuer would produce.
  std::vector<uint8_t> rebuild_sign1(
    std::span<const uint8_t> token,
    const std::vector<uint8_t>* protected_header,
    const std::vector<uint8_t>* payload,
    const std::vector<uint8_t>* signature)
  {
    const auto root = cbor::parse(token);
    const auto& parts =
      std::get<cbor::Array>(root->tag_at(cbor::tag::COSE_SIGN_1)->value).items;

    std::vector<cbor::MapItem> uhdr;
    for (const auto& [key, value] : std::get<cbor::Map>(parts[1]->value).items)
    {
      uhdr.emplace_back(key, value);
    }

    return cbor::serialize(cbor::make_tagged(
      cbor::tag::COSE_SIGN_1,
      cbor::make_array(
        {protected_header == nullptr ? parts[0] :
                                       sdcwt::bytes_value(*protected_header),
         cbor::make_map(std::move(uhdr)),
         payload == nullptr ? parts[2] : sdcwt::bytes_value(*payload),
         signature == nullptr ? parts[3] : sdcwt::bytes_value(*signature)})));
  }

  std::vector<uint8_t> attach_unknown_unprotected(
    std::span<const uint8_t> token)
  {
    const auto root = cbor::parse(token);
    const auto& parts =
      std::get<cbor::Array>(root->tag_at(cbor::tag::COSE_SIGN_1)->value).items;
    std::vector<cbor::MapItem> unprotected;
    for (const auto& [key, value] : std::get<cbor::Map>(parts[1]->value).items)
    {
      unprotected.emplace_back(key, value);
    }
    unprotected.emplace_back(cbor::make_signed(999), cbor::make_signed(1));
    return cbor::serialize(cbor::make_tagged(
      cbor::tag::COSE_SIGN_1,
      cbor::make_array(
        {parts[0],
         cbor::make_map(std::move(unprotected)),
         parts[2],
         parts[3]})));
  }

  // A scenario over a CCF-generated chain, whose leaf cannot carry an EKU: the
  // did:x509 therefore pins the leaf subject instead.
  Scenario make_subject_scenario(
    const report::Selection& selection = EVERYTHING,
    const std::string& valid_from = "20240101000000Z",
    size_t validity_days = 3650)
  {
    Scenario scenario;
    scenario.chain = make_ccf_chain("test-issuer", valid_from, validity_days);
    scenario.issuer = {
      subject_did(scenario.chain, "test-issuer"),
      "bug-report",
      scenario.chain.x5chain()};
    scenario.issued =
      report::issue(sample_report(), scenario.issuer, *scenario.chain.leaf_key);
    scenario.proof = make_proof(
      scenario.issued,
      report::select_disclosures(scenario.issued, selection),
      scenario.receipt);
    return scenario;
  }

  verify::Params subject_params(const Chain& chain)
  {
    verify::Params params;
    params.trusted_root = chain.root_pem;
    params.required_eku.clear(); // the subject policy is what is pinned here
    return params;
  }

  // --- Positive paths -----------------------------------------------------

  // The end-to-end path over a chain that really does carry the profile's
  // code-signing EKU.
  TEST(Verify, AcceptsAValidBundleAndReportsTheDisclosedContent)
  {
    const auto scenario = make_eku_scenario(EVERYTHING);
    const RecordingReceiptVerifier receipts;

    const auto result = verify::verify_bundle(
      scenario.proof, eku_params(scenario.chain), receipts);

    EXPECT_EQ(result.issuer_did, scenario.issuer.issuer_did);
    EXPECT_EQ(result.subject, "bug-report");
    EXPECT_EQ(result.issued_at, 1700000000);
    EXPECT_NE(result.leaf_subject.find("Test Issuer"), std::string::npos);

    ASSERT_TRUE(result.disclosed.title.has_value());
    EXPECT_EQ(*result.disclosed.title, "Heap overflow in parser");
    ASSERT_TRUE(result.disclosed.component.has_value());
    EXPECT_EQ(*result.disclosed.component, "parser");
    ASSERT_TRUE(result.disclosed.severity.has_value());
    EXPECT_EQ(*result.disclosed.severity, "high");
    ASSERT_TRUE(result.disclosed.fingerprint.has_value());
    EXPECT_EQ(
      *result.disclosed.fingerprint,
      (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));

    // The body's shape is revealed (two chunks) but only chunk 1 is readable.
    EXPECT_TRUE(result.disclosed.body_disclosed);
    EXPECT_EQ(result.disclosed.body_chunk_count, 2U);
    ASSERT_EQ(result.disclosed.body_chunks.size(), 1U);
    EXPECT_EQ(result.disclosed.body_chunks.at(1), " chars");

    EXPECT_TRUE(result.disclosed.references_disclosed);
    EXPECT_EQ(result.disclosed.reference_count, 2U);
    ASSERT_EQ(result.disclosed.references.size(), 1U);
    EXPECT_EQ(result.disclosed.references.at(0), "CVE-2024-0001");

    ASSERT_EQ(result.receipts.size(), 1U);
    EXPECT_EQ(result.receipts[0].txid, "2.14");
  }

  // The receipt covers what was registered, so the verifier must be handed
  // those exact bytes: not a re-encoding, and not the presented statement.
  TEST(Verify, ReceiptVerifierSeesTheExactRegisteredStatement)
  {
    const auto scenario = make_eku_scenario();
    const RecordingReceiptVerifier receipts;

    (void)verify::verify_bundle(
      scenario.proof, eku_params(scenario.chain), receipts);

    ASSERT_EQ(receipts.calls.size(), 1U);
    EXPECT_EQ(receipts.calls[0].first, scenario.receipt);
    EXPECT_EQ(receipts.calls[0].second, scenario.proof.registered_statement);
    EXPECT_EQ(receipts.calls[0].second, scenario.issued.statement);
    EXPECT_NE(receipts.calls[0].second, scenario.proof.transparent_statement);
  }

  TEST(Verify, AcceptsASubjectPolicyDid)
  {
    const auto scenario = make_subject_scenario();
    const RecordingReceiptVerifier receipts;
    EXPECT_NO_THROW((void)verify::verify_bundle(
      scenario.proof, subject_params(scenario.chain), receipts));
  }

  // Disclosing nothing is a legitimate presentation: registration is still
  // proved, and only `iat` is readable.
  TEST(Verify, AcceptsABundleWithNoDisclosures)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.disclosures.clear();
    const RecordingReceiptVerifier receipts;

    const auto result = verify::verify_bundle(
      scenario.proof, eku_params(scenario.chain), receipts);
    EXPECT_FALSE(result.disclosed.title.has_value());
    EXPECT_FALSE(result.disclosed.body_disclosed);
    EXPECT_EQ(result.issued_at, 1700000000);
  }

  TEST(Verify, RejectsDisclosuresSmuggledInTheTransparentStatement)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.transparent_statement = report::present(
      scenario.proof.transparent_statement, scenario.proof.disclosures);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected verification to reject unsigned disclosures";
    }

    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.check(), verify::Check::StatementBinding);
      EXPECT_NE(
        e.reason().find("transparent statement carries disclosures"),
        std::string::npos);
    }
  }

  TEST(Verify, RejectsUnknownTransparentUnprotectedHeaders)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.transparent_statement =
      attach_unknown_unprotected(scenario.proof.transparent_statement);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected verification to reject unknown unprotected headers";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.check(), verify::Check::StatementBinding);
      EXPECT_NE(
        e.reason().find("must contain only receipts"), std::string::npos);
    }
  }

  TEST(Verify, IgnoreCertificateTimeAcceptsAnExpiredChain)
  {
    const auto scenario =
      make_subject_scenario(EVERYTHING, "20200101000000Z", 1);
    auto params = subject_params(scenario.chain);
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(scenario.proof, params, receipts),
      verify::VerificationError);

    params.ignore_certificate_time = true;
    EXPECT_NO_THROW(
      (void)verify::verify_bundle(scenario.proof, params, receipts));
  }

  // --- Certificate and identity negatives ---------------------------------

  TEST(Verify, RejectsAnUntrustedRoot)
  {
    const auto scenario = make_eku_scenario();
    const auto other = make_ccf_chain();
    auto params = eku_params(scenario.chain);
    params.trusted_root = other.root_pem;
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(scenario.proof, params, receipts),
      verify::VerificationError);
  }

  TEST(Verify, RejectsAMissingTrustedRoot)
  {
    const auto scenario = make_eku_scenario();
    verify::Params params;
    const RecordingReceiptVerifier receipts;
    EXPECT_THROW(
      (void)verify::verify_bundle(scenario.proof, params, receipts),
      verify::VerificationError);
  }

  // The chain ends at the trusted root, but the leaf was endorsed by someone
  // else: pinning the anchor is not enough, the chain must verify.
  TEST(Verify, RejectsALeafThatDoesNotChainToTheRoot)
  {
    const auto trusted = make_ccf_chain("test-issuer");
    const auto other = make_ccf_chain("test-issuer");
    const IssuerIdentity issuer{
      subject_did(trusted, "test-issuer"),
      "bug-report",
      {other.leaf_der, trusted.root_der}};

    const auto issued = report::issue(sample_report(), issuer, *other.leaf_key);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(issued, {}, receipt);
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(proof, subject_params(trusted), receipts),
      verify::VerificationError);
  }

  // The did:x509 must pin the separately trusted root, not some other CA.
  TEST(Verify, RejectsADidThatPinsAnotherCa)
  {
    const auto chain = make_ccf_chain("test-issuer");
    const auto other = make_ccf_chain();
    const IssuerIdentity issuer{
      subject_did(other, "test-issuer"), "bug-report", chain.x5chain()};

    const auto issued = report::issue(sample_report(), issuer, *chain.leaf_key);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(issued, {}, receipt);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(proof, subject_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("does not pin the trusted root"),
        std::string::npos);
    }
  }

  // The profile requires the leaf to carry id-kp-codeSigning: a chain whose
  // leaf has no EKU extension must be refused when that EKU is required.
  TEST(Verify, RejectsALeafWithoutTheRequiredEku)
  {
    const auto chain = make_ccf_chain("test-issuer");
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};
    const auto issued = report::issue(sample_report(), issuer, *chain.leaf_key);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(issued, {}, receipt);
    const RecordingReceiptVerifier receipts;

    // The DID pins the right EKU, so this is the certificate failing the
    // policy rather than the DID failing the parameter check.
    try
    {
      (void)verify::verify_bundle(proof, eku_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("did:x509 policy"), std::string::npos);
    }
  }

  // A did:x509 that does not pin the EKU the caller requires is refused even
  // when its other policies hold.
  TEST(Verify, RejectsADidThatDoesNotPinTheRequiredEku)
  {
    const auto scenario = make_subject_scenario();
    auto params = subject_params(scenario.chain);
    params.required_eku = std::string(CODE_SIGNING_EKU_OID);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(scenario.proof, params, receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(std::string(e.what()).find("required EKU"), std::string::npos);
    }
  }

  TEST(Verify, RejectsAnIssuerSignatureFromAnotherKey)
  {
    const auto chain = make_ccf_chain("test-issuer");
    const auto impostor =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    const IssuerIdentity issuer{
      subject_did(chain, "test-issuer"), "bug-report", chain.x5chain()};

    // The chain is genuine; the signature is not.
    const auto issued = report::issue(sample_report(), issuer, *impostor);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(issued, {}, receipt);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(proof, subject_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("COSE signature"), std::string::npos);
    }
  }

  // --- Registered / transparent binding ------------------------------------

  TEST(Verify, RejectsAPayloadThatDiffersFromTheRegisteredOne)
  {
    auto scenario = make_eku_scenario();
    auto other = sample_report();
    other.issued_at = 1700000001;
    const auto second =
      report::issue(other, scenario.issuer, *scenario.chain.leaf_key);
    scenario.proof.transparent_statement =
      attach_receipts(second.statement, {scenario.receipt});
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("payloads differ"), std::string::npos);
    }
  }

  TEST(Verify, RejectsAProtectedHeaderThatDiffersFromTheRegisteredOne)
  {
    auto scenario = make_eku_scenario();
    const IssuerIdentity other_subject{
      scenario.issuer.issuer_did, "another-subject", scenario.chain.x5chain()};
    const auto second =
      report::issue(sample_report(), other_subject, *scenario.chain.leaf_key);
    const auto phdr = parse_sign1(second.statement).protected_header;

    scenario.proof.transparent_statement = rebuild_sign1(
      scenario.proof.transparent_statement, &phdr, nullptr, nullptr);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("protected headers differ"),
        std::string::npos);
    }
  }

  TEST(Verify, RejectsASignatureThatDiffersFromTheRegisteredOne)
  {
    auto scenario = make_eku_scenario();
    auto signature = parse_sign1(scenario.issued.statement).signature;
    signature[0] ^= 0xFFU;
    scenario.proof.transparent_statement = rebuild_sign1(
      scenario.proof.transparent_statement, nullptr, nullptr, &signature);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("signatures differ"), std::string::npos);
    }
  }

  // What is registered must be the redacted statement: a registered statement
  // carrying disclosures would put the cleartext inside the receipt's scope.
  TEST(Verify, RejectsARegisteredStatementCarryingDisclosures)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.registered_statement =
      report::present(scenario.issued.statement, scenario.proof.disclosures);
    scenario.proof.transparent_statement =
      attach_receipts(scenario.proof.registered_statement, {scenario.receipt});
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("carries disclosures"), std::string::npos);
    }
  }

  TEST(Verify, RejectsATransparentStatementWithoutAReceipt)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.transparent_statement = scenario.issued.statement;
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(std::string(e.what()).find("no receipt"), std::string::npos);
    }
  }

  TEST(Verify, RejectsAFailedReceipt)
  {
    const auto scenario = make_eku_scenario();
    const RecordingReceiptVerifier receipts(/*succeed=*/false);

    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
    // Even a rejected receipt is checked against the registered statement.
    ASSERT_EQ(receipts.calls.size(), 1U);
    EXPECT_EQ(receipts.calls[0].second, scenario.proof.registered_statement);
  }

  TEST(Verify, RejectsAnUnsupportedBundleVersion)
  {
    auto scenario = make_eku_scenario();
    scenario.proof.version = bundle::VERSION + 1;
    const RecordingReceiptVerifier receipts;
    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
  }

  TEST(Verify, RejectsMalformedStatements)
  {
    auto scenario = make_eku_scenario();
    const RecordingReceiptVerifier receipts;

    scenario.proof.registered_statement = {0xFF, 0xFF};
    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);

    scenario = make_eku_scenario();
    scenario.proof.transparent_statement =
      cbor::serialize(cbor::make_array({}));
    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
  }

  // --- Disclosure negatives -------------------------------------------------

  TEST(Verify, RejectsATamperedDisclosure)
  {
    auto scenario = make_eku_scenario();
    ASSERT_FALSE(scenario.proof.disclosures.empty());
    scenario.proof.disclosures[0].back() ^= 0x01U;
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("not committed to"), std::string::npos);
    }
  }

  TEST(Verify, RejectsADisclosureFromAnotherReport)
  {
    auto scenario = make_eku_scenario();
    const auto other = make_eku_scenario();
    scenario.proof.disclosures.push_back(
      report::select_disclosures(
        other.issued, {{report::label::SEVERITY}, {}, {}})
        .front());
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
  }

  // A child disclosure is only meaningful once its parent has been opened: the
  // parent's own value is what commits to the child.
  TEST(Verify, RejectsAChildDisclosureWithoutItsParent)
  {
    auto scenario = make_eku_scenario();
    const auto with_parent = report::select_disclosures(
      scenario.issued, {{}, {0}, {}}); // body, body[0]
    ASSERT_EQ(with_parent.size(), 2U);
    scenario.proof.disclosures = {with_parent[1]}; // the child alone
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
  }

  TEST(Verify, RejectsADuplicatedDisclosure)
  {
    auto scenario = make_eku_scenario();
    ASSERT_FALSE(scenario.proof.disclosures.empty());
    scenario.proof.disclosures.push_back(scenario.proof.disclosures.front());
    const RecordingReceiptVerifier receipts;

    // The second copy has no unopened commitment left to match.
    EXPECT_THROW(
      (void)verify::verify_bundle(
        scenario.proof, eku_params(scenario.chain), receipts),
      verify::VerificationError);
  }

  // Salts must be full length: a short salt weakens the commitment even though
  // the digest still matches.
  TEST(Verify, RejectsAShortSalt)
  {
    const auto chain = load_eku_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    uint8_t counter = 0;
    const sdcwt::RandomSource short_salts = [&counter](size_t) {
      std::vector<uint8_t> salt(sdcwt::SALT_LEN / 2, 0);
      salt[0] = counter++;
      return salt;
    };
    const auto issued = report::detail::issue(
      sample_report(),
      issuer,
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      short_salts);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(
      issued,
      report::select_disclosures(issued, {{report::label::TITLE}, {}, {}}),
      receipt);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(proof, eku_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(std::string(e.what()).find("salt"), std::string::npos);
    }
  }

  // Reusing a salt across disclosures leaks that two commitments share it, so
  // it is refused even when both digests are genuine.
  TEST(Verify, RejectsAReusedSalt)
  {
    const auto chain = load_eku_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    const sdcwt::RandomSource fixed_salt = [](size_t) {
      return std::vector<uint8_t>(sdcwt::SALT_LEN, 0x5A);
    };
    const auto issued = report::detail::issue(
      sample_report(),
      issuer,
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      fixed_salt);
    const std::vector<uint8_t> receipt = {0x01};
    const auto proof = make_proof(
      issued,
      report::select_disclosures(
        issued, {{report::label::TITLE, report::label::SEVERITY}, {}, {}}),
      receipt);
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(proof, eku_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(std::string(e.what()).find("reuse"), std::string::npos);
    }
  }

  // --- Statement shape negatives -------------------------------------------

  TEST(Verify, RejectsAPayloadWithAClaimInTheClear)
  {
    const auto chain = load_eku_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    // A statement whose title claim was never redacted.
    const std::vector<sdcwt::Claim> claims = {
      {report::label::IAT, sdcwt::CborValue::Int(1700000000)},
      {report::label::TITLE, sdcwt::value::text("in the clear")}};
    const auto token = sdcwt::issue(
      claims,
      {},
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      0,
      scitt_x509_header_entries(issuer));

    bundle::ProofBundle proof;
    proof.registered_statement = token.token;
    proof.transparent_statement = attach_receipts(token.token, {{0x01}});
    proof.scitt_url = "https://transparency.example";
    proof.txid = "2.14";
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(proof, eku_params(chain), receipts),
      verify::VerificationError);
  }

  TEST(Verify, RejectsAPayloadThatRedactsTheWrongNumberOfClaims)
  {
    const auto chain = load_eku_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    const std::vector<sdcwt::Claim> claims = {
      {report::label::IAT, sdcwt::CborValue::Int(1700000000)},
      {report::label::TITLE, sdcwt::value::text("hidden")}};
    const auto token = sdcwt::issue(
      claims,
      {{int64_t{report::label::TITLE}}},
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      0,
      scitt_x509_header_entries(issuer));

    bundle::ProofBundle proof;
    proof.registered_statement = token.token;
    proof.transparent_statement = attach_receipts(token.token, {{0x01}});
    proof.scitt_url = "https://transparency.example";
    proof.txid = "2.14";
    const RecordingReceiptVerifier receipts;

    try
    {
      (void)verify::verify_bundle(proof, eku_params(chain), receipts);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_NE(
        std::string(e.what()).find("content claims"), std::string::npos);
    }
  }

  // The SCITT X.509 profile headers are what carry the issuer identity: a
  // statement without them cannot be attributed at all.
  TEST(Verify, RejectsAStatementWithoutTheProfileHeaders)
  {
    const auto chain = load_eku_chain();
    const auto phdr = sdcwt::encode_sdcwt_protected_header(
      sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_256);
    const std::vector<uint8_t> payload = {0xA0};
    const auto token = sdcwt::sign_cose_sign1(*chain.leaf_key, phdr, payload);

    bundle::ProofBundle proof;
    proof.registered_statement = token;
    proof.transparent_statement = attach_receipts(token, {{0x01}});
    proof.scitt_url = "https://transparency.example";
    proof.txid = "2.14";
    const RecordingReceiptVerifier receipts;

    EXPECT_THROW(
      (void)verify::verify_bundle(proof, eku_params(chain), receipts),
      verify::VerificationError);
  }

  // --- receipt-free verification ------------------------------------------

  // A caller that owns receipt verification separately still gets every other
  // check, and gets no receipt information back.
  TEST(VerifyWithoutReceipts, ChecksEverythingExceptTheReceipt)
  {
    const auto scenario = make_subject_scenario();

    const auto result =
      verify::verify_bundle(scenario.proof, subject_params(scenario.chain));

    EXPECT_EQ(result.issuer_did, scenario.issuer.issuer_did);
    EXPECT_EQ(result.subject, "bug-report");
    EXPECT_TRUE(result.receipts.empty());
    ASSERT_TRUE(result.disclosed.title.has_value());
    EXPECT_EQ(*result.disclosed.title, sample_report().title);
  }

  // Not verifying the receipt is not the same as not requiring one: a bundle
  // that was never registered is still refused.
  TEST(VerifyWithoutReceipts, StillRequiresAReceiptToBePresent)
  {
    auto scenario = make_subject_scenario();
    scenario.proof.transparent_statement = scenario.issued.statement;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, subject_params(scenario.chain));
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.check(), verify::Check::StatementBinding);
      EXPECT_NE(std::string(e.what()).find("no receipt"), std::string::npos);
    }
  }

  // The trust anchor still decides: a bundle that does not chain to the
  // supplied root is refused whether or not receipts are checked.
  TEST(VerifyWithoutReceipts, RejectsAnUntrustedRoot)
  {
    const auto scenario = make_subject_scenario();
    const auto other = make_ccf_chain("other-issuer");

    try
    {
      (void)verify::verify_bundle(scenario.proof, subject_params(other));
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.check(), verify::Check::MsrcChain);
    }
  }

  // --- failed checks name themselves --------------------------------------

  TEST(Verify, NamesTheCheckThatFailed)
  {
    const auto scenario = make_subject_scenario();

    // A tampered signature is the issuer's signature failing, not the chain.
    {
      auto proof = scenario.proof;
      auto signature = extract_signature(scenario.issued.statement);
      signature[0] ^= 0xFF;
      proof.registered_statement =
        rebuild_sign1(scenario.issued.statement, nullptr, nullptr, &signature);
      proof.transparent_statement =
        attach_receipts(proof.registered_statement, {scenario.receipt});
      try
      {
        (void)verify::verify_bundle(proof, subject_params(scenario.chain));
        FAIL() << "expected a rejection";
      }
      catch (const verify::VerificationError& e)
      {
        EXPECT_EQ(e.check(), verify::Check::IssuerSignature);
      }
    }

    // A disclosure that commits to nothing in the payload is the disclosures
    // failing, and nothing else.
    {
      auto proof = scenario.proof;
      const auto other = make_subject_scenario();
      proof.disclosures.push_back(
        report::select_disclosures(
          other.issued, {{report::label::SEVERITY}, {}, {}})
          .front());
      try
      {
        (void)verify::verify_bundle(proof, subject_params(scenario.chain));
        FAIL() << "expected a rejection";
      }
      catch (const verify::VerificationError& e)
      {
        EXPECT_EQ(e.check(), verify::Check::Disclosures);
      }
    }

    // A receipt the verifier rejects is the receipt check failing.
    {
      const RecordingReceiptVerifier receipts(false);
      try
      {
        (void)verify::verify_bundle(
          scenario.proof, subject_params(scenario.chain), receipts);
        FAIL() << "expected a rejection";
      }
      catch (const verify::VerificationError& e)
      {
        EXPECT_EQ(e.check(), verify::Check::Receipt);
        EXPECT_NE(
          e.reason().find("receipt verification failed"), std::string::npos);
      }
    }
  }

  // The reason is the message without the prefix the exception adds, so a
  // caller can report it without repeating "verification failed".
  TEST(Verify, ReportsAReasonWithoutThePrefix)
  {
    auto scenario = make_subject_scenario();
    scenario.proof.version = bundle::VERSION + 1;

    try
    {
      (void)verify::verify_bundle(
        scenario.proof, subject_params(scenario.chain));
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.reason(), "unsupported proof bundle version");
      EXPECT_EQ(
        std::string(e.what()),
        "verification failed: unsupported proof "
        "bundle version");
    }
  }

  // --- inspection ----------------------------------------------------------

  // Inspection reads a bundle with no trust anchor at all: it is what a viewer
  // needs to DISPLAY the disclosed fields, and says nothing about trust.
  TEST(Inspect, ReadsABundleWithoutATrustAnchor)
  {
    const auto scenario = make_subject_scenario();

    const auto result = verify::inspect_bundle(scenario.proof);

    EXPECT_EQ(result.issuer_did, scenario.issuer.issuer_did);
    EXPECT_EQ(result.leaf_subject, "CN=test-issuer");
    EXPECT_TRUE(result.receipts.empty());
    ASSERT_TRUE(result.disclosed.title.has_value());
    EXPECT_EQ(*result.disclosed.title, sample_report().title);
    EXPECT_EQ(result.disclosed.body_chunks.size(), 1U);
  }

  // Inspection makes no trust decision, so a did:x509 pinning a root nobody
  // trusts still describes what the bundle contains.
  TEST(Inspect, DoesNotCheckWhoTheIssuerIs)
  {
    const auto chain = make_ccf_chain("test-issuer");
    const auto other = make_ccf_chain();
    const IssuerIdentity issuer{
      subject_did(other, "test-issuer"), "bug-report", chain.x5chain()};
    const auto issued = report::issue(sample_report(), issuer, *chain.leaf_key);
    const auto proof = make_proof(
      issued, report::select_disclosures(issued, EVERYTHING), {0x01});

    // The same bundle is refused the moment a trust anchor is involved.
    EXPECT_THROW(
      (void)verify::verify_bundle(proof, subject_params(chain)),
      verify::VerificationError);

    const auto result = verify::inspect_bundle(proof);
    ASSERT_TRUE(result.disclosed.title.has_value());
    EXPECT_EQ(*result.disclosed.title, sample_report().title);
  }

  // Inspection still checks that the bundle is internally consistent: a
  // statement whose signature does not verify under its own leaf is refused.
  TEST(Inspect, RejectsAStatementTheLeafDidNotSign)
  {
    const auto scenario = make_subject_scenario();
    auto signature = extract_signature(scenario.issued.statement);
    signature[0] ^= 0xFF;

    bundle::ProofBundle proof = scenario.proof;
    proof.registered_statement =
      rebuild_sign1(scenario.issued.statement, nullptr, nullptr, &signature);
    proof.transparent_statement =
      attach_receipts(proof.registered_statement, {scenario.receipt});

    try
    {
      (void)verify::inspect_bundle(proof);
      FAIL() << "expected a rejection";
    }
    catch (const verify::VerificationError& e)
    {
      EXPECT_EQ(e.check(), verify::Check::IssuerSignature);
    }
  }

  // Every presented disclosure is reported with the path it resolved to, in
  // the order the bundle carries them: that is how a presenter knows which
  // byte string is which without re-deriving it.
  TEST(Inspect, ReportsThePathOfEveryDisclosure)
  {
    const report::Selection selection{
      {report::label::TITLE, report::label::REFERENCES}, {1}, {0}};
    const auto scenario = make_subject_scenario(selection);

    const auto result = verify::inspect_bundle(scenario.proof);

    ASSERT_EQ(
      result.disclosure_paths.size(), scenario.proof.disclosures.size());
    std::vector<std::string> described;
    described.reserve(result.disclosure_paths.size());
    for (const auto& path : result.disclosure_paths)
    {
      described.push_back(report::describe_path(path));
    }
    std::sort(described.begin(), described.end());
    EXPECT_EQ(
      described,
      (std::vector<std::string>{
        "body", "body[1]", "references", "references[0]", "title"}));
  }
}
