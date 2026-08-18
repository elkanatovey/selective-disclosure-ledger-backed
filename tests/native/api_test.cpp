// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The in-memory API, driven directly: bytes in, bytes out, no filesystem and
// no command line. This is where the whole flow is pinned end to end, because
// it is the one place that can run it without a transparency service: the
// transparent statement a service would return is produced here by attaching
// an opaque receipt to the registered statement with the same CBOR library
// the core uses.
//
// Every key and certificate below is produced by the API itself, through the
// CCF crypto APIs.

#include "native/api.h"

#include "core/cose.h"
#include "core/profile.h"
#include "core/sd_cwt.h"
#include "core/text_chunks.h"
#include "native/identity.h"
#include "tests/core/test_support.h"

#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/sha256.h>
#include <ccf/crypto/verifier.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using namespace scitt_sd::native;
using nlohmann::json;

namespace
{
  const std::vector<uint8_t> RECEIPT = {0x52, 0x43, 0x50, 0x54};

  std::string report_document(const std::string& body = "Twelve chars")
  {
    return R"({"title": "Heap overflow in parser",)"
           R"("body": ")" +
      body +
      R"(",)"
      R"("component": "parser",)"
      R"("severity": "high",)"
      R"("fingerprint": "abc123",)"
      R"("references": ["CVE-2024-0001", "internal-1234"]})";
  }

  // Everything the demo produces before a bundle exists, in the order an
  // operator would produce it.
  struct Issued
  {
    RootIdentity root;
    Bytes private_key;
    Bytes public_key;
    Bytes leaf_cert;
    IssuedStatement statement;
    Bytes transparent;
  };

  Issued issue_everything(const std::string& body = "Twelve chars")
  {
    Issued issued;
    issued.root = create_root_identity();
    issued.private_key = generate_private_key();
    issued.public_key = derive_public_key(issued.private_key);
    issued.leaf_cert = issue_certificate(
      issued.root.private_key, issued.root.certificate, issued.public_key);
    issued.statement = issue_statement(
      report_document(body),
      issued.private_key,
      issued.leaf_cert,
      issued.root.certificate);
    // What a transparency service returns: the same statement with a receipt
    // in its unprotected header.
    issued.transparent = scitt_sd::testing::attach_receipts(
      issued.statement.registered_statement, {RECEIPT});
    return issued;
  }

  Bytes make_bundle(const Issued& issued)
  {
    return create_bundle(
             issued.statement.registered_statement,
             issued.transparent,
             issued.statement.disclosure_set,
             "https://transparency.example",
             "2.14",
             1700000100)
      .bundle;
  }

  json field_of(const json& document, const std::string& name)
  {
    for (const auto& field : document.at("fields"))
    {
      if (field.at("name") == name)
      {
        return field;
      }
    }
    ADD_FAILURE() << "no field named '" << name << "'";
    return {};
  }

  // A reporter that keeps its own key: only the public half is ever handed to
  // the API under test.
  struct Held
  {
    RootIdentity root;
    Bytes private_key;
    Bytes public_key;
    Bytes leaf_cert;
  };

  Held hold_a_key()
  {
    Held held;
    held.root = create_root_identity();
    held.private_key = generate_private_key();
    held.public_key = derive_public_key(held.private_key);
    held.leaf_cert = issue_certificate(
      held.root.private_key, held.root.certificate, held.public_key);
    return held;
  }

  // Exactly what WebCrypto's ECDSA does: hash, sign, emit raw r||s.
  Bytes sign_detached(const Bytes& private_key_pem, const Bytes& to_be_signed)
  {
    const auto key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(private_key_pem));
    const auto curve = key->get_curve_id();
    const auto md = ccf::crypto::get_md_for_ec(curve);
    const auto digest = ccf::crypto::make_hash_provider()->hash(
      to_be_signed.data(), to_be_signed.size(), md);
    const auto der = key->sign_hash(digest.data(), digest.size());
    return ccf::crypto::ecdsa_sig_der_to_p1363(der, curve);
  }

  std::vector<uint8_t> digest_of(std::span<const uint8_t> data)
  {
    const auto hash = ccf::crypto::sha256(data);
    return {hash.begin(), hash.end()};
  }

  // One step of the CCF Merkle tree.
  std::vector<uint8_t> join(
    std::span<const uint8_t> left, std::span<const uint8_t> right)
  {
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), left.begin(), left.end());
    preimage.insert(preimage.end(), right.begin(), right.end());
    return digest_of(preimage);
  }

  // A receipt shaped exactly as a CCF transparency service issues one: the
  // statement's digest is the leaf's claims digest, `path` leads from that
  // leaf to the root, and the service signs the root with a detached payload.
  // Building it here rather than mocking the service is what lets the tests
  // corrupt one part at a time.
  Bytes ccf_receipt(
    const Bytes& service_key_pem,
    const Bytes& statement,
    const std::string& txid,
    const std::vector<std::pair<bool, std::vector<uint8_t>>>& path = {},
    int64_t vds = 2)
  {
    namespace cbor = ccf::cbor;

    const std::vector<uint8_t> write_set(32, 0x11);
    const std::string commit_evidence = "ce:" + txid + ":test";
    const auto claims = digest_of(statement);

    std::vector<uint8_t> leaf_preimage;
    leaf_preimage.insert(
      leaf_preimage.end(), write_set.begin(), write_set.end());
    const auto evidence_digest = digest_of(std::span<const uint8_t>{
      reinterpret_cast<const uint8_t*>(commit_evidence.data()),
      commit_evidence.size()});
    leaf_preimage.insert(
      leaf_preimage.end(), evidence_digest.begin(), evidence_digest.end());
    leaf_preimage.insert(leaf_preimage.end(), claims.begin(), claims.end());

    auto root = digest_of(leaf_preimage);
    std::vector<cbor::Value> path_items;
    path_items.reserve(path.size());
    for (const auto& [on_the_left, sibling] : path)
    {
      root = on_the_left ? join(sibling, root) : join(root, sibling);
      path_items.push_back(cbor::make_array(
        {cbor::make_simple(cbor::boolean_to_simple(on_the_left)),
         cbor::make_bytes(sibling)}));
    }

    std::vector<cbor::MapItem> proof_items;
    proof_items.emplace_back(
      cbor::make_signed(1),
      cbor::make_array(
        {cbor::make_bytes(write_set),
         cbor::make_string(commit_evidence),
         cbor::make_bytes(claims)}));
    proof_items.emplace_back(
      cbor::make_signed(2), cbor::make_array(std::move(path_items)));
    const auto proof = cbor::serialize(cbor::make_map(std::move(proof_items)));

    const auto key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(service_key_pem));
    sdcwt::CborValue ccf_claims = sdcwt::CborValue::Map({});
    ccf_claims.map_put(std::string("txid"), sdcwt::CborValue::Text(txid));
    const auto phdr = sdcwt::encode_protected_header(
      sdcwt::cose_es_alg_for_curve(key->get_curve_id()),
      {{int64_t{395}, sdcwt::CborValue::Int(vds)},
       {std::string("ccf.v1"), ccf_claims}});

    const auto signature =
      sign_detached(service_key_pem, sdcwt::cose_to_be_signed(phdr, root));

    return cbor::serialize(cbor::make_tagged(
      18,
      cbor::make_array(
        {cbor::make_bytes(phdr),
         cbor::make_map(
           {{cbor::make_signed(396),
             cbor::make_map(
               {{cbor::make_signed(-1),
                 cbor::make_array({cbor::make_bytes(proof)})}})}}),
         cbor::make_simple(cbor::SimpleValue::Null),
         cbor::make_bytes(signature)})));
  }

  struct CnfKey
  {
    bool present = false;
    int64_t kty = 0;
    int64_t crv = 0;
    Bytes x;
    Bytes y;
  };

  // The COSE_Key the payload's cnf claim carries, if it has one.
  CnfKey cnf_cose_key(const Bytes& payload)
  {
    namespace cbor = ccf::cbor;
    CnfKey out;
    const auto root = cbor::parse(payload);
    for (const auto& [label, value] : std::get<cbor::Map>(root->value).items)
    {
      if (
        !std::holds_alternative<cbor::Signed>(label->value) ||
        label->as_signed() != sdcwt::CWT_CNF)
      {
        continue;
      }
      for (const auto& [member, key] : std::get<cbor::Map>(value->value).items)
      {
        if (member->as_signed() != sdcwt::CNF_COSE_KEY)
        {
          continue;
        }
        out.present = true;
        for (const auto& [parameter, entry] :
             std::get<cbor::Map>(key->value).items)
        {
          switch (parameter->as_signed())
          {
            case sdcwt::COSE_KEY_KTY:
              out.kty = entry->as_signed();
              break;
            case sdcwt::COSE_KEY_CRV:
              out.crv = entry->as_signed();
              break;
            case sdcwt::COSE_KEY_X:
              out.x = scitt_sd::testing::copy_bytes(entry);
              break;
            case sdcwt::COSE_KEY_Y:
              out.y = scitt_sd::testing::copy_bytes(entry);
              break;
            default:
              break;
          }
        }
      }
    }
    return out;
  }

  json check_of(const json& document, const std::string& id)
  {
    for (const auto& check : document.at("checks"))
    {
      if (check.at("id") == id)
      {
        return check;
      }
    }
    ADD_FAILURE() << "no check with id '" << id << "'";
    return {};
  }
}

TEST(Keys, GeneratesADistinctUsableKeyEveryTime)
{
  const auto first = generate_private_key();
  const auto second = generate_private_key();
  EXPECT_NE(first, second);

  const ccf::crypto::Pem pem(first);
  const auto key = ccf::crypto::make_ec_key_pair(pem);
  EXPECT_EQ(derive_public_key(first), key->public_key_pem().raw());
}

TEST(Keys, RefusesSomethingThatIsNotAPrivateKey)
{
  EXPECT_THROW((void)derive_public_key(Bytes{'n', 'o', 't'}), InvalidInput);

  // A public key is a PEM document, and still not a private key.
  const auto key = generate_private_key();
  EXPECT_THROW((void)derive_public_key(derive_public_key(key)), InvalidInput);
}

TEST(RootIdentity, DescribesTheCertificateItProduced)
{
  const auto identity = create_root_identity();

  const ccf::crypto::Pem key_pem(identity.private_key);
  const ccf::crypto::Pem cert_pem(identity.certificate);
  const auto key = ccf::crypto::make_ec_key_pair(key_pem);
  const auto der = ccf::crypto::cert_pem_to_der(cert_pem);
  EXPECT_EQ(ccf::crypto::public_key_pem_from_cert(der), key->public_key_pem());

  const auto issuer = json::parse(identity.issuer_json);
  EXPECT_EQ(issuer.at("version"), 1);
  EXPECT_EQ(issuer.at("certificate_subject"), profile::ROOT_SUBJECT);
  EXPECT_EQ(issuer.at("reporter_subject"), profile::REPORTER_SUBJECT);
  EXPECT_EQ(issuer.at("report_subject"), profile::REPORT_SUBJECT);
  EXPECT_EQ(
    issuer.at("ca_fingerprint").get<std::string>(),
    scitt_sd::did_x509_ca_fingerprint(der));
  EXPECT_EQ(issuer.at("issuer_did").get<std::string>(), make_subject_did(der));
  EXPECT_EQ(issuer.at("issuer_did"), identity.issuer_did);
}

TEST(RootIdentity, EveryRootIsDistinct)
{
  const auto first = create_root_identity();
  const auto second = create_root_identity();
  EXPECT_NE(first.private_key, second.private_key);
  EXPECT_NE(first.certificate, second.certificate);
  EXPECT_NE(first.issuer_did, second.issuer_did);
}

TEST(IssueCertificate, EndorsesThePublicKeyItWasGiven)
{
  const auto root = create_root_identity();
  const auto key = generate_private_key();
  const auto public_key = derive_public_key(key);
  const auto leaf =
    issue_certificate(root.private_key, root.certificate, public_key);

  const auto leaf_der = ccf::crypto::cert_pem_to_der(ccf::crypto::Pem(leaf));
  EXPECT_EQ(
    ccf::crypto::public_key_pem_from_cert(leaf_der),
    ccf::crypto::Pem(public_key));

  // The demo CA signed it: the leaf verifies against the root it was issued
  // under.
  const ccf::crypto::Pem root_pem(root.certificate);
  const std::vector<const ccf::crypto::Pem*> trusted{&root_pem};
  const auto verifier = ccf::crypto::make_verifier(leaf_der);
  EXPECT_TRUE(verifier->verify_certificate(trusted, {}, true));
}

TEST(IssueCertificate, RefusesAPrivateKeyInPlaceOfAPublicOne)
{
  const auto root = create_root_identity();
  const auto key = generate_private_key();
  EXPECT_THROW(
    (void)issue_certificate(root.private_key, root.certificate, key),
    InvalidInput);
}

TEST(IssueCertificate, RefusesMalformedMaterial)
{
  const auto root = create_root_identity();
  const auto public_key = derive_public_key(generate_private_key());
  EXPECT_THROW(
    (void)issue_certificate(Bytes{'n', 'o', 't'}, root.certificate, public_key),
    InvalidInput);
  EXPECT_THROW(
    (void)issue_certificate(root.private_key, Bytes{'n', 'o', 't'}, public_key),
    InvalidInput);
}

TEST(IssueStatement, HidesEveryContentClaimAndCommitsToTheDisclosures)
{
  const auto issued = issue_everything();
  EXPECT_FALSE(issued.statement.registered_statement.empty());
  EXPECT_FALSE(issued.statement.disclosure_set.empty());
  EXPECT_EQ(issued.statement.issuer_did, issued.root.issuer_did);
  EXPECT_EQ(issued.statement.body_chunk_count, 2U);
  EXPECT_EQ(issued.statement.reference_count, 2U);
  // The six content claims, the body's two chunks and both references.
  EXPECT_EQ(issued.statement.disclosure_count, 10U);

  // Nothing the report said is in the registered statement: it is what a
  // transparency service sees.
  EXPECT_FALSE(scitt_sd::testing::contains(
    issued.statement.registered_statement, "Heap overflow in parser"));
  EXPECT_FALSE(scitt_sd::testing::contains(
    issued.statement.registered_statement, "Twelve chars"));
}

TEST(IssueStatement, RefusesAKeyTheCertificateDoesNotCertify)
{
  const auto issued = issue_everything();
  const auto other_key = generate_private_key();
  EXPECT_THROW(
    (void)issue_statement(
      report_document(), other_key, issued.leaf_cert, issued.root.certificate),
    InvalidInput);
}

TEST(IssueStatement, RefusesAMalformedReport)
{
  const auto issued = issue_everything();
  EXPECT_THROW(
    (void)issue_statement(
      R"({"title": "only a title"})",
      issued.private_key,
      issued.leaf_cert,
      issued.root.certificate),
    InvalidInput);
}

TEST(Bundle, CarriesTheStatementsVerbatim)
{
  const auto issued = issue_everything();
  const auto encoded = make_bundle(issued);

  const auto statements = extract_statements(encoded);
  EXPECT_EQ(
    statements.registered_statement, issued.statement.registered_statement);
  EXPECT_EQ(statements.transparent_statement, issued.transparent);
  EXPECT_NE(statements.registered_statement, statements.transparent_statement)
    << "the transparent statement carries a receipt the registered one does "
       "not";
}

TEST(Bundle, RefusesADisclosureSetItCannotRead)
{
  const auto issued = issue_everything();
  EXPECT_THROW(
    (void)create_bundle(
      issued.statement.registered_statement,
      issued.transparent,
      Bytes{0x01, 0x02, 0x03},
      "https://transparency.example",
      "2.14"),
    InvalidInput);
}

TEST(Inspect, DescribesEveryDisclosedField)
{
  const auto issued = issue_everything();
  const auto document = json::parse(inspect_bundle(make_bundle(issued)));

  EXPECT_EQ(document.at("chunk_size"), scitt_sd::text::TEXT_CHUNK_SIZE);
  EXPECT_EQ(field_of(document, "title").at("disclosed"), true);
  EXPECT_EQ(field_of(document, "title").at("value"), "Heap overflow in parser");
  EXPECT_EQ(field_of(document, "severity").at("value"), "high");
  EXPECT_EQ(document.at("body").at("disclosed"), true);
  // Twelve code points, in TEXT_CHUNK_SIZE chunks.
  EXPECT_EQ(document.at("body").at("chunks").size(), 2U);
  EXPECT_EQ(document.at("body").at("chunks").at(0).at("text"), "Twelve");
  EXPECT_EQ(document.at("body").at("chunks").at(1).at("text"), " chars");
  EXPECT_EQ(document.at("scitt").at("url"), "https://transparency.example");
  EXPECT_EQ(document.at("scitt").at("txid"), "2.14");
}

TEST(Inspect, RefusesSomethingThatIsNotABundle)
{
  EXPECT_THROW((void)inspect_bundle(Bytes{0x01, 0x02}), InvalidInput);
  EXPECT_THROW((void)extract_statements(Bytes{0x01, 0x02}), InvalidInput);
}

TEST(Present, DropsOnlyTheSelectedDisclosures)
{
  const auto issued = issue_everything();
  const auto encoded = make_bundle(issued);

  const auto presented = present_bundle(
    encoded, R"({"version": 1, "redact_fields": ["title", "body"]})");
  EXPECT_EQ(presented.total, issued.statement.disclosure_count);
  // The title, the body and both chunks the body carried: a chunk without its
  // parent could not be opened.
  EXPECT_EQ(presented.dropped, 4U);

  const auto document = json::parse(inspect_bundle(presented.bundle));
  EXPECT_EQ(field_of(document, "title").at("disclosed"), false);
  EXPECT_EQ(field_of(document, "title").at("value"), nullptr);
  EXPECT_EQ(field_of(document, "severity").at("value"), "high");
  EXPECT_EQ(document.at("body").at("disclosed"), false);
  EXPECT_EQ(document.at("body").at("chunks").size(), 0U);

  // Redaction removes disclosures and nothing else.
  const auto before = extract_statements(encoded);
  const auto after = extract_statements(presented.bundle);
  EXPECT_EQ(before.registered_statement, after.registered_statement);
  EXPECT_EQ(before.transparent_statement, after.transparent_statement);
}

TEST(Present, RefusesASelectionItDoesNotUnderstand)
{
  const auto issued = issue_everything();
  const auto encoded = make_bundle(issued);

  EXPECT_THROW(
    (void)present_bundle(encoded, R"({"version": 2})"), InvalidInput);
  EXPECT_THROW(
    (void)present_bundle(encoded, R"({"redact_fields": ["nonesuch"]})"),
    InvalidInput);
  EXPECT_THROW(
    (void)present_bundle(encoded, R"({"unknown": 1})"), InvalidInput);
  EXPECT_THROW((void)present_bundle(encoded, "not json"), InvalidInput);
}

TEST(Verify, PassesTheFourChecksItOwnsAndSkipsTheReceipt)
{
  const auto issued = issue_everything();
  const auto outcome =
    verify_bundle(make_bundle(issued), issued.root.certificate);

  ASSERT_TRUE(outcome.passed) << outcome.reason;
  EXPECT_TRUE(outcome.reason.empty());

  const auto document = json::parse(outcome.report_json);
  EXPECT_EQ(document.at("overall"), "pass");
  EXPECT_EQ(check_of(document, "statement_binding").at("status"), "pass");
  EXPECT_EQ(check_of(document, "msrc_chain").at("status"), "pass");
  EXPECT_EQ(check_of(document, "issuer_signature").at("status"), "pass");
  EXPECT_EQ(check_of(document, "disclosures").at("status"), "pass");
  EXPECT_EQ(check_of(document, "scitt_receipt").at("status"), "skipped");
}

TEST(Verify, ReportsAFailureRatherThanThrowing)
{
  const auto issued = issue_everything();
  const auto other = create_root_identity();

  // A bundle that is not the one this root anchors.
  const auto outcome = verify_bundle(make_bundle(issued), other.certificate);
  EXPECT_FALSE(outcome.passed);
  EXPECT_FALSE(outcome.reason.empty());

  const auto document = json::parse(outcome.report_json);
  EXPECT_EQ(document.at("overall"), "fail");
  EXPECT_EQ(check_of(document, "msrc_chain").at("status"), "fail");
  EXPECT_EQ(check_of(document, "scitt_receipt").at("status"), "skipped");
}

TEST(Verify, ReportsSomethingThatIsNotABundleAsAFailedCheck)
{
  const auto root = create_root_identity();
  const auto outcome = verify_bundle(Bytes{0x01, 0x02}, root.certificate);
  EXPECT_FALSE(outcome.passed);
  EXPECT_EQ(json::parse(outcome.report_json).at("overall"), "fail");
}

TEST(Verify, RefusesTrustMaterialThatIsNotThere)
{
  const auto issued = issue_everything();
  const auto encoded = make_bundle(issued);
  const std::optional<std::span<const uint8_t>> empty_trust{
    std::span<const uint8_t>{}};
  EXPECT_THROW(
    (void)verify_bundle(encoded, issued.root.certificate, empty_trust),
    InvalidInput);
}

TEST(Limits, RefusesAnOversizedDocumentBeforeParsingIt)
{
  const std::string oversized(limits::MAX_JSON_BYTES + 1, 'x');
  const auto issued = issue_everything();
  EXPECT_THROW(
    (void)issue_statement(
      oversized, issued.private_key, issued.leaf_cert, issued.root.certificate),
    InvalidInput);

  const Bytes long_pem(limits::MAX_PEM_BYTES + 1, 'x');
  EXPECT_THROW((void)derive_public_key(long_pem), InvalidInput);
}

TEST(PrepareStatement, ProducesAStatementTheHolderSignedForItself)
{
  const auto held = hold_a_key();

  const auto prepared = prepare_statement(
    report_document(), held.public_key, held.leaf_cert, held.root.certificate);
  ASSERT_FALSE(prepared.to_be_signed.empty());
  ASSERT_FALSE(prepared.protected_header.empty());
  ASSERT_FALSE(prepared.payload.empty());

  // The detached path has to describe the same issuer as the in-process one.
  const auto signed_here = issue_statement(
    report_document(), held.private_key, held.leaf_cert, held.root.certificate);
  EXPECT_EQ(prepared.issuer_did, signed_here.issuer_did);
  EXPECT_EQ(prepared.body_chunk_count, signed_here.body_chunk_count);
  EXPECT_EQ(prepared.disclosure_count, signed_here.disclosure_count);

  // The holder signs, exactly as a browser would.
  const auto signature = sign_detached(held.private_key, prepared.to_be_signed);
  const auto statement =
    attach_signature(prepared.protected_header, prepared.payload, signature);

  const auto registration =
    mock_register_statement(statement, held.root.private_key);
  const auto bundle = create_bundle(
                        statement,
                        registration.transparent_statement,
                        prepared.disclosure_set,
                        "https://transparency.example",
                        "2.14",
                        1700000100)
                        .bundle;

  const auto outcome = verify_bundle(bundle, held.root.certificate);
  EXPECT_TRUE(outcome.passed) << outcome.reason;
}

TEST(PrepareStatement, RefusesAPublicKeyTheCertificateDoesNotCertify)
{
  const auto held = hold_a_key();
  const auto stranger = derive_public_key(generate_private_key());
  EXPECT_THROW(
    (void)prepare_statement(
      report_document(), stranger, held.leaf_cert, held.root.certificate),
    InvalidInput);
}

TEST(PrepareStatement, PublishesTheDisclosersKeyInTheClearAsCnf)
{
  const auto held = hold_a_key();
  // The discloser's key is its own, not the CA key that endorsed the reporter.
  const auto disclosure_key = generate_private_key();
  const auto disclosure_public = derive_public_key(disclosure_key);

  const auto prepared = prepare_statement(
    report_document(),
    held.public_key,
    held.leaf_cert,
    held.root.certificate,
    disclosure_public);

  const auto cose_key = cnf_cose_key(prepared.payload);
  ASSERT_TRUE(cose_key.present) << "no cnf claim in the payload";

  const auto expected =
    ccf::crypto::make_ec_public_key(ccf::crypto::Pem(disclosure_public))
      ->coordinates();
  EXPECT_EQ(cose_key.kty, sdcwt::COSE_KTY_EC2);
  EXPECT_EQ(cose_key.crv, 1); // P-256
  EXPECT_EQ(cose_key.x, expected.x);
  EXPECT_EQ(cose_key.y, expected.y);
}

TEST(PrepareStatement, OmitsCnfWhenNoDiscloserIsNamed)
{
  const auto held = hold_a_key();
  const auto prepared = prepare_statement(
    report_document(), held.public_key, held.leaf_cert, held.root.certificate);
  EXPECT_FALSE(cnf_cose_key(prepared.payload).present);
}

TEST(PrepareStatement, NamingADiscloserKeepsTheBundleVerifiableAndReadable)
{
  const auto held = hold_a_key();
  const auto disclosure_public = derive_public_key(generate_private_key());

  const auto prepared = prepare_statement(
    report_document(),
    held.public_key,
    held.leaf_cert,
    held.root.certificate,
    disclosure_public);
  const auto statement = attach_signature(
    prepared.protected_header,
    prepared.payload,
    sign_detached(held.private_key, prepared.to_be_signed));
  const auto registration =
    mock_register_statement(statement, held.root.private_key);
  const auto bundle = create_bundle(
                        statement,
                        registration.transparent_statement,
                        prepared.disclosure_set,
                        "https://transparency.example",
                        "2.14",
                        1700000100)
                        .bundle;

  const auto outcome = verify_bundle(bundle, held.root.certificate);
  EXPECT_TRUE(outcome.passed) << outcome.reason;

  // inspect_bundle verifies before it renders, so a cnf claim the verifier
  // refused would surface here rather than in the browser.
  const auto rendered = json::parse(inspect_bundle(bundle));
  EXPECT_EQ(field_of(rendered, "title").at("value"), "Heap overflow in parser");
}

TEST(PrepareStatement, RefusesAConfirmationKeyThatIsNotAPublicKey)
{
  const auto held = hold_a_key();
  EXPECT_THROW(
    (void)prepare_statement(
      report_document(),
      held.public_key,
      held.leaf_cert,
      held.root.certificate,
      generate_private_key()),
    InvalidInput);
}

TEST(AttachSignature, RefusesASignatureThatIsNotRawRS)
{
  const auto held = hold_a_key();
  const auto prepared = prepare_statement(
    report_document(), held.public_key, held.leaf_cert, held.root.certificate);

  // A DER signature is the usual mistake, and it is not 64 bytes.
  EXPECT_THROW(
    (void)attach_signature(
      prepared.protected_header, prepared.payload, Bytes(70, 0x00)),
    InvalidInput);
  EXPECT_THROW(
    (void)attach_signature(
      prepared.protected_header, prepared.payload, Bytes{}),
    InvalidInput);
}

TEST(MockRegisterStatement, AttachesAReceiptWithoutTouchingTheStatement)
{
  const auto issued = issue_everything();
  const auto registration = mock_register_statement(
    issued.statement.registered_statement, issued.root.private_key);

  EXPECT_FALSE(registration.receipt.empty());
  EXPECT_NE(
    registration.transparent_statement, issued.statement.registered_statement);

  // The registered statement has to survive verbatim inside the transparent
  // one, or the receipt would no longer cover what was registered.
  const auto bundle = create_bundle(
                        issued.statement.registered_statement,
                        registration.transparent_statement,
                        issued.statement.disclosure_set,
                        "https://transparency.example",
                        "2.14",
                        1700000100)
                        .bundle;
  const auto outcome = verify_bundle(bundle, issued.root.certificate);
  EXPECT_TRUE(outcome.passed) << outcome.reason;
}

namespace
{
  // A full round trip: a statement naming a discloser, registered, bundled,
  // then presented and signed by that discloser.
  struct Released
  {
    Held held;
    Bytes discloser_key;
    Bytes bundle;
    Bytes release;
  };

  Released release_everything(bool name_a_discloser = true)
  {
    Released out;
    out.held = hold_a_key();
    out.discloser_key = generate_private_key();
    const auto discloser_public = derive_public_key(out.discloser_key);

    const auto prepared = prepare_statement(
      report_document(),
      out.held.public_key,
      out.held.leaf_cert,
      out.held.root.certificate,
      name_a_discloser ? discloser_public : Bytes{});
    const auto statement = attach_signature(
      prepared.protected_header,
      prepared.payload,
      sign_detached(out.held.private_key, prepared.to_be_signed));
    const auto registration =
      mock_register_statement(statement, out.held.root.private_key);
    out.bundle = create_bundle(
                   statement,
                   registration.transparent_statement,
                   prepared.disclosure_set,
                   "https://transparency.example",
                   "2.14",
                   1700000100)
                   .bundle;

    const auto for_signing = prepare_release(out.bundle, discloser_public);
    out.release = attach_signature(
      for_signing.protected_header,
      for_signing.payload,
      sign_detached(out.discloser_key, for_signing.to_be_signed));
    return out;
  }

  json check_status(const std::string& report, const std::string& id)
  {
    return check_of(json::parse(report), id).at("status");
  }
}

TEST(VerifyRelease, PassesWhenTheDiscloserNamedInCnfSignedIt)
{
  const auto released = release_everything();
  const auto outcome =
    verify_release(released.release, released.held.root.certificate);

  EXPECT_TRUE(outcome.passed) << outcome.reason;
  EXPECT_TRUE(outcome.attributable);
  EXPECT_EQ(check_status(outcome.report_json, "release_signature"), "pass");
  EXPECT_EQ(check_status(outcome.report_json, "statement_binding"), "pass");
  EXPECT_EQ(check_status(outcome.report_json, "msrc_chain"), "pass");
  EXPECT_EQ(check_status(outcome.report_json, "issuer_signature"), "pass");
  EXPECT_EQ(check_status(outcome.report_json, "disclosures"), "pass");
  // The receipt is never checked here, however the release verifies.
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "skipped");
}

TEST(VerifyRelease, RefusesAReleaseSignedByAnyoneElse)
{
  auto released = release_everything();
  const auto stranger = generate_private_key();
  const auto for_signing =
    prepare_release(released.bundle, derive_public_key(stranger));
  const auto forged = attach_signature(
    for_signing.protected_header,
    for_signing.payload,
    sign_detached(stranger, for_signing.to_be_signed));

  const auto outcome = verify_release(forged, released.held.root.certificate);
  EXPECT_FALSE(outcome.passed);
  EXPECT_TRUE(outcome.attributable);
  EXPECT_EQ(check_status(outcome.report_json, "release_signature"), "fail");
}

TEST(VerifyRelease, ReportsAStatementWithNoCnfAsUnattributable)
{
  const auto released = release_everything(/*name_a_discloser=*/false);
  const auto outcome =
    verify_release(released.release, released.held.root.certificate);

  // Nothing is wrong with the content; there is simply nobody to attribute
  // the release to, which is not the same as a failed signature.
  EXPECT_FALSE(outcome.attributable);
  EXPECT_EQ(
    check_status(outcome.report_json, "release_signature"), "unattributable");
  EXPECT_TRUE(outcome.passed) << outcome.reason;
}

TEST(VerifyRelease, RefusesAnUntrustedMsrcRoot)
{
  const auto released = release_everything();
  const auto stranger = create_root_identity();
  const auto outcome = verify_release(released.release, stranger.certificate);

  EXPECT_FALSE(outcome.passed);
  EXPECT_EQ(check_status(outcome.report_json, "release_signature"), "pass");
  EXPECT_EQ(check_status(outcome.report_json, "msrc_chain"), "fail");
}

TEST(VerifyRelease, RefusesSomethingThatIsNotARelease)
{
  const auto released = release_everything();
  const auto outcome =
    verify_release(released.bundle, released.held.root.certificate);
  EXPECT_FALSE(outcome.passed);
}

namespace
{
  // A statement naming a discloser, with a real CCF-shaped receipt attached,
  // bundled and then released by that discloser.
  struct Registered
  {
    Held held;
    Bytes discloser_key;
    Bytes statement;
    Bytes disclosures;
    Bytes release;
  };

  Registered register_and_release(
    const Bytes& service_key,
    const std::vector<std::pair<bool, std::vector<uint8_t>>>& path = {})
  {
    Registered out;
    out.held = hold_a_key();
    out.discloser_key = generate_private_key();
    const auto discloser_public = derive_public_key(out.discloser_key);

    const auto prepared = prepare_statement(
      report_document(),
      out.held.public_key,
      out.held.leaf_cert,
      out.held.root.certificate,
      discloser_public);
    out.statement = attach_signature(
      prepared.protected_header,
      prepared.payload,
      sign_detached(out.held.private_key, prepared.to_be_signed));
    out.disclosures = prepared.disclosure_set;

    const auto receipt = ccf_receipt(service_key, out.statement, "2.14", path);
    const auto transparent = sdcwt::set_unprotected_bstr_array(
      out.statement, scitt_sd::label::SCITT_RECEIPTS, {receipt});
    const auto bundle = create_bundle(
                          out.statement,
                          transparent,
                          prepared.disclosure_set,
                          "https://transparency.example",
                          "2.14",
                          1700000100)
                          .bundle;

    const auto for_signing = prepare_release(bundle, discloser_public);
    out.release = attach_signature(
      for_signing.protected_header,
      for_signing.payload,
      sign_detached(out.discloser_key, for_signing.to_be_signed));
    return out;
  }

  // The service identity: a self-signed certificate, as CCF publishes.
  RootIdentity a_transparency_service()
  {
    return create_root_identity();
  }
}

TEST(VerifyRelease, PassesWhenTheStatementIsIncludedInTheLog)
{
  const auto service = a_transparency_service();
  const auto released = register_and_release(service.private_key);

  const std::optional<std::span<const uint8_t>> trusted{service.certificate};
  const auto outcome =
    verify_release(released.release, released.held.root.certificate, trusted);
  EXPECT_TRUE(outcome.passed) << outcome.reason;
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "pass");
}

TEST(VerifyRelease, PassesWithAProofPathOfSeveralSteps)
{
  const auto service = a_transparency_service();
  const std::vector<std::pair<bool, std::vector<uint8_t>>> path = {
    {true, std::vector<uint8_t>(32, 0xA1)},
    {false, std::vector<uint8_t>(32, 0xB2)},
    {true, std::vector<uint8_t>(32, 0xC3)}};
  const auto released = register_and_release(service.private_key, path);

  const std::optional<std::span<const uint8_t>> trusted{service.certificate};
  const auto outcome =
    verify_release(released.release, released.held.root.certificate, trusted);
  EXPECT_TRUE(outcome.passed) << outcome.reason;
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "pass");
}

TEST(VerifyRelease, RefusesAReceiptFromAnotherService)
{
  const auto service = a_transparency_service();
  const auto released = register_and_release(service.private_key);

  const auto stranger = a_transparency_service();
  const std::optional<std::span<const uint8_t>> wrong{stranger.certificate};
  const auto outcome =
    verify_release(released.release, released.held.root.certificate, wrong);
  EXPECT_FALSE(outcome.passed);
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "fail");
}

TEST(VerifyRelease, RefusesAReceiptWhoseProofLeadsElsewhere)
{
  const auto service = a_transparency_service();
  auto released = register_and_release(service.private_key);

  // A receipt for a different statement, signed by the same service: the
  // signature is genuine, but its leaf commits to other bytes.
  const auto elsewhere = register_and_release(service.private_key);
  const auto stolen =
    ccf_receipt(service.private_key, elsewhere.statement, "2.14");
  const auto transparent = sdcwt::set_unprotected_bstr_array(
    released.statement, scitt_sd::label::SCITT_RECEIPTS, {stolen});
  const auto bundle = create_bundle(
                        released.statement,
                        transparent,
                        released.disclosures,
                        "https://transparency.example",
                        "2.14",
                        1700000100)
                        .bundle;

  const std::optional<std::span<const uint8_t>> trusted{service.certificate};
  const auto outcome =
    verify_bundle(bundle, released.held.root.certificate, trusted);
  EXPECT_FALSE(outcome.passed);
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "fail");
}

TEST(VerifyRelease, RefusesAReceiptOverAnUnknownDataStructure)
{
  const auto service = a_transparency_service();
  auto released = register_and_release(service.private_key);

  // Same proof, same signature, but claiming a verifiable data structure this
  // verifier does not implement. Guessing at it would be worse than refusing.
  const auto other = ccf_receipt(
    service.private_key, released.statement, "2.14", {}, /*vds=*/99);
  const auto transparent = sdcwt::set_unprotected_bstr_array(
    released.statement, scitt_sd::label::SCITT_RECEIPTS, {other});
  const auto bundle = create_bundle(
                        released.statement,
                        transparent,
                        released.disclosures,
                        "https://transparency.example",
                        "2.14",
                        1700000100)
                        .bundle;

  const std::optional<std::span<const uint8_t>> trusted{service.certificate};
  const auto outcome =
    verify_bundle(bundle, released.held.root.certificate, trusted);
  EXPECT_FALSE(outcome.passed);
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "fail");
}

TEST(VerifyRelease, LeavesTheReceiptUncheckedWithoutAServiceCertificate)
{
  const auto released = release_everything();
  const auto outcome =
    verify_release(released.release, released.held.root.certificate);
  EXPECT_EQ(check_status(outcome.report_json, "scitt_receipt"), "skipped");
}
