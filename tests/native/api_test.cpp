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

#include "core/profile.h"
#include "core/text_chunks.h"
#include "native/identity.h"
#include "tests/core/test_support.h"

#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/hash_provider.h>
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
