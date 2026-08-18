// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The commands, driven directly rather than through the command line, so that
// what each one writes (and refuses to write) is pinned independently of how
// it is spelled on a command line. Every key and certificate here is produced
// by the commands themselves, through the CCF crypto APIs.

#include "cli/commands.h"

#include "cli/disclosure_set.h"
#include "cli/files.h"
#include "cli/identity.h"
#include "core/bundle.h"
#include "core/profile.h"
#include "core/report.h"
#include "core/text_chunks.h"
#include "core/verify.h"
#include "tests/cli/cli_test_support.h"

#include <algorithm>
#include <ccf/crypto/ec_public_key.h>
#include <ccf/crypto/md_type.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

using namespace scitt_sd::cli;
using namespace scitt_sd::cli::testing;
using nlohmann::json;

namespace
{
  namespace profile_ns = scitt_sd::cli::profile;
  namespace report_ns = scitt_sd::report;
  namespace bundle_ns = scitt_sd::bundle;
  namespace verify_ns = scitt_sd::verify;
  namespace text_ns = scitt_sd::text;

  json read_json(const fs::path& path)
  {
    return json::parse(read_raw(path));
  }

  // The check with this id, whichever position it holds in the report.
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

  fs::perms permissions_of(const fs::path& path)
  {
    return fs::status(path).permissions();
  }

  // Every entry in a directory, so a test can assert that a command produced
  // exactly the files it promised and left no temporary behind.
  std::vector<std::string> entries_of(const fs::path& directory)
  {
    std::vector<std::string> names;
    for (const auto& entry : fs::directory_iterator(directory))
    {
      names.push_back(entry.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    return names;
  }

  // The bundle that `issue_everything` built, decoded.
  bundle_ns::ProofBundle decode_bundle(const fs::path& path)
  {
    return bundle_ns::decode(read_raw_bytes(path));
  }
}

// --- root init ---------------------------------------------------------------

TEST(RootInit, WritesTheKeyCertificateAndIssuerIdentity)
{
  const ScratchDir dir("root_init");
  std::ostringstream out;
  const RootInitArgs args{
    dir / "root.key", dir / "root.pem", dir / "issuer.json"};

  ASSERT_EQ(root_init(args, out), EXIT_OK);
  EXPECT_TRUE(fs::is_regular_file(args.private_key));
  EXPECT_TRUE(fs::is_regular_file(args.certificate));
  EXPECT_TRUE(fs::is_regular_file(args.issuer_json));
  EXPECT_NE(out.str().find(profile_ns::ROOT_SUBJECT), std::string::npos);
}

TEST(RootInit, WritesThePrivateKeyOwnerReadableOnly)
{
  const ScratchDir dir("root_init_perms");
  std::ostringstream out;
  const RootInitArgs args{
    dir / "root.key", dir / "root.pem", dir / "issuer.json"};
  ASSERT_EQ(root_init(args, out), EXIT_OK);

  const auto key_mode = permissions_of(args.private_key);
  EXPECT_EQ(key_mode & fs::perms::group_all, fs::perms::none)
    << "the root private key must not be group readable";
  EXPECT_EQ(key_mode & fs::perms::others_all, fs::perms::none)
    << "the root private key must not be world readable";
  EXPECT_EQ(key_mode & fs::perms::owner_read, fs::perms::owner_read);

  // The certificate is meant to be handed around, so it is not narrowed.
  EXPECT_EQ(
    permissions_of(args.certificate) & fs::perms::owner_read,
    fs::perms::owner_read);
}

TEST(RootInit, ProducesUsableRootArtifacts)
{
  const ScratchDir dir("root_init_usable");
  std::ostringstream out;
  const RootInitArgs args{
    dir / "root.key", dir / "root.pem", dir / "issuer.json"};
  ASSERT_EQ(root_init(args, out), EXIT_OK);

  // The key parses as an EC private key, the certificate as X.509, and the
  // two belong together.
  const ccf::crypto::Pem key_pem(read_raw(args.private_key));
  const ccf::crypto::Pem cert_pem(read_raw(args.certificate));
  const auto key = ccf::crypto::make_ec_key_pair(key_pem);
  const auto der = ccf::crypto::cert_pem_to_der(cert_pem);
  EXPECT_EQ(ccf::crypto::public_key_pem_from_cert(der), key->public_key_pem());

  const auto issuer = read_json(args.issuer_json);
  EXPECT_EQ(issuer.at("version"), 1);
  EXPECT_EQ(issuer.at("certificate_subject"), profile_ns::ROOT_SUBJECT);
  EXPECT_EQ(issuer.at("reporter_subject"), profile_ns::REPORTER_SUBJECT);
  EXPECT_EQ(issuer.at("ca_fingerprint_alg"), "sha256");
  // The identity names the certificate that was actually written.
  EXPECT_EQ(
    issuer.at("ca_fingerprint").get<std::string>(),
    scitt_sd::did_x509_ca_fingerprint(der));
  EXPECT_EQ(issuer.at("issuer_did").get<std::string>(), make_subject_did(der));
  EXPECT_EQ(issuer.at("report_subject"), profile_ns::REPORT_SUBJECT);
}

TEST(RootInit, EveryRootIsDistinct)
{
  const ScratchDir dir("root_init_distinct");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "a.key", dir / "a.pem", dir / "a.json"}, out), EXIT_OK);
  ASSERT_EQ(
    root_init({dir / "b.key", dir / "b.pem", dir / "b.json"}, out), EXIT_OK);
  EXPECT_NE(read_raw(dir / "a.key"), read_raw(dir / "b.key"));
  EXPECT_NE(
    read_json(dir / "a.json").at("issuer_did"),
    read_json(dir / "b.json").at("issuer_did"));
}

TEST(RootInit, RefusesAMissingOutputDirectory)
{
  const ScratchDir dir("root_init_nodir");
  std::ostringstream out;
  EXPECT_THROW(
    (void)root_init(
      {dir / "absent" / "root.key", dir / "root.pem", dir / "issuer.json"},
      out),
    UsageError);
}

// --- key public --------------------------------------------------------------

// --- key generate ------------------------------------------------------------

TEST(KeyGenerate, WritesAUsablePrivateKeyAndNothingElse)
{
  const ScratchDir dir("key_generate");
  std::ostringstream out;
  const KeyGenerateArgs args{dir / "researcher.key"};
  ASSERT_EQ(key_generate(args, out), EXIT_OK);

  const auto pem = read_raw(args.output);
  EXPECT_NE(pem.find("BEGIN PRIVATE KEY"), std::string::npos) << pem;

  // Usable: CCF parses it back and it signs and verifies.
  const auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(pem));
  const std::vector<uint8_t> message = {'s', 'm', 'o', 'k', 'e'};
  const auto signature = key->sign(message, ccf::crypto::MDType::SHA256);
  const auto verifier =
    ccf::crypto::make_ec_public_key(ccf::crypto::Pem(key->public_key_pem()));
  EXPECT_TRUE(verifier->verify(
    message.data(),
    message.size(),
    signature.data(),
    signature.size(),
    ccf::crypto::MDType::SHA256));

  // The command produces a private key and nothing else: no certificate and
  // no public half, because enrolment sends only what `key public` derives.
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"researcher.key"});
}

TEST(KeyGenerate, ThePrivateKeyIsOwnerOnly)
{
  const ScratchDir dir("key_generate_perms");
  std::ostringstream out;
  const KeyGenerateArgs args{dir / "researcher.key"};
  ASSERT_EQ(key_generate(args, out), EXIT_OK);

  const auto mode = permissions_of(args.output);
  EXPECT_EQ(mode & fs::perms::owner_read, fs::perms::owner_read);
  EXPECT_EQ(mode & fs::perms::owner_write, fs::perms::owner_write);
  EXPECT_EQ(mode & fs::perms::group_all, fs::perms::none);
  EXPECT_EQ(mode & fs::perms::others_all, fs::perms::none);
}

TEST(KeyGenerate, ThePrivateKeyIsOwnerOnlyWhateverTheUmask)
{
  const ScratchDir dir("key_generate_umask");
  std::ostringstream out;
  // A permissive umask must not widen a private key.
  const auto previous = ::umask(0);
  ASSERT_EQ(key_generate({dir / "researcher.key"}, out), EXIT_OK);
  (void)::umask(previous);

  EXPECT_EQ(
    permissions_of(dir / "researcher.key") &
      (fs::perms::group_all | fs::perms::others_all),
    fs::perms::none);
}

TEST(KeyGenerate, ProducesAP256Key)
{
  const ScratchDir dir("key_generate_curve");
  std::ostringstream out;
  ASSERT_EQ(key_generate({dir / "researcher.key"}, out), EXIT_OK);

  const auto key = ccf::crypto::make_ec_key_pair(
    ccf::crypto::Pem(read_raw(dir / "researcher.key")));
  // ES256 is the only algorithm the report profile signs with, so a key on
  // any other curve would produce statements nothing in the demo can verify.
  EXPECT_EQ(key->get_curve_id(), ccf::crypto::CurveID::SECP256R1);

  // The same curve `root init` picks, so the two cannot drift apart.
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  const auto root =
    ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(read_raw(dir / "root.key")));
  EXPECT_EQ(key->get_curve_id(), root->get_curve_id());
}

TEST(KeyGenerate, EveryKeyIsDifferent)
{
  const ScratchDir dir("key_generate_distinct");
  std::ostringstream out;
  ASSERT_EQ(key_generate({dir / "first.key"}, out), EXIT_OK);
  ASSERT_EQ(key_generate({dir / "second.key"}, out), EXIT_OK);
  EXPECT_NE(read_raw(dir / "first.key"), read_raw(dir / "second.key"));
}

TEST(KeyGenerate, ReplacesAnExistingKeyAtomicallyAndStaysPrivate)
{
  const ScratchDir dir("key_generate_replace");
  std::ostringstream out;
  const KeyGenerateArgs args{dir / "researcher.key"};
  ASSERT_EQ(key_generate(args, out), EXIT_OK);
  const auto first = read_raw(args.output);

  ASSERT_EQ(key_generate(args, out), EXIT_OK);
  const auto second = read_raw(args.output);

  EXPECT_NE(first, second);
  // Whole-file replacement: no leftover temporary next to the key.
  EXPECT_EQ(entries_of(dir.path()), std::vector<std::string>{"researcher.key"});
  EXPECT_EQ(
    permissions_of(args.output) &
      (fs::perms::group_all | fs::perms::others_all),
    fs::perms::none);
}

TEST(KeyGenerate, RefusesADirectoryThatDoesNotExist)
{
  const ScratchDir dir("key_generate_nodir");
  std::ostringstream out;
  EXPECT_THROW(
    (void)key_generate({dir / "absent" / "researcher.key"}, out), UsageError);
}

TEST(KeyGenerate, TheGeneratedKeyDrivesTheRestOfTheFlow)
{
  const ScratchDir dir("key_generate_flow");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  ASSERT_EQ(key_generate({dir / "reporter.key"}, out), EXIT_OK);
  ASSERT_EQ(
    key_public({dir / "reporter.key", dir / "reporter.pub"}, out), EXIT_OK);
  ASSERT_EQ(
    issue_cert(
      {dir / "root.key",
       dir / "root.pem",
       dir / "reporter.pub",
       dir / "reporter.pem"},
      out),
    EXIT_OK);

  write_raw(dir / "report.json", sample_report_json());
  ASSERT_EQ(
    issue(
      {dir / "report.json",
       dir / "reporter.key",
       dir / "reporter.pem",
       dir / "root.pem",
       dir / "registered.cbor",
       dir / "disclosures.cbor"},
      out),
    EXIT_OK);
  EXPECT_GT(fs::file_size(dir / "registered.cbor"), 0U);
  EXPECT_GT(fs::file_size(dir / "disclosures.cbor"), 0U);
}

TEST(KeyPublic, DerivesThePublicKeyOfAPrivateKey)
{
  const ScratchDir dir("key_public");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);

  const KeyPublicArgs args{dir / "root.key", dir / "root.pub"};
  ASSERT_EQ(key_public(args, out), EXIT_OK);

  const auto derived = read_raw(args.output);
  EXPECT_NE(derived.find("BEGIN PUBLIC KEY"), std::string::npos);
  EXPECT_EQ(derived.find("PRIVATE"), std::string::npos)
    << "the private key must never be written out";

  const auto key =
    ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(read_raw(args.private_key)));
  EXPECT_EQ(derived, key->public_key_pem().str());
}

TEST(KeyPublic, ThePublicKeyIsShareable)
{
  const ScratchDir dir("key_public_perms");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  ASSERT_EQ(key_public({dir / "root.key", dir / "root.pub"}, out), EXIT_OK);
  EXPECT_EQ(
    permissions_of(dir / "root.pub") & fs::perms::owner_read,
    fs::perms::owner_read);
}

TEST(KeyPublic, RefusesSomethingThatIsNotAPrivateKey)
{
  const ScratchDir dir("key_public_bad");
  std::ostringstream out;
  write_raw(dir / "not.key", "-----BEGIN NONSENSE-----\nabc\n");
  EXPECT_THROW(
    (void)key_public({dir / "not.key", dir / "out.pub"}, out), UsageError);
  EXPECT_FALSE(fs::exists(dir / "out.pub"));
}

TEST(KeyPublic, RefusesACertificateInPlaceOfAKey)
{
  const ScratchDir dir("key_public_cert");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  EXPECT_THROW(
    (void)key_public({dir / "root.pem", dir / "out.pub"}, out), UsageError);
}

TEST(KeyPublic, RefusesAMissingFile)
{
  const ScratchDir dir("key_public_missing");
  std::ostringstream out;
  EXPECT_THROW(
    (void)key_public({dir / "absent.key", dir / "out.pub"}, out), UsageError);
}

// --- issue-cert --------------------------------------------------------------

TEST(IssueCert, EndorsesAnEnrolledPublicKey)
{
  const ScratchDir dir("issue_cert");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);

  auto reporter =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  write_raw(dir / "reporter.key", reporter->private_key_pem().str());
  ASSERT_EQ(
    key_public({dir / "reporter.key", dir / "reporter.pub"}, out), EXIT_OK);

  const IssueCertArgs args{
    dir / "root.key",
    dir / "root.pem",
    dir / "reporter.pub",
    dir / "reporter.pem"};
  ASSERT_EQ(issue_cert(args, out), EXIT_OK);

  // The certificate certifies the enrolled key, and nothing else: the CA has
  // only ever seen the public half.
  const auto leaf_der =
    ccf::crypto::cert_pem_to_der(ccf::crypto::Pem(read_raw(args.output)));
  EXPECT_EQ(
    ccf::crypto::public_key_pem_from_cert(leaf_der),
    reporter->public_key_pem());

  const auto verifier = ccf::crypto::make_unique_verifier(leaf_der);
  EXPECT_EQ(verifier->subject(), profile_ns::REPORTER_SUBJECT);
}

TEST(IssueCert, TheCertificateChainsToTheRoot)
{
  const ScratchDir dir("issue_cert_chain");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  auto reporter =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  write_raw(dir / "reporter.key", reporter->private_key_pem().str());
  ASSERT_EQ(
    key_public({dir / "reporter.key", dir / "reporter.pub"}, out), EXIT_OK);
  ASSERT_EQ(
    issue_cert(
      {dir / "root.key",
       dir / "root.pem",
       dir / "reporter.pub",
       dir / "reporter.pem"},
      out),
    EXIT_OK);

  const auto leaf =
    ccf::crypto::make_unique_verifier(ccf::crypto::cert_pem_to_der(
      ccf::crypto::Pem(read_raw(dir / "reporter.pem"))));
  const ccf::crypto::Pem root(read_raw(dir / "root.pem"));
  EXPECT_TRUE(leaf->verify_certificate({&root}));
}

TEST(IssueCert, RefusesAPrivateKeyInPlaceOfAPublicKey)
{
  const ScratchDir dir("issue_cert_private");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);

  // Endorsing a private key would silently leak it into a public artifact.
  EXPECT_THROW(
    (void)issue_cert(
      {dir / "root.key", dir / "root.pem", dir / "root.key", dir / "out.pem"},
      out),
    UsageError);
  EXPECT_FALSE(fs::exists(dir / "out.pem"));
}

TEST(IssueCert, RefusesRubbishInPlaceOfAPublicKey)
{
  const ScratchDir dir("issue_cert_rubbish");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "root.key", dir / "root.pem", dir / "issuer.json"}, out),
    EXIT_OK);
  write_raw(dir / "rubbish.pub", "-----BEGIN PUBLIC KEY-----\nnot base64\n");
  EXPECT_THROW(
    (void)issue_cert(
      {dir / "root.key",
       dir / "root.pem",
       dir / "rubbish.pub",
       dir / "out.pem"},
      out),
    UsageError);
}

TEST(IssueCert, RefusesARootKeyThatDoesNotMatchTheRootCertificate)
{
  const ScratchDir dir("issue_cert_mismatch");
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "a.key", dir / "a.pem", dir / "a.json"}, out), EXIT_OK);
  ASSERT_EQ(
    root_init({dir / "b.key", dir / "b.pem", dir / "b.json"}, out), EXIT_OK);
  ASSERT_EQ(key_public({dir / "a.key", dir / "a.pub"}, out), EXIT_OK);

  EXPECT_THROW(
    (void)issue_cert(
      {dir / "a.key", dir / "b.pem", dir / "a.pub", dir / "out.pem"}, out),
    UsageError);
}

// --- issue -------------------------------------------------------------------

TEST(Issue, WritesAStatementAndItsDisclosures)
{
  const ScratchDir dir("issue");
  const auto files = issue_everything(dir);

  const auto registered = read_raw_bytes(files.registered);
  EXPECT_FALSE(registered.empty());
  // A COSE_Sign1, tagged 18.
  EXPECT_EQ(registered.at(0), 0xD2);

  const auto entries =
    disclosure_set::decode(read_raw_bytes(files.disclosures));
  EXPECT_FALSE(entries.empty());
  for (const auto& entry : entries)
  {
    EXPECT_FALSE(entry.path.empty());
    EXPECT_FALSE(entry.encoded.empty());
  }
}

TEST(Issue, TheRegisteredStatementCarriesNoContentInTheClear)
{
  const ScratchDir dir("issue_opaque");
  const auto files = issue_everything(dir, "A very secret body indeed");
  const auto registered = read_raw_bytes(files.registered);

  // Nothing a reader could recover the report from: the statement is fully
  // redacted, and only the disclosure set reopens it.
  EXPECT_FALSE(
    scitt_sd::testing::contains(registered, "Heap overflow in parser"));
  EXPECT_FALSE(scitt_sd::testing::contains(registered, "A very secret body"));
  EXPECT_FALSE(scitt_sd::testing::contains(registered, "CVE-2024-0001"));
  EXPECT_FALSE(scitt_sd::testing::contains(registered, "abc123"));
  // The subject, which names only the KIND of thing attested, is in the clear.
  EXPECT_TRUE(
    scitt_sd::testing::contains(registered, profile_ns::REPORT_SUBJECT));
}

TEST(Issue, DisclosesEveryFieldAndChunk)
{
  const ScratchDir dir("issue_paths");
  // Two chunks of TEXT_CHUNK_SIZE code points each.
  const std::string body(text_ns::TEXT_CHUNK_SIZE * 2, 'a');
  const auto files = issue_everything(dir, body);

  const auto entries =
    disclosure_set::decode(read_raw_bytes(files.disclosures));
  size_t body_children = 0;
  size_t reference_children = 0;
  bool has_title = false;
  for (const auto& entry : entries)
  {
    const auto* head = std::get_if<int64_t>(&entry.path.front());
    ASSERT_NE(head, nullptr);
    if (*head == report_ns::label::TITLE)
    {
      has_title = true;
    }
    if (*head == report_ns::label::BODY && entry.path.size() == 2)
    {
      ++body_children;
    }
    if (*head == report_ns::label::REFERENCES && entry.path.size() == 2)
    {
      ++reference_children;
    }
  }
  EXPECT_TRUE(has_title);
  EXPECT_EQ(body_children, 2U);
  EXPECT_EQ(reference_children, 2U);
}

TEST(Issue, RefusesAKeyTheCertificateDoesNotCertify)
{
  const ScratchDir dir("issue_wrong_key");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  // Another key, certified by nothing.
  auto other = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  write_raw(dir / "other.key", other->private_key_pem().str());

  try
  {
    (void)issue(
      {files.report_json,
       dir / "other.key",
       files.leaf_cert,
       files.root_cert,
       dir / "out.cbor",
       dir / "out.disclosures"},
      out);
    FAIL() << "signing with an uncertified key must be refused";
  }
  catch (const UsageError& error)
  {
    EXPECT_NE(
      std::string(error.what()).find("does not certify"), std::string::npos);
  }
  EXPECT_FALSE(fs::exists(dir / "out.cbor"));
}

TEST(Issue, RefusesAMalformedReport)
{
  const ScratchDir dir("issue_bad_report");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(files.report_json, R"({"title": "only a title"})");
  EXPECT_THROW(
    (void)issue(
      {files.report_json,
       files.private_key,
       files.leaf_cert,
       files.root_cert,
       dir / "out.cbor",
       dir / "out.disclosures"},
      out),
    UsageError);
}

TEST(Issue, RefusesACertificateThatIsNotACertificate)
{
  const ScratchDir dir("issue_bad_cert");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "bad.pem", "-----BEGIN CERTIFICATE-----\nnope\n");
  EXPECT_THROW(
    (void)issue(
      {files.report_json,
       files.private_key,
       dir / "bad.pem",
       files.root_cert,
       dir / "out.cbor",
       dir / "out.disclosures"},
      out),
    UsageError);
}

TEST(Issue, RefusesAnEmptyReportFile)
{
  const ScratchDir dir("issue_empty_report");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "empty.json", "");
  EXPECT_THROW(
    (void)issue(
      {dir / "empty.json",
       files.private_key,
       files.leaf_cert,
       files.root_cert,
       dir / "out.cbor",
       dir / "out.disclosures"},
      out),
    UsageError);
}

// --- bundle create -----------------------------------------------------------

TEST(BundleCreate, CarriesTheStatementsAndDisclosures)
{
  const ScratchDir dir("bundle_create");
  const auto files = issue_everything(dir);
  const auto proof = decode_bundle(files.bundle);

  EXPECT_EQ(proof.version, bundle_ns::VERSION);
  EXPECT_EQ(proof.registered_statement, read_raw_bytes(files.registered));
  EXPECT_EQ(proof.transparent_statement, read_raw_bytes(files.transparent));
  EXPECT_EQ(proof.scitt_url, "https://transparency.example");
  EXPECT_EQ(proof.txid, "2.14");
  EXPECT_GT(proof.timestamp, 0);
  EXPECT_EQ(
    proof.disclosures.size(),
    disclosure_set::decode(read_raw_bytes(files.disclosures)).size());
}

TEST(BundleCreate, RefusesADisclosureSetItCannotRead)
{
  const ScratchDir dir("bundle_create_bad_set");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "rubbish.cbor", "not cbor at all");
  EXPECT_THROW(
    (void)bundle_create(
      {files.registered,
       files.transparent,
       dir / "rubbish.cbor",
       "https://transparency.example",
       "2.14",
       dir / "out.cbor"},
      out),
    UsageError);
}

TEST(BundleCreate, RefusesAMissingStatement)
{
  const ScratchDir dir("bundle_create_missing");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  EXPECT_THROW(
    (void)bundle_create(
      {dir / "absent.cbor",
       files.transparent,
       files.disclosures,
       "https://transparency.example",
       "2.14",
       dir / "out.cbor"},
      out),
    UsageError);
}

// --- bundle extract ----------------------------------------------------------

TEST(BundleExtract, CopiesTheStatementBytesExactly)
{
  const ScratchDir dir("bundle_extract");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  const BundleExtractArgs args{
    files.bundle, dir / "out-registered.cbor", dir / "out-transparent.cbor"};
  ASSERT_EQ(bundle_extract(args, out), EXIT_OK);

  // Byte for byte: the receipt is bound to these exact bytes, so anything
  // that re-encoded them would silently break the official verifier.
  EXPECT_EQ(read_raw_bytes(args.registered), read_raw_bytes(files.registered));
  EXPECT_EQ(
    read_raw_bytes(args.transparent), read_raw_bytes(files.transparent));
  EXPECT_NE(read_raw_bytes(args.registered), read_raw_bytes(args.transparent))
    << "the transparent statement carries a receipt the registered one does "
       "not";
}

TEST(BundleExtract, ExtractionSurvivesRedaction)
{
  const ScratchDir dir("bundle_extract_presented");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", selection_json({"title", "severity"}, {0}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  ASSERT_EQ(
    bundle_extract(
      {dir / "presented.cbor", dir / "r.cbor", dir / "t.cbor"}, out),
    EXIT_OK);

  // Redaction removes disclosures and nothing else: the registered bytes a
  // receipt is bound to are unchanged.
  EXPECT_EQ(read_raw_bytes(dir / "r.cbor"), read_raw_bytes(files.registered));
  EXPECT_EQ(read_raw_bytes(dir / "t.cbor"), read_raw_bytes(files.transparent));
}

TEST(BundleExtract, RefusesSomethingThatIsNotABundle)
{
  const ScratchDir dir("bundle_extract_bad");
  std::ostringstream out;
  write_raw(dir / "not-a-bundle.cbor", "\x01\x02\x03");
  EXPECT_THROW(
    (void)bundle_extract(
      {dir / "not-a-bundle.cbor", dir / "r.cbor", dir / "t.cbor"}, out),
    UsageError);
  EXPECT_FALSE(fs::exists(dir / "r.cbor"));
}

// --- bundle inspect ----------------------------------------------------------

TEST(BundleInspect, RendersEveryFieldAndChunk)
{
  const ScratchDir dir("bundle_inspect");
  const std::string body(text_ns::TEXT_CHUNK_SIZE * 2, 'x');
  const auto files = issue_everything(dir, body);
  std::ostringstream out;

  ASSERT_EQ(
    bundle_inspect({files.bundle, dir / "inspection.json"}, out), EXIT_OK);
  const auto document = read_json(dir / "inspection.json");

  EXPECT_EQ(document.at("chunk_size"), text_ns::TEXT_CHUNK_SIZE);
  ASSERT_EQ(document.at("fields").size(), 5U);
  EXPECT_EQ(field_of(document, "title").at("value"), "Heap overflow in parser");
  EXPECT_TRUE(field_of(document, "title").at("disclosed"));
  EXPECT_EQ(field_of(document, "component").at("value"), "parser");
  EXPECT_EQ(field_of(document, "severity").at("value"), "high");
  EXPECT_EQ(field_of(document, "fingerprint").at("value"), "abc123");
  EXPECT_EQ(
    field_of(document, "references").at("value"),
    "CVE-2024-0001\ninternal-1234");

  EXPECT_TRUE(document.at("body").at("disclosed"));
  ASSERT_EQ(document.at("body").at("chunks").size(), 2U);
  EXPECT_EQ(document.at("body").at("chunks").at(0).at("index"), 0);
  EXPECT_TRUE(document.at("body").at("chunks").at(0).at("disclosed"));
  EXPECT_EQ(
    document.at("body").at("chunks").at(0).at("text").get<std::string>() +
      document.at("body").at("chunks").at(1).at("text").get<std::string>(),
    body);

  EXPECT_EQ(document.at("scitt").at("url"), "https://transparency.example");
  EXPECT_EQ(document.at("scitt").at("txid"), "2.14");
}

TEST(BundleInspect, SaysWhatItDidNotCheck)
{
  const ScratchDir dir("bundle_inspect_notes");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  ASSERT_EQ(
    bundle_inspect({files.bundle, dir / "inspection.json"}, out), EXIT_OK);

  const auto document = read_json(dir / "inspection.json");
  std::string notes;
  for (const auto& note : document.at("notes"))
  {
    notes += note.get<std::string>() + "\n";
  }
  // Inspection makes no trust decision, and must say so.
  EXPECT_NE(notes.find("No trust anchor"), std::string::npos);
  EXPECT_NE(notes.find("SCITT"), std::string::npos);
}

TEST(BundleInspect, ShowsARedactedFieldAsUndisclosed)
{
  const ScratchDir dir("bundle_inspect_redacted");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(
    dir / "selection.json", selection_json({"severity", "fingerprint"}, {}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  ASSERT_EQ(
    bundle_inspect({dir / "presented.cbor", dir / "inspection.json"}, out),
    EXIT_OK);

  const auto document = read_json(dir / "inspection.json");
  EXPECT_FALSE(field_of(document, "severity").at("disclosed"));
  EXPECT_TRUE(field_of(document, "severity").at("value").is_null());
  EXPECT_FALSE(field_of(document, "fingerprint").at("disclosed"));
  EXPECT_TRUE(field_of(document, "title").at("disclosed"));
}

TEST(BundleInspect, RefusesABundleItCannotDecode)
{
  const ScratchDir dir("bundle_inspect_bad");
  std::ostringstream out;
  write_raw(dir / "bad.cbor", "\xA1\x01");
  EXPECT_THROW(
    (void)bundle_inspect({dir / "bad.cbor", dir / "inspection.json"}, out),
    UsageError);
  EXPECT_FALSE(fs::exists(dir / "inspection.json"));
}

TEST(BundleInspect, RefusesABundleWhoseSignatureDoesNotVerify)
{
  const ScratchDir dir("bundle_inspect_tampered");
  // A second, wholly independent issuance: a shared directory would have the
  // two overwrite each other's artifacts.
  const ScratchDir other_dir("bundle_inspect_tampered_other");
  const auto files = issue_everything(dir);
  const auto other = issue_everything(other_dir, "A completely different body");
  std::ostringstream out;

  // A statement that is not the one the disclosures belong to.
  auto proof = decode_bundle(files.bundle);
  proof.registered_statement = read_raw_bytes(other.registered);
  write_raw_bytes(dir / "mixed.cbor", bundle_ns::encode(proof));

  EXPECT_THROW(
    (void)bundle_inspect({dir / "mixed.cbor", dir / "inspection.json"}, out),
    UsageError);
}

// --- bundle present ----------------------------------------------------------

TEST(BundlePresent, DropsOnlyTheSelectedFields)
{
  const ScratchDir dir("present_fields");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  const auto before = decode_bundle(files.bundle).disclosures.size();
  write_raw(dir / "selection.json", selection_json({"title"}, {}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);

  const auto after = decode_bundle(dir / "presented.cbor");
  EXPECT_EQ(after.disclosures.size(), before - 1);
  EXPECT_NE(out.str().find("dropped 1 of"), std::string::npos);

  // The statements are carried over byte for byte.
  EXPECT_EQ(after.registered_statement, read_raw_bytes(files.registered));
  EXPECT_EQ(after.transparent_statement, read_raw_bytes(files.transparent));
  EXPECT_EQ(after.txid, "2.14");
}

TEST(BundlePresent, DroppingTheBodyDropsItsChunks)
{
  const ScratchDir dir("present_body");
  const std::string body(text_ns::TEXT_CHUNK_SIZE * 3, 'z');
  const auto files = issue_everything(dir, body);
  std::ostringstream out;

  const auto before = decode_bundle(files.bundle).disclosures.size();
  write_raw(dir / "selection.json", selection_json({"body"}, {}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);

  // The body claim and all three of its chunks: a chunk without its parent
  // could not be opened, so leaving one in would make the bundle unreadable.
  EXPECT_EQ(
    decode_bundle(dir / "presented.cbor").disclosures.size(), before - 4);

  ASSERT_EQ(
    bundle_inspect({dir / "presented.cbor", dir / "inspection.json"}, out),
    EXIT_OK);
  const auto document = read_json(dir / "inspection.json");
  EXPECT_FALSE(document.at("body").at("disclosed"));
  EXPECT_TRUE(document.at("body").at("chunks").empty())
    << "a hidden body hides how long it is too";
}

TEST(BundlePresent, DropsIndividualBodyChunks)
{
  const ScratchDir dir("present_chunks");
  const std::string body(text_ns::TEXT_CHUNK_SIZE * 3, 'q');
  const auto files = issue_everything(dir, body);
  std::ostringstream out;

  write_raw(dir / "selection.json", selection_json({}, {1}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  ASSERT_EQ(
    bundle_inspect({dir / "presented.cbor", dir / "inspection.json"}, out),
    EXIT_OK);

  const auto document = read_json(dir / "inspection.json");
  EXPECT_TRUE(document.at("body").at("disclosed"));
  ASSERT_EQ(document.at("body").at("chunks").size(), 3U);
  EXPECT_TRUE(document.at("body").at("chunks").at(0).at("disclosed"));
  EXPECT_FALSE(document.at("body").at("chunks").at(1).at("disclosed"));
  EXPECT_EQ(document.at("body").at("chunks").at(1).at("text"), "");
  EXPECT_TRUE(document.at("body").at("chunks").at(2).at("disclosed"));
}

TEST(BundlePresent, IsCumulative)
{
  const ScratchDir dir("present_twice");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "first.json", selection_json({"title"}, {}));
  ASSERT_EQ(
    bundle_present({files.bundle, dir / "first.json", dir / "one.cbor"}, out),
    EXIT_OK);
  write_raw(dir / "second.json", selection_json({"severity"}, {}));
  ASSERT_EQ(
    bundle_present(
      {dir / "one.cbor", dir / "second.json", dir / "two.cbor"}, out),
    EXIT_OK);
  ASSERT_EQ(
    bundle_inspect({dir / "two.cbor", dir / "inspection.json"}, out), EXIT_OK);

  const auto document = read_json(dir / "inspection.json");
  EXPECT_FALSE(field_of(document, "title").at("disclosed"));
  EXPECT_FALSE(field_of(document, "severity").at("disclosed"));
  EXPECT_TRUE(field_of(document, "component").at("disclosed"));
}

TEST(BundlePresent, AnEmptySelectionChangesNothing)
{
  const ScratchDir dir("present_nothing");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", R"({"version": 1})");
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  EXPECT_EQ(
    decode_bundle(dir / "presented.cbor").disclosures,
    decode_bundle(files.bundle).disclosures);
}

TEST(BundlePresent, RefusesAnUnknownFieldName)
{
  const ScratchDir dir("present_unknown_field");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", selection_json({"not_a_field"}, {}));
  try
  {
    (void)bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out);
    FAIL() << "an unknown field name must be refused";
  }
  catch (const UsageError& error)
  {
    EXPECT_NE(std::string(error.what()).find("not_a_field"), std::string::npos);
  }
  EXPECT_FALSE(fs::exists(dir / "presented.cbor"));
}

TEST(BundlePresent, RefusesAnUnknownSelectionMember)
{
  const ScratchDir dir("present_unknown_member");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", R"({"version": 1, "reveal": ["title"]})");
  EXPECT_THROW(
    (void)bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    UsageError);
}

TEST(BundlePresent, RefusesAnUnsupportedSelectionVersion)
{
  const ScratchDir dir("present_version");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", R"({"version": 2})");
  EXPECT_THROW(
    (void)bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    UsageError);
}

TEST(BundlePresent, RefusesSelectionsOfTheWrongShape)
{
  const ScratchDir dir("present_shapes");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  const std::vector<std::string> bad = {
    R"({"redact_fields": "title"})",
    R"({"redact_fields": [1]})",
    R"({"redact_body_chunks": 1})",
    R"({"redact_body_chunks": [-1]})",
    R"({"redact_body_chunks": ["0"]})",
    R"([])",
    R"(not json)"};
  for (const auto& selection : bad)
  {
    write_raw(dir / "selection.json", selection);
    EXPECT_THROW(
      (void)bundle_present(
        {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
      UsageError)
      << "accepted: " << selection;
  }
}

TEST(BundlePresent, IgnoresAChunkIndexTheReportDoesNotHave)
{
  const ScratchDir dir("present_absent_chunk");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", selection_json({}, {999}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  EXPECT_EQ(
    decode_bundle(dir / "presented.cbor").disclosures.size(),
    decode_bundle(files.bundle).disclosures.size());
}

TEST(BundlePresent, RefusesABundleItCannotDecode)
{
  const ScratchDir dir("present_bad_bundle");
  std::ostringstream out;
  write_raw(dir / "bad.cbor", "\x01\x02\x03");
  write_raw(dir / "selection.json", selection_json({"title"}, {}));
  EXPECT_THROW(
    (void)bundle_present(
      {dir / "bad.cbor", dir / "selection.json", dir / "presented.cbor"}, out),
    UsageError);
}

// --- verify ------------------------------------------------------------------

TEST(Verify, ReportsFourOwnedChecksAndSkipsTheReceipt)
{
  const ScratchDir dir("verify_pass");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  const VerifyArgs args{
    files.bundle, files.root_cert, dir / "verification.json", std::nullopt};
  ASSERT_EQ(verify(args, out), EXIT_OK);

  const auto document = read_json(args.json_output);
  EXPECT_EQ(document.at("overall"), "pass");
  ASSERT_EQ(document.at("checks").size(), 5U);

  for (const auto& id :
       {"statement_binding", "msrc_chain", "issuer_signature", "disclosures"})
  {
    const auto check = check_of(document, id);
    EXPECT_EQ(check.at("status"), "pass") << id;
    EXPECT_FALSE(check.at("detail").get<std::string>().empty()) << id;
    EXPECT_FALSE(check.at("label").get<std::string>().empty()) << id;
  }

  // The receipt is the official verifier's job, always.
  const auto receipt = check_of(document, "scitt_receipt");
  EXPECT_EQ(receipt.at("status"), "skipped");
  EXPECT_NE(
    receipt.at("detail").get<std::string>().find("official SCITT verifier"),
    std::string::npos);
}

TEST(Verify, TheChecksAreReportedInTheOrderTheyArePerformed)
{
  const ScratchDir dir("verify_order");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  ASSERT_EQ(
    verify(
      {files.bundle, files.root_cert, dir / "verification.json", std::nullopt},
      out),
    EXIT_OK);

  const auto document = read_json(dir / "verification.json");
  const std::vector<std::string> expected = {
    "statement_binding",
    "msrc_chain",
    "issuer_signature",
    "disclosures",
    "scitt_receipt"};
  std::vector<std::string> actual;
  for (const auto& check : document.at("checks"))
  {
    actual.push_back(check.at("id").get<std::string>());
  }
  EXPECT_EQ(actual, expected);
}

TEST(Verify, NamesTheIssuerAndSubjectInItsNotes)
{
  const ScratchDir dir("verify_notes");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  ASSERT_EQ(
    verify(
      {files.bundle, files.root_cert, dir / "verification.json", std::nullopt},
      out),
    EXIT_OK);

  const auto document = read_json(dir / "verification.json");
  std::string notes;
  for (const auto& note : document.at("notes"))
  {
    notes += note.get<std::string>() + "\n";
  }
  EXPECT_NE(notes.find("did:x509:0:sha256:"), std::string::npos);
  EXPECT_NE(notes.find(profile_ns::REPORT_SUBJECT), std::string::npos);
  EXPECT_NE(notes.find("SCITT receipt was not verified"), std::string::npos);
}

TEST(Verify, PassesOnARedactedBundle)
{
  const ScratchDir dir("verify_redacted");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  write_raw(dir / "selection.json", selection_json({"title", "body"}, {}));
  ASSERT_EQ(
    bundle_present(
      {files.bundle, dir / "selection.json", dir / "presented.cbor"}, out),
    EXIT_OK);
  ASSERT_EQ(
    verify(
      {dir / "presented.cbor",
       files.root_cert,
       dir / "verification.json",
       std::nullopt},
      out),
    EXIT_OK);
  EXPECT_EQ(read_json(dir / "verification.json").at("overall"), "pass");
}

TEST(Verify, FailsAgainstADifferentRoot)
{
  const ScratchDir dir("verify_other_root");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  ASSERT_EQ(
    root_init({dir / "other.key", dir / "other.pem", dir / "other.json"}, out),
    EXIT_OK);

  const VerifyArgs args{
    files.bundle, dir / "other.pem", dir / "verification.json", std::nullopt};
  EXPECT_EQ(verify(args, out), EXIT_VERIFICATION_FAILED);

  // A failed verification always comes with a report.
  const auto document = read_json(args.json_output);
  EXPECT_EQ(document.at("overall"), "fail");
  EXPECT_EQ(check_of(document, "msrc_chain").at("status"), "fail");
  EXPECT_EQ(check_of(document, "statement_binding").at("status"), "pass");
  // Nothing after the failure is claimed to have been checked.
  EXPECT_EQ(check_of(document, "issuer_signature").at("status"), "skipped");
  EXPECT_EQ(check_of(document, "disclosures").at("status"), "skipped");
  EXPECT_EQ(check_of(document, "scitt_receipt").at("status"), "skipped");
}

TEST(Verify, FailsWhenTheTransparentStatementIsNotTheRegisteredOne)
{
  const ScratchDir dir("verify_binding");
  const ScratchDir other_dir("verify_binding_other");
  const auto files = issue_everything(dir);
  const auto other = issue_everything(other_dir, "A different report body");
  std::ostringstream out;

  auto proof = decode_bundle(files.bundle);
  proof.transparent_statement = read_raw_bytes(other.transparent);
  write_raw_bytes(dir / "mixed.cbor", bundle_ns::encode(proof));

  const VerifyArgs args{
    dir / "mixed.cbor",
    files.root_cert,
    dir / "verification.json",
    std::nullopt};
  EXPECT_EQ(verify(args, out), EXIT_VERIFICATION_FAILED);

  const auto document = read_json(args.json_output);
  EXPECT_EQ(document.at("overall"), "fail");
  EXPECT_EQ(check_of(document, "statement_binding").at("status"), "fail");
  EXPECT_EQ(check_of(document, "msrc_chain").at("status"), "skipped");
}

TEST(Verify, ReportsABundleItCannotDecodeAsAFailedCheck)
{
  const ScratchDir dir("verify_bad_bundle");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  write_raw(dir / "bad.cbor", "\x01\x02\x03");

  const VerifyArgs args{
    dir / "bad.cbor", files.root_cert, dir / "verification.json", std::nullopt};
  EXPECT_EQ(verify(args, out), EXIT_VERIFICATION_FAILED);
  EXPECT_EQ(read_json(args.json_output).at("overall"), "fail");
  EXPECT_EQ(
    check_of(read_json(args.json_output), "scitt_receipt").at("status"),
    "skipped");
}

TEST(Verify, ReportsAnUnusableRootAsAFailedChainCheck)
{
  const ScratchDir dir("verify_bad_root");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  write_raw(dir / "root-nonsense.pem", "not a pem at all");

  const VerifyArgs args{
    files.bundle,
    dir / "root-nonsense.pem",
    dir / "verification.json",
    std::nullopt};
  EXPECT_EQ(verify(args, out), EXIT_VERIFICATION_FAILED);
  EXPECT_EQ(
    check_of(read_json(args.json_output), "msrc_chain").at("status"), "fail");
}

TEST(Verify, RefusesAMissingBundleRatherThanReportingAFailure)
{
  const ScratchDir dir("verify_missing_bundle");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  // A usage error is never a statement about a bundle's trustworthiness, so
  // no report is written.
  EXPECT_THROW(
    (void)verify(
      {dir / "absent.cbor",
       files.root_cert,
       dir / "verification.json",
       std::nullopt},
      out),
    UsageError);
  EXPECT_FALSE(fs::exists(dir / "verification.json"));
}

TEST(Verify, RefusesAMissingMsrcRoot)
{
  const ScratchDir dir("verify_missing_root");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  EXPECT_THROW(
    (void)verify(
      {files.bundle,
       dir / "absent.pem",
       dir / "verification.json",
       std::nullopt},
      out),
    UsageError);
}

TEST(Verify, RefusesScittTrustMaterialThatIsNotThere)
{
  const ScratchDir dir("verify_scitt_trust");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  // Accepted for compatibility and deliberately not parsed, so a caller that
  // believes it supplied trust material is told when it did not.
  EXPECT_THROW(
    (void)verify(
      {files.bundle,
       files.root_cert,
       dir / "verification.json",
       dir / "absent.pem"},
      out),
    UsageError);

  write_raw(dir / "empty.pem", "");
  EXPECT_THROW(
    (void)verify(
      {files.bundle,
       files.root_cert,
       dir / "verification.json",
       dir / "empty.pem"},
      out),
    UsageError);
}

TEST(Verify, AcceptsScittTrustMaterialWithoutCheckingAnyReceipt)
{
  const ScratchDir dir("verify_scitt_trust_ok");
  const auto files = issue_everything(dir);
  std::ostringstream out;
  write_raw(dir / "scitt.pem", "anything at all, this is never parsed");

  ASSERT_EQ(
    verify(
      {files.bundle,
       files.root_cert,
       dir / "verification.json",
       dir / "scitt.pem"},
      out),
    EXIT_OK);
  // Supplying trust material does not turn the receipt check on.
  EXPECT_EQ(
    check_of(read_json(dir / "verification.json"), "scitt_receipt")
      .at("status"),
    "skipped");
}

TEST(Verify, AcceptsADirectoryOfScittTrustMaterial)
{
  const ScratchDir dir("verify_scitt_trust_dir");
  const auto files = issue_everything(dir);
  std::ostringstream out;

  fs::create_directories(dir / "trust");
  EXPECT_THROW(
    (void)verify(
      {files.bundle, files.root_cert, dir / "verification.json", dir / "trust"},
      out),
    UsageError)
    << "an empty directory carries no trust material";

  write_raw(dir / "trust" / "service.pem", "anything");
  EXPECT_EQ(
    verify(
      {files.bundle, files.root_cert, dir / "verification.json", dir / "trust"},
      out),
    EXIT_OK);
}
