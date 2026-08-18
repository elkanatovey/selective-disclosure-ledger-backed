// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/report.h"

#include "core/report_internal.h"
#include "tests/core/test_support.h"

#include <gtest/gtest.h>
#include <set>
#include <stdexcept>

using namespace scitt_sd;
using namespace scitt_sd::testing;

namespace
{
  struct IssuedFixture
  {
    Chain chain;
    IssuerIdentity issuer;
    report::IssuedReport issued;
  };

  IssuedFixture issue_sample(report::ReportInput input = sample_report())
  {
    IssuedFixture fixture;
    fixture.chain = make_ccf_chain();
    fixture.issuer = {
      make_did_x509(fixture.chain.root_der),
      "bug-report",
      fixture.chain.x5chain()};
    fixture.issued =
      report::issue(input, fixture.issuer, *fixture.chain.leaf_key);
    return fixture;
  }

  TEST(Report, LabelsAndFieldNames)
  {
    EXPECT_EQ(report::label::IAT, 6);
    EXPECT_EQ(report::label::TITLE, 1001);
    EXPECT_EQ(report::label::BODY, 1002);
    EXPECT_EQ(report::label::COMPONENT, 1003);
    EXPECT_EQ(report::label::SEVERITY, 1004);
    EXPECT_EQ(report::label::FINGERPRINT, 1005);
    EXPECT_EQ(report::label::REFERENCES, 1006);
    EXPECT_EQ(report::CONTENT_LABELS.size(), 6U);

    EXPECT_EQ(report::field_name(report::label::TITLE), "title");
    EXPECT_EQ(report::field_name(report::label::REFERENCES), "references");
    EXPECT_TRUE(report::field_name(9999).empty());

    EXPECT_EQ(report::describe_path({int64_t{1002}}), "body");
    EXPECT_EQ(report::describe_path({int64_t{1002}, int64_t{3}}), "body[3]");
    EXPECT_EQ(report::describe_path({}), "decoy");
  }

  // The whole point of the profile: nothing but `iat` is readable from a
  // registered statement.
  TEST(Report, EveryContentClaimIsRedacted)
  {
    const auto fixture = issue_sample();

    EXPECT_FALSE(contains(fixture.issued.statement, "Heap overflow in parser"));
    EXPECT_FALSE(contains(fixture.issued.statement, "Twelve chars"));
    EXPECT_FALSE(contains(fixture.issued.statement, "parser"));
    EXPECT_FALSE(contains(fixture.issued.statement, "high"));
    EXPECT_FALSE(contains(fixture.issued.statement, "CVE-2024-0001"));
    EXPECT_FALSE(contains(fixture.issued.statement, "internal-1234"));
    const std::vector<uint8_t> fingerprint = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_FALSE(contains(fixture.issued.statement, fingerprint));

    // A registered statement carries no disclosures at all.
    EXPECT_TRUE(
      unprotected_bstr_array(fixture.issued.statement, label::SD_CLAIMS)
        .empty());
  }

  // One disclosure per content claim, per body chunk and per reference.
  TEST(Report, DisclosureSetCoversEveryClaimChunkAndElement)
  {
    const auto fixture = issue_sample();
    EXPECT_EQ(fixture.issued.body_chunk_count, 2U); // "Twelve chars" = 12 cp
    EXPECT_EQ(fixture.issued.reference_count, 2U);
    EXPECT_EQ(fixture.issued.disclosures.size(), 6U + 2U + 2U);

    std::set<std::string> described;
    for (const auto& disclosure : fixture.issued.disclosures)
    {
      described.insert(report::describe_path(disclosure.path));
    }
    const std::set<std::string> expected = {
      "title",
      "body",
      "body[0]",
      "body[1]",
      "component",
      "severity",
      "fingerprint",
      "references",
      "references[0]",
      "references[1]"};
    EXPECT_EQ(described, expected);
  }

  // Body chunk indices are stable map keys, so a disclosed chunk always says
  // where it belongs and a gap in a partial disclosure is unambiguous.
  TEST(Report, BodyChunksUseStableMapIndices)
  {
    auto input = sample_report();
    input.body = "abcdefghijklmnopq"; // 17 code points -> 3 chunks
    const auto fixture = issue_sample(input);
    ASSERT_EQ(fixture.issued.body_chunk_count, 3U);

    for (const auto& disclosure : fixture.issued.disclosures)
    {
      if (
        disclosure.path.size() == 2 &&
        std::get<int64_t>(disclosure.path[0]) == report::label::BODY)
      {
        const auto index = std::get<int64_t>(disclosure.path[1]);
        // A body chunk is [salt, value, key]: its key is its index.
        EXPECT_EQ(disclosure.encoded[0], 0x83);
        const std::string expected_text =
          index == 0 ? "abcdef" : (index == 1 ? "ghijkl" : "mnopq");
        EXPECT_TRUE(contains(disclosure.encoded, expected_text));
      }
    }
  }

  TEST(Report, EmptyBodyStillHasOneChunk)
  {
    auto input = sample_report();
    input.body = "";
    const auto fixture = issue_sample(input);
    EXPECT_EQ(fixture.issued.body_chunk_count, 1U);
  }

  TEST(Report, MalformedInputRejected)
  {
    const auto chain = make_ccf_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    auto bad_utf8 = sample_report();
    bad_utf8.body = std::string("\xC3\x28");
    EXPECT_THROW(
      report::issue(bad_utf8, issuer, *chain.leaf_key), std::invalid_argument);

    auto negative = sample_report();
    negative.issued_at = -1;
    EXPECT_THROW(
      report::issue(negative, issuer, *chain.leaf_key), std::invalid_argument);

    const IssuerIdentity bad_issuer{"not-a-did", "sub", chain.x5chain()};
    EXPECT_THROW(
      report::issue(sample_report(), bad_issuer, *chain.leaf_key),
      std::invalid_argument);
  }

  // Selecting a child pulls in its parent: without the parent's disclosure a
  // verifier cannot resolve the child's commitment at all.
  TEST(Report, SelectionAddsAncestors)
  {
    const auto fixture = issue_sample();

    const auto only_chunk =
      report::select_disclosures(fixture.issued, {{}, {1}, {}});
    ASSERT_EQ(only_chunk.size(), 2U); // body, body[1]

    const auto find = [&](const sdcwt::Path& path) {
      for (const auto& disclosure : fixture.issued.disclosures)
      {
        if (disclosure.path == path)
        {
          return disclosure.encoded;
        }
      }
      ADD_FAILURE() << "missing disclosure";
      return std::vector<uint8_t>{};
    };
    // Parent before child, so a verifier can resolve them in order.
    EXPECT_EQ(only_chunk[0], find({int64_t{report::label::BODY}}));
    EXPECT_EQ(only_chunk[1], find({int64_t{report::label::BODY}, int64_t{1}}));

    const auto reference =
      report::select_disclosures(fixture.issued, {{}, {}, {0}});
    ASSERT_EQ(reference.size(), 2U);
    EXPECT_EQ(reference[0], find({int64_t{report::label::REFERENCES}}));
  }

  TEST(Report, SelectionIsDeduplicatedAndOrdered)
  {
    const auto fixture = issue_sample();
    const auto selected = report::select_disclosures(
      fixture.issued,
      {{report::label::BODY, report::label::TITLE}, {0, 1, 0}, {}});
    // title, body, body[0], body[1]: the body claim appears once.
    EXPECT_EQ(selected.size(), 4U);

    const auto by_field = report::select_disclosures(
      fixture.issued, {{report::label::TITLE}, {}, {}});
    ASSERT_EQ(by_field.size(), 1U);
    EXPECT_TRUE(contains(by_field[0], "Heap overflow in parser"));
  }

  TEST(Report, SelectionRejectsUnknownAndOutOfRange)
  {
    const auto fixture = issue_sample();
    EXPECT_THROW(
      report::select_disclosures(
        fixture.issued, {{report::label::IAT}, {}, {}}),
      std::invalid_argument);
    EXPECT_THROW(
      report::select_disclosures(fixture.issued, {{9999}, {}, {}}),
      std::invalid_argument);
    EXPECT_THROW(
      report::select_disclosures(fixture.issued, {{}, {99}, {}}),
      std::out_of_range);
    EXPECT_THROW(
      report::select_disclosures(fixture.issued, {{}, {}, {99}}),
      std::out_of_range);
  }

  // A receipt (394) must survive every disclosure (17) edit: presenting is not
  // allowed to strip the proof of registration.
  TEST(Report, PresentPreservesReceiptsAcrossDisclosureEdits)
  {
    const auto fixture = issue_sample();
    const std::vector<uint8_t> receipt = {0x52, 0x43, 0x50, 0x54};
    const auto transparent =
      attach_receipts(fixture.issued.statement, {receipt});

    const auto first = report::present(
      transparent,
      report::select_disclosures(
        fixture.issued, {{report::label::TITLE}, {}, {}}));
    const auto second = report::present(
      first,
      report::select_disclosures(
        fixture.issued, {{report::label::SEVERITY}, {}, {}}));
    const auto none = report::present(second, {});

    for (const auto& presentation : {first, second, none})
    {
      const auto receipts =
        unprotected_bstr_array(presentation, label::SCITT_RECEIPTS);
      ASSERT_EQ(receipts.size(), 1U);
      EXPECT_EQ(receipts[0], receipt);
    }

    // The selection is replaced, never accumulated.
    EXPECT_EQ(unprotected_bstr_array(first, label::SD_CLAIMS).size(), 1U);
    EXPECT_TRUE(contains(first, "Heap overflow in parser"));
    EXPECT_FALSE(contains(second, "Heap overflow in parser"));
    EXPECT_TRUE(contains(second, "high"));
    EXPECT_TRUE(unprotected_bstr_array(none, label::SD_CLAIMS).empty());

    // And the signed parts never move.
    const auto signed_parts = parse_sign1(fixture.issued.statement);
    for (const auto& presentation : {transparent, first, second, none})
    {
      const auto parts = parse_sign1(presentation);
      EXPECT_EQ(parts.protected_header, signed_parts.protected_header);
      EXPECT_EQ(parts.payload, signed_parts.payload);
      EXPECT_EQ(parts.signature, signed_parts.signature);
    }
  }

  // Issuance is reproducible when the randomness is injected, which is what
  // makes a disclosure's bytes a stable function of the report.
  TEST(Report, InjectedRandomSourceMakesIssuanceReproducible)
  {
    const auto chain = make_ccf_chain();
    const IssuerIdentity issuer{
      make_did_x509(chain.root_der), "bug-report", chain.x5chain()};

    const auto first = report::detail::issue(
      sample_report(),
      issuer,
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      counting_random_source(1));
    const auto second = report::detail::issue(
      sample_report(),
      issuer,
      *chain.leaf_key,
      sdcwt::HashAlg::SHA_256,
      counting_random_source(1));

    ASSERT_EQ(first.disclosures.size(), second.disclosures.size());
    for (size_t i = 0; i < first.disclosures.size(); ++i)
    {
      EXPECT_EQ(first.disclosures[i].path, second.disclosures[i].path);
      EXPECT_EQ(first.disclosures[i].encoded, second.disclosures[i].encoded);
    }
    EXPECT_EQ(
      parse_sign1(first.statement).payload,
      parse_sign1(second.statement).payload);

    // Distinct salts across the whole report, even under a counting source.
    std::set<std::vector<uint8_t>> salts;
    for (const auto& disclosure : first.disclosures)
    {
      EXPECT_EQ(disclosure.salt.size(), sdcwt::SALT_LEN);
      EXPECT_TRUE(salts.insert(disclosure.salt).second) << "salt reused";
    }
  }
}
