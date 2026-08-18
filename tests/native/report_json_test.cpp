// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The report parser is what stops a caller from silently issuing a statement
// over something other than what it meant to say, so every refusal it makes
// is pinned here.

#include "native/report_json.h"

#include "core/report.h"
#include "native/errors.h"

#include <gtest/gtest.h>
#include <string>

using namespace scitt_sd::native;

namespace
{
  constexpr int64_t ISSUED_AT = 1700000000;

  std::string document(
    const std::string& title = R"("Heap overflow")",
    const std::string& body = R"("Twelve chars")",
    const std::string& component = R"("parser")",
    const std::string& severity = R"("high")",
    const std::string& fingerprint = R"("abc123")",
    const std::string& references = R"(["CVE-2024-0001"])")
  {
    return R"({"title": )" + title + R"(, "body": )" + body +
      R"(, "component": )" + component + R"(, "severity": )" + severity +
      R"(, "fingerprint": )" + fingerprint + R"(, "references": )" +
      references + "}";
  }

  std::string repeated(const std::string& unit, size_t count)
  {
    std::string out;
    out.reserve(unit.size() * count);
    for (size_t i = 0; i < count; ++i)
    {
      out += unit;
    }
    return out;
  }
}

TEST(ReportJson, ParsesEveryField)
{
  const auto input = parse_report_json(document(), ISSUED_AT);
  EXPECT_EQ(input.issued_at, ISSUED_AT);
  EXPECT_EQ(input.title, "Heap overflow");
  EXPECT_EQ(input.body, "Twelve chars");
  EXPECT_EQ(input.component, "parser");
  EXPECT_EQ(input.severity, "high");
  EXPECT_EQ(
    std::string(input.fingerprint.begin(), input.fingerprint.end()), "abc123");
  ASSERT_EQ(input.references.size(), 1U);
  EXPECT_EQ(input.references.at(0), "CVE-2024-0001");
}

TEST(ReportJson, CarriesTheFingerprintAsOpaqueBytes)
{
  // "abc123" is valid hex, and must NOT be decoded: the profile treats a
  // fingerprint as opaque.
  const auto input = parse_report_json(document(), ISSUED_AT);
  EXPECT_EQ(input.fingerprint.size(), 6U);
  EXPECT_EQ(input.fingerprint.at(0), static_cast<uint8_t>('a'));
}

TEST(ReportJson, AcceptsAnEmptyFingerprintAndNoReferences)
{
  const auto input = parse_report_json(
    document(R"("t")", R"("b")", R"("c")", R"("s")", R"("")", "[]"), ISSUED_AT);
  EXPECT_TRUE(input.fingerprint.empty());
  EXPECT_TRUE(input.references.empty());
}

TEST(ReportJson, RefusesMalformedJson)
{
  EXPECT_THROW((void)parse_report_json("{", ISSUED_AT), InvalidInput);
}

TEST(ReportJson, RefusesANonObject)
{
  EXPECT_THROW((void)parse_report_json("[]", ISSUED_AT), InvalidInput);
  EXPECT_THROW((void)parse_report_json("\"text\"", ISSUED_AT), InvalidInput);
  EXPECT_THROW((void)parse_report_json("null", ISSUED_AT), InvalidInput);
}

TEST(ReportJson, RefusesAMissingField)
{
  const std::string missing =
    R"({"title": "t", "body": "b", "component": "c", "severity": "s",)"
    R"( "references": []})";
  try
  {
    (void)parse_report_json(missing, ISSUED_AT);
    FAIL() << "a missing field must be refused";
  }
  catch (const InvalidInput& error)
  {
    EXPECT_NE(std::string(error.what()).find("fingerprint"), std::string::npos);
  }
}

TEST(ReportJson, RefusesAnUnknownField)
{
  const std::string extra =
    R"({"title": "t", "body": "b", "component": "c", "severity": "s",)"
    R"( "fingerprint": "f", "references": [], "extra": 1})";
  try
  {
    (void)parse_report_json(extra, ISSUED_AT);
    FAIL() << "an unknown field must be refused";
  }
  catch (const InvalidInput& error)
  {
    EXPECT_NE(std::string(error.what()).find("extra"), std::string::npos);
  }
}

TEST(ReportJson, RefusesAFieldOfTheWrongType)
{
  EXPECT_THROW(
    (void)parse_report_json(document("42"), ISSUED_AT), InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(document("null"), ISSUED_AT), InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(document(R"("t")", "true"), ISSUED_AT),
    InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("s")", R"("f")", R"("no")"),
      ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesANonStringReference)
{
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("s")", R"("f")", "[1]"),
      ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesAnEmptyRequiredField)
{
  EXPECT_THROW(
    (void)parse_report_json(document(R"("")"), ISSUED_AT), InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(document(R"("t")", R"("")"), ISSUED_AT),
    InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(document(R"("t")", R"("b")", R"("")"), ISSUED_AT),
    InvalidInput);
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("")"), ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesAnEmptyReference)
{
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("s")", R"("f")", R"([""])"),
      ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesAnEmbeddedNul)
{
  const std::string with_nul = std::string(R"({"title": "a)") + '\0' +
    R"(b", "body": "b", "component": "c", "severity": "s",)"
    R"( "fingerprint": "f", "references": []})";
  EXPECT_THROW((void)parse_report_json(with_nul, ISSUED_AT), InvalidInput);
}

TEST(ReportJson, CountsLimitsInCodePointsNotBytes)
{
  // U+00E9 is two bytes and one code point: a title of MAX_TITLE_CHARS of them
  // is accepted, and one more is refused.
  const std::string accent("\xC3\xA9");
  const auto at_limit =
    R"(")" + repeated(accent, report_limits::MAX_TITLE_CHARS) + R"(")";
  const auto over_limit =
    R"(")" + repeated(accent, report_limits::MAX_TITLE_CHARS + 1) + R"(")";

  EXPECT_NO_THROW((void)parse_report_json(document(at_limit), ISSUED_AT));
  EXPECT_THROW(
    (void)parse_report_json(document(over_limit), ISSUED_AT), InvalidInput);
}

TEST(ReportJson, RefusesTooManyReferences)
{
  std::string references = "[";
  for (size_t i = 0; i <= report_limits::MAX_REFERENCES; ++i)
  {
    references += (i == 0 ? "" : ", ");
    references += R"("ref-)" + std::to_string(i) + R"(")";
  }
  references += "]";
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("s")", R"("f")", references),
      ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesAnOverlongReference)
{
  const auto reference =
    R"([")" + repeated("a", report_limits::MAX_REFERENCE_CHARS + 1) + R"("])";
  EXPECT_THROW(
    (void)parse_report_json(
      document(R"("t")", R"("b")", R"("c")", R"("s")", R"("f")", reference),
      ISSUED_AT),
    InvalidInput);
}

TEST(ReportJson, RefusesAnOverlongBody)
{
  const auto body =
    R"(")" + repeated("a", report_limits::MAX_BODY_CHARS + 1) + R"(")";
  EXPECT_THROW(
    (void)parse_report_json(document(R"("t")", body), ISSUED_AT), InvalidInput);
}
