// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "native/report_json.h"

#include "core/text_chunks.h"
#include "native/errors.h"

#include <algorithm>
#include <array>
#include <nlohmann/json.hpp>

namespace scitt_sd::native
{
  namespace
  {
    using nlohmann::json;

    constexpr std::array<std::string_view, 6> MEMBERS = {
      "title", "body", "component", "severity", "fingerprint", "references"};

    const json& member(const json& document, std::string_view name)
    {
      const auto it = document.find(name);
      if (it == document.end())
      {
        throw InvalidInput(
          "the report is missing the '" + std::string(name) + "' field");
      }
      return *it;
    }

    // A text field, checked for shape and size before anything is issued over
    // it. `max_chars` counts code points: a report is chunked by code point,
    // so that is the unit a limit has to be expressed in.
    std::string text_field(
      const json& document,
      std::string_view name,
      size_t max_chars,
      bool required)
    {
      const auto& value = member(document, name);
      if (!value.is_string())
      {
        throw InvalidInput(
          "the report field '" + std::string(name) + "' must be a string");
      }
      auto text = value.get<std::string>();
      if (text.find('\0') != std::string::npos)
      {
        throw InvalidInput(
          "the report field '" + std::string(name) +
          "' contains a NUL character");
      }
      size_t chars = 0;
      try
      {
        chars = text::count_code_points(text);
      }
      catch (const std::exception&)
      {
        throw InvalidInput(
          "the report field '" + std::string(name) +
          "' is not well-formed UTF-8");
      }
      if (required && chars == 0)
      {
        throw InvalidInput(
          "the report field '" + std::string(name) + "' must not be empty");
      }
      if (chars > max_chars)
      {
        throw InvalidInput(
          "the report field '" + std::string(name) + "' is longer than " +
          std::to_string(max_chars) + " characters");
      }
      return text;
    }
  }

  report::ReportInput parse_report_json(
    std::string_view document, int64_t issued_at)
  {
    json parsed;
    try
    {
      parsed = json::parse(document);
    }
    catch (const json::exception& e)
    {
      throw InvalidInput(
        std::string("the report is not valid JSON: ") + e.what());
    }
    if (!parsed.is_object())
    {
      throw InvalidInput("the report must be a JSON object");
    }
    for (const auto& [key, unused] : parsed.items())
    {
      (void)unused;
      if (std::find(MEMBERS.begin(), MEMBERS.end(), key) == MEMBERS.end())
      {
        throw InvalidInput("the report carries an unknown field '" + key + "'");
      }
    }

    report::ReportInput input;
    input.issued_at = issued_at;
    input.title =
      text_field(parsed, "title", report_limits::MAX_TITLE_CHARS, true);
    input.body =
      text_field(parsed, "body", report_limits::MAX_BODY_CHARS, true);
    input.component =
      text_field(parsed, "component", report_limits::MAX_COMPONENT_CHARS, true);
    input.severity =
      text_field(parsed, "severity", report_limits::MAX_SEVERITY_CHARS, true);

    // The fingerprint is opaque to the profile, so whatever the reporter calls
    // a fingerprint is carried through as its UTF-8 bytes rather than being
    // reinterpreted as hex or base64.
    const auto fingerprint = text_field(
      parsed, "fingerprint", report_limits::MAX_FINGERPRINT_CHARS, false);
    input.fingerprint.assign(fingerprint.begin(), fingerprint.end());

    const auto& references = member(parsed, "references");
    if (!references.is_array())
    {
      throw InvalidInput("the report field 'references' must be an array");
    }
    if (references.size() > report_limits::MAX_REFERENCES)
    {
      throw InvalidInput(
        "the report carries more than " +
        std::to_string(report_limits::MAX_REFERENCES) + " references");
    }
    for (const auto& reference : references)
    {
      if (!reference.is_string())
      {
        throw InvalidInput("every report reference must be a string");
      }
      auto text = reference.get<std::string>();
      if (text.find('\0') != std::string::npos)
      {
        throw InvalidInput("a report reference contains a NUL character");
      }
      size_t chars = 0;
      try
      {
        chars = text::count_code_points(text);
      }
      catch (const std::exception&)
      {
        throw InvalidInput("a report reference is not well-formed UTF-8");
      }
      if (chars == 0)
      {
        throw InvalidInput("a report reference must not be empty");
      }
      if (chars > report_limits::MAX_REFERENCE_CHARS)
      {
        throw InvalidInput(
          "a report reference is longer than " +
          std::to_string(report_limits::MAX_REFERENCE_CHARS) + " characters");
      }
      input.references.push_back(std::move(text));
    }
    return input;
  }
}
