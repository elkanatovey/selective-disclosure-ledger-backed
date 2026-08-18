// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/report.h"

#include "core/report_internal.h"

#include <algorithm>
#include <stdexcept>

namespace scitt_sd::report
{
  namespace
  {
    sdcwt::Path claim_path(int64_t claim_label)
    {
      return {sdcwt::PathElem(claim_label)};
    }

    sdcwt::Path child_path(int64_t claim_label, size_t index)
    {
      return {
        sdcwt::PathElem(claim_label),
        sdcwt::PathElem(static_cast<int64_t>(index))};
    }

    // A total order over paths: shorter prefixes first, integers before text,
    // integers numerically. Keeps a selection's output stable and lists a
    // parent before its children.
    bool path_less(const sdcwt::Path& a, const sdcwt::Path& b)
    {
      const size_t common = std::min(a.size(), b.size());
      for (size_t i = 0; i < common; ++i)
      {
        if (a[i] == b[i])
        {
          continue;
        }
        const bool a_int = std::holds_alternative<int64_t>(a[i]);
        const bool b_int = std::holds_alternative<int64_t>(b[i]);
        if (a_int != b_int)
        {
          return a_int;
        }
        if (a_int)
        {
          return std::get<int64_t>(a[i]) < std::get<int64_t>(b[i]);
        }
        return std::get<std::string>(a[i]) < std::get<std::string>(b[i]);
      }
      return a.size() < b.size();
    }

    bool is_content_label(int64_t claim_label)
    {
      return std::find(
               CONTENT_LABELS.begin(), CONTENT_LABELS.end(), claim_label) !=
        CONTENT_LABELS.end();
    }

    void validate_input(const ReportInput& input)
    {
      if (input.issued_at < 0)
      {
        throw std::invalid_argument("issued_at must not be negative");
      }
      text::validate_utf8(input.title);
      text::validate_utf8(input.body);
      text::validate_utf8(input.component);
      text::validate_utf8(input.severity);
      for (const auto& reference : input.references)
      {
        text::validate_utf8(reference);
      }
    }
  }

  IssuedReport detail::issue(
    const ReportInput& input,
    const IssuerIdentity& issuer,
    const ccf::crypto::ECKeyPair& key,
    sdcwt::HashAlg sd_alg,
    const sdcwt::RandomSource& rng)
  {
    validate_input(input);

    const auto chunks = text::chunk_text(input.body);

    // The body is a map keyed by stable chunk index, so a disclosed chunk
    // always says where it belongs and gaps are unambiguous.
    sdcwt::CborValue body = sdcwt::CborValue::Map({});
    for (size_t i = 0; i < chunks.size(); ++i)
    {
      body.map_put(
        sdcwt::CborKey(static_cast<int64_t>(i)),
        sdcwt::CborValue::Text(chunks[i]));
    }

    const std::vector<sdcwt::Claim> claims = {
      {label::IAT, sdcwt::CborValue::Int(input.issued_at)},
      {label::TITLE, sdcwt::CborValue::Text(input.title)},
      {label::BODY, std::move(body)},
      {label::COMPONENT, sdcwt::CborValue::Text(input.component)},
      {label::SEVERITY, sdcwt::CborValue::Text(input.severity)},
      {label::FINGERPRINT, sdcwt::CborValue::Bytes(input.fingerprint)},
      {label::REFERENCES, sdcwt::value::text_array(input.references)}};

    // Every content claim is redacted, and so is every body chunk and
    // reference element: revealing a parent still leaves its children hidden
    // until they are disclosed too.
    std::vector<sdcwt::Path> redact_paths;
    for (const auto content_label : CONTENT_LABELS)
    {
      redact_paths.push_back(claim_path(content_label));
    }
    for (size_t i = 0; i < chunks.size(); ++i)
    {
      redact_paths.push_back(child_path(label::BODY, i));
    }
    for (size_t i = 0; i < input.references.size(); ++i)
    {
      redact_paths.push_back(child_path(label::REFERENCES, i));
    }

    // The profile fixes the top-level redacted-claim count, so decoy padding
    // would not hide anything: pad_to is deliberately 0.
    auto token = sdcwt::detail::issue(
      claims,
      redact_paths,
      key,
      sd_alg,
      rng,
      /*pad_to=*/0,
      scitt_x509_header_entries(issuer));

    IssuedReport out;
    out.statement = std::move(token.token);
    out.disclosures = std::move(token.disclosures);
    out.body_chunk_count = chunks.size();
    out.reference_count = input.references.size();
    return out;
  }

  IssuedReport issue(
    const ReportInput& input,
    const IssuerIdentity& issuer,
    const ccf::crypto::ECKeyPair& key,
    sdcwt::HashAlg sd_alg)
  {
    return detail::issue(
      input, issuer, key, sd_alg, sdcwt::default_random_source());
  }

  std::vector<std::vector<uint8_t>> select_disclosures(
    const IssuedReport& issued, const Selection& selection)
  {
    std::vector<sdcwt::Path> wanted;
    const auto want = [&wanted](sdcwt::Path path) {
      if (std::find(wanted.begin(), wanted.end(), path) == wanted.end())
      {
        wanted.push_back(std::move(path));
      }
    };

    for (const auto field : selection.fields)
    {
      if (!is_content_label(field))
      {
        throw std::invalid_argument(
          "unknown report claim label " + std::to_string(field));
      }
      want(claim_path(field));
    }
    for (const auto index : selection.body_chunks)
    {
      if (index >= issued.body_chunk_count)
      {
        throw std::out_of_range(
          "body chunk index " + std::to_string(index) + " out of range");
      }
      want(claim_path(label::BODY)); // ancestor disclosure
      want(child_path(label::BODY, index));
    }
    for (const auto index : selection.references)
    {
      if (index >= issued.reference_count)
      {
        throw std::out_of_range(
          "reference index " + std::to_string(index) + " out of range");
      }
      want(claim_path(label::REFERENCES)); // ancestor disclosure
      want(child_path(label::REFERENCES, index));
    }

    std::sort(wanted.begin(), wanted.end(), path_less);

    std::vector<std::vector<uint8_t>> selected;
    selected.reserve(wanted.size());
    for (const auto& path : wanted)
    {
      const auto found = std::find_if(
        issued.disclosures.begin(),
        issued.disclosures.end(),
        [&path](const sdcwt::Disclosure& d) { return d.path == path; });
      if (found == issued.disclosures.end())
      {
        throw std::invalid_argument(
          "no disclosure for " + describe_path(path) +
          " (report and selection do not match)");
      }
      selected.push_back(found->encoded);
    }
    return selected;
  }

  std::vector<uint8_t> present(
    std::span<const uint8_t> transparent_statement,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    // sdcwt::present replaces only the disclosures header (17); the receipts
    // header (394) and any other unprotected entry survive unchanged.
    return sdcwt::present(transparent_statement, selected);
  }

  std::string field_name(int64_t claim_label)
  {
    switch (claim_label)
    {
      case label::IAT:
        return "iat";
      case label::TITLE:
        return "title";
      case label::BODY:
        return "body";
      case label::COMPONENT:
        return "component";
      case label::SEVERITY:
        return "severity";
      case label::FINGERPRINT:
        return "fingerprint";
      case label::REFERENCES:
        return "references";
      default:
        return {};
    }
  }

  std::string describe_path(const sdcwt::Path& path)
  {
    if (path.empty())
    {
      return "decoy";
    }
    std::string out;
    if (std::holds_alternative<int64_t>(path[0]))
    {
      const auto claim_label = std::get<int64_t>(path[0]);
      const auto name = field_name(claim_label);
      out = name.empty() ? std::to_string(claim_label) : name;
    }
    else
    {
      out = std::get<std::string>(path[0]);
    }
    for (size_t i = 1; i < path.size(); ++i)
    {
      out += "[";
      out += std::holds_alternative<int64_t>(path[i]) ?
        std::to_string(std::get<int64_t>(path[i])) :
        std::get<std::string>(path[i]);
      out += "]";
    }
    return out;
  }
}
