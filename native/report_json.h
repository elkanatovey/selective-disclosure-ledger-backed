// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/report.h"

#include <cstddef>
#include <string>
#include <string_view>

namespace scitt_sd::native
{
  // What a report document may contain. The ceilings are code points, not
  // bytes, and are deliberately looser than the web layer's own limits: this
  // API refuses what it cannot faithfully represent, and leaves editorial
  // limits to whoever collects the report.
  namespace report_limits
  {
    inline constexpr size_t MAX_TITLE_CHARS = 512;
    inline constexpr size_t MAX_BODY_CHARS = 20000;
    inline constexpr size_t MAX_COMPONENT_CHARS = 512;
    inline constexpr size_t MAX_SEVERITY_CHARS = 512;
    inline constexpr size_t MAX_FINGERPRINT_CHARS = 512;
    inline constexpr size_t MAX_REFERENCES = 64;
    inline constexpr size_t MAX_REFERENCE_CHARS = 1024;
  }

  // Parse a report document into the core's input structure.
  //
  // The document must be a JSON object with exactly these six members:
  //
  //   {"title": str, "body": str, "component": str, "severity": str,
  //    "fingerprint": str, "references": [str, ...]}
  //
  // Anything else is refused: a missing member, an unknown member, a member of
  // the wrong type (null included), a field over its ceiling, an empty title,
  // component or severity, an embedded NUL, or malformed UTF-8. Being strict
  // here is what stops a caller from silently issuing a statement over
  // something other than what it meant to say.
  //
  // `issued_at` becomes the CWT `iat` claim, the only claim in the clear.
  //
  // Throws InvalidInput describing the first problem found.
  report::ReportInput parse_report_json(
    std::string_view document, int64_t issued_at);
}
