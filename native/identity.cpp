// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli/identity.h"

#include "core/profile.h"

#include <array>
#include <ccf/ds/x509_time_fmt.h>
#include <chrono>

namespace scitt_sd::cli
{
  namespace
  {
    bool is_unreserved(char c)
    {
      const auto u = static_cast<unsigned char>(c);
      return (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
        (u >= '0' && u <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }
  }

  std::string percent_encode_did_arg(std::string_view value)
  {
    static constexpr std::array<char, 16> HEX = {
      '0',
      '1',
      '2',
      '3',
      '4',
      '5',
      '6',
      '7',
      '8',
      '9',
      'A',
      'B',
      'C',
      'D',
      'E',
      'F'};

    std::string out;
    out.reserve(value.size());
    for (const char c : value)
    {
      if (is_unreserved(c))
      {
        out.push_back(c);
        continue;
      }
      const auto u = static_cast<unsigned char>(c);
      out.push_back('%');
      out.push_back(HEX.at(u >> 4U));
      out.push_back(HEX.at(u & 0x0FU));
    }
    return out;
  }

  std::string make_subject_did(
    std::span<const uint8_t> root_der, std::string_view common_name)
  {
    return "did:x509:0:sha256:" + did_x509_ca_fingerprint(root_der) +
      "::subject:CN:" + percent_encode_did_arg(common_name);
  }

  std::string x509_time_from_now(int64_t offset_seconds)
  {
    return ccf::ds::to_x509_time_string(
      std::chrono::system_clock::now() + std::chrono::seconds(offset_seconds));
  }

  int64_t now_seconds()
  {
    return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
  }
}
