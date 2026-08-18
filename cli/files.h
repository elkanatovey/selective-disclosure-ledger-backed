// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace scitt_sd::cli
{
  // Anything the tool refuses because of how it was invoked or what it was
  // handed, as opposed to a verification that legitimately failed. A usage
  // error is never a statement about a bundle's trustworthiness.
  class UsageError : public std::runtime_error
  {
  public:
    explicit UsageError(const std::string& what) : std::runtime_error(what) {}
  };

  // Size ceilings. They match the control plane's own limits so neither side
  // can be made to read something the other would refuse, and they bound the
  // memory an untrusted file can cost before anything parses it.
  inline constexpr size_t MAX_PEM_BYTES = 64UL * 1024UL;
  inline constexpr size_t MAX_JSON_BYTES = 1024UL * 1024UL;
  inline constexpr size_t MAX_BUNDLE_BYTES = 4UL * 1024UL * 1024UL;
  inline constexpr size_t MAX_STATEMENT_BYTES = 4UL * 1024UL * 1024UL;
  inline constexpr size_t MAX_DISCLOSURE_SET_BYTES = 4UL * 1024UL * 1024UL;

  enum class Access : uint8_t
  {
    // Readable by whoever the umask allows: certificates, public keys,
    // statements, bundles and reports are all meant to be handed around.
    Shareable,
    // Owner only. Private keys, and nothing else.
    Private,
  };

  // Read a whole file, refusing anything larger than `max_bytes` before
  // reading it. `description` names the file in any error message.
  std::vector<uint8_t> read_file(
    const std::filesystem::path& path,
    size_t max_bytes,
    std::string_view description);

  // As read_file, additionally refusing content that is not well-formed UTF-8
  // or that contains a NUL.
  std::string read_text_file(
    const std::filesystem::path& path,
    size_t max_bytes,
    std::string_view description);

  // Write a file so that a reader sees either the previous content or the
  // complete new content, never a partial write: the bytes go to a temporary
  // file in the SAME directory, are flushed to disk, and are then renamed over
  // the target. A private file is never readable by anyone else, not even
  // briefly, because the temporary is created 0600 and widened only if the
  // file is meant to be shared.
  void write_file(
    const std::filesystem::path& path,
    std::span<const uint8_t> contents,
    Access access = Access::Shareable);

  void write_text_file(
    const std::filesystem::path& path,
    std::string_view contents,
    Access access = Access::Shareable);
}
