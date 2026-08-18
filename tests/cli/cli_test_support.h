// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// Shared helpers for the command line tests. Scratch files are created below
// the current directory (the build directory, when run through ctest) and
// removed again, so a test never depends on, or leaves anything in, a shared
// temporary directory.

#include "cli/commands.h"
#include "cli/files.h"
#include "tests/core/test_support.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace scitt_sd::cli::testing
{
  namespace fs = std::filesystem;

  // A directory of its own for each test, removed when the test ends.
  class ScratchDir
  {
  public:
    explicit ScratchDir(const std::string& name) :
      root_(fs::path("cli_test_scratch") / name)
    {
      std::error_code ignored;
      (void)fs::remove_all(root_, ignored);
      fs::create_directories(root_);
    }

    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;
    ScratchDir(ScratchDir&&) = delete;
    ScratchDir& operator=(ScratchDir&&) = delete;

    ~ScratchDir()
    {
      std::error_code ignored;
      (void)fs::remove_all(root_, ignored);
    }

    [[nodiscard]] fs::path operator/(const std::string& name) const
    {
      return root_ / name;
    }

    [[nodiscard]] const fs::path& path() const
    {
      return root_;
    }

  private:
    fs::path root_;
  };

  inline void write_raw(const fs::path& path, std::string_view contents)
  {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(
      contents.data(), static_cast<std::streamsize>(contents.size()));
  }

  inline void write_raw_bytes(
    const fs::path& path, const std::vector<uint8_t>& contents)
  {
    write_raw(
      path,
      std::string_view(
        reinterpret_cast<const char*>(contents.data()), contents.size()));
  }

  inline std::string read_raw(const fs::path& path)
  {
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
  }

  inline std::vector<uint8_t> read_raw_bytes(const fs::path& path)
  {
    const auto text = read_raw(path);
    return {text.begin(), text.end()};
  }

  // A report document the strict parser accepts, so a test that is about
  // something else does not have to spell one out.
  inline std::string sample_report_json(
    const std::string& body = "Twelve chars")
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

  // Everything `bundle create` needs: an issued statement, the transparent
  // statement a transparency service would return, and the disclosure set.
  struct IssuedFiles
  {
    fs::path root_key;
    fs::path root_cert;
    fs::path issuer_json;
    fs::path private_key;
    fs::path public_key;
    fs::path leaf_cert;
    fs::path report_json;
    fs::path registered;
    fs::path transparent;
    fs::path disclosures;
    fs::path bundle;
  };

  // Runs the real commands, in the order an operator would: this is the
  // fixture every pipeline test starts from.
  inline IssuedFiles issue_everything(
    const ScratchDir& dir,
    const std::string& body = "Twelve chars",
    const std::vector<uint8_t>& receipt = {0x52, 0x43, 0x50, 0x54})
  {
    std::ostringstream out;
    IssuedFiles files{
      dir / "root.key",
      dir / "root.pem",
      dir / "issuer.json",
      dir / "reporter.key",
      dir / "reporter.pub",
      dir / "reporter.pem",
      dir / "report.json",
      dir / "registered.cbor",
      dir / "transparent.cbor",
      dir / "disclosures.cbor",
      dir / "bundle.cbor"};

    root_init({files.root_key, files.root_cert, files.issuer_json}, out);

    // The reporter's own key never leaves this directory; only the public key
    // is certified.
    auto reporter =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    write_raw(files.private_key, reporter->private_key_pem().str());

    key_public({files.private_key, files.public_key}, out);
    issue_cert(
      {files.root_key, files.root_cert, files.public_key, files.leaf_cert},
      out);

    write_raw(files.report_json, sample_report_json(body));
    issue(
      {files.report_json,
       files.private_key,
       files.leaf_cert,
       files.root_cert,
       files.registered,
       files.disclosures},
      out);

    // What a transparency service returns: the same statement with a receipt
    // in its unprotected header.
    const auto registered = read_raw_bytes(files.registered);
    const auto transparent =
      scitt_sd::testing::attach_receipts(registered, {receipt});
    write_raw(
      files.transparent, std::string(transparent.begin(), transparent.end()));

    bundle_create(
      {files.registered,
       files.transparent,
       files.disclosures,
       "https://transparency.example",
       "2.14",
       files.bundle},
      out);
    return files;
  }

  inline std::string selection_json(
    const std::vector<std::string>& fields,
    const std::vector<size_t>& body_chunks)
  {
    std::ostringstream out;
    out << R"({"version": 1, "redact_fields": [)";
    for (size_t i = 0; i < fields.size(); ++i)
    {
      out << (i == 0 ? "" : ", ") << '"' << fields[i] << '"';
    }
    out << R"(], "redact_body_chunks": [)";
    for (size_t i = 0; i < body_chunks.size(); ++i)
    {
      out << (i == 0 ? "" : ", ") << body_chunks[i];
    }
    out << "]}";
    return out.str();
  }
}
