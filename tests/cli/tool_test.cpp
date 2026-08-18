// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The tool as the control plane actually runs it: a separate process, driven
// by the exact command lines src/scitt_selective_disclosure/cli/client.py
// spells out, judged only by its exit code and the files it leaves behind.
//
// The executable is located through SCITT_SD_TOOL, which CMake sets for the
// test. When it is unset the process-level tests skip rather than fail, so
// running the test binary by hand still exercises everything else.

#include "core/bundle.h"
#include "core/text_chunks.h"
#include "tests/cli/cli_test_support.h"

#include <algorithm>
#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <spawn.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;

using namespace scitt_sd::cli;
using namespace scitt_sd::cli::testing;
using nlohmann::json;

namespace
{
  struct ToolResult
  {
    int exit_code = -1;
    std::string out;
    std::string err;
  };

  // The built executable, or an empty path when the test was not told where
  // it is.
  fs::path tool_path()
  {
    const char* configured = std::getenv("SCITT_SD_TOOL");
    return configured == nullptr ? fs::path() : fs::path(configured);
  }

  // Runs the tool with exactly `args`, without a shell: nothing here has to
  // quote or escape a path, so no argument can be reinterpreted.
  ToolResult run_tool(
    const std::vector<std::string>& args, const ScratchDir& dir)
  {
    const auto tool = tool_path();
    const auto out_path = (dir / "tool.stdout").string();
    const auto err_path = (dir / "tool.stderr").string();

    std::vector<std::string> owned;
    owned.reserve(args.size() + 1);
    owned.push_back(tool.string());
    owned.insert(owned.end(), args.begin(), args.end());

    std::vector<char*> argv;
    argv.reserve(owned.size() + 1);
    for (auto& argument : owned)
    {
      argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0)
    {
      ADD_FAILURE() << "could not initialise the spawn file actions";
      return {};
    }
    (void)posix_spawn_file_actions_addopen(
      &actions,
      STDOUT_FILENO,
      out_path.c_str(),
      O_WRONLY | O_CREAT | O_TRUNC,
      0600);
    (void)posix_spawn_file_actions_addopen(
      &actions,
      STDERR_FILENO,
      err_path.c_str(),
      O_WRONLY | O_CREAT | O_TRUNC,
      0600);

    pid_t pid = 0;
    const auto spawned =
      posix_spawn(&pid, tool.c_str(), &actions, nullptr, argv.data(), environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    if (spawned != 0)
    {
      ADD_FAILURE() << "could not run " << tool << ": " << spawned;
      return {};
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
    {
      ADD_FAILURE() << "could not wait for " << tool;
      return {};
    }

    ToolResult result;
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    result.out = read_raw(out_path);
    result.err = read_raw(err_path);
    return result;
  }

  json read_json(const fs::path& path)
  {
    return json::parse(read_raw(path));
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

  // The command lines below are the ones CliClient issues, so the fixture is
  // named for it.
  class Tool : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      if (tool_path().empty())
      {
        GTEST_SKIP() << "SCITT_SD_TOOL is not set";
      }
      ASSERT_TRUE(fs::exists(tool_path()))
        << "SCITT_SD_TOOL points at " << tool_path()
        << ", which does not exist";
    }
  };
}

TEST_F(Tool, ReportsItsVersion)
{
  const ScratchDir dir("tool_version");
  // The demo launcher and the container image both use this as a liveness
  // check before any file exists, and the launcher logs
  // `--version 2>&1 | head -n 1`. The output is therefore pinned here: one
  // line on stdout, nothing on stderr, and a successful exit.
  const auto result = run_tool({"--version"}, dir);
  EXPECT_EQ(result.exit_code, EXIT_OK);
  EXPECT_EQ(result.err, "");

  const auto text = result.out;
  ASSERT_FALSE(text.empty());
  EXPECT_EQ(text.back(), '\n');
  EXPECT_EQ(std::count(text.begin(), text.end(), '\n'), 1);

  const std::string line = text.substr(0, text.size() - 1);
  EXPECT_TRUE(line.starts_with("scitt-sd ")) << line;
  const auto version = line.substr(std::string("scitt-sd ").size());
  // A dotted version and nothing else, so a parser downstream cannot be
  // surprised by a build date or a git hash.
  EXPECT_FALSE(version.empty());
  EXPECT_TRUE(std::all_of(
    version.begin(),
    version.end(),
    [](char c) {
      return (c >= '0' && c <= '9') || c == '.' || c == '-' ||
        (c >= 'a' && c <= 'z');
    }))
    << version;

  // Stable: the same bytes every time, with no timestamp or nonce in them.
  EXPECT_EQ(run_tool({"--version"}, dir).out, text);
}

TEST_F(Tool, ReportsTheSameVersionThroughEveryEntryPoint)
{
  const ScratchDir dir("tool_version_help");
  const auto version = run_tool({"--version"}, dir);
  ASSERT_EQ(version.exit_code, EXIT_OK);

  // The flag is top level, so it must not be shadowed by a subcommand and it
  // must be listed in the top level help the launcher's users will read.
  const auto help = run_tool({"--help"}, dir);
  EXPECT_EQ(help.exit_code, EXIT_OK);
  EXPECT_NE(help.out.find("--version"), std::string::npos);

  // Asking a subcommand for the version is a usage error rather than a
  // silently different answer.
  EXPECT_EQ(run_tool({"root", "init", "--version"}, dir).exit_code, EXIT_USAGE);
}

TEST_F(Tool, ShowsHelpForEverySubcommand)
{
  const ScratchDir dir("tool_help");
  const auto result = run_tool({"--help-all"}, dir);
  EXPECT_EQ(result.exit_code, EXIT_OK);
  for (const auto* command :
       {"root", "key", "issue-cert", "issue", "bundle", "verify"})
  {
    EXPECT_NE(result.out.find(command), std::string::npos) << command;
  }
}

TEST_F(Tool, RunsTheWholePipeline)
{
  const ScratchDir dir("tool_pipeline");
  const std::string body(scitt_sd::text::TEXT_CHUNK_SIZE * 3, 'e');

  // 1. The demo trust anchor.
  auto result = run_tool(
    {"root",
     "init",
     "--private-key",
     (dir / "root.key").string(),
     "--certificate",
     (dir / "root.pem").string(),
     "--issuer-json",
     (dir / "issuer.json").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  EXPECT_EQ(
    fs::status(dir / "root.key").permissions() & fs::perms::others_all,
    fs::perms::none);

  // 2. A reporter key, made by the tool and enrolled by its public half only.
  result = run_tool(
    {"key", "generate", "--output", (dir / "reporter.key").string()}, dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  EXPECT_EQ(
    fs::status(dir / "reporter.key").permissions() &
      (fs::perms::group_all | fs::perms::others_all),
    fs::perms::none);
  auto reporter = ccf::crypto::make_ec_key_pair(
    ccf::crypto::Pem(read_raw(dir / "reporter.key")));

  result = run_tool(
    {"key",
     "public",
     "--private-key",
     (dir / "reporter.key").string(),
     "--output",
     (dir / "reporter.pub").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  EXPECT_EQ(read_raw(dir / "reporter.pub"), reporter->public_key_pem().str());

  result = run_tool(
    {"issue-cert",
     "--root-key",
     (dir / "root.key").string(),
     "--root-cert",
     (dir / "root.pem").string(),
     "--public-key",
     (dir / "reporter.pub").string(),
     "--output",
     (dir / "reporter.pem").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;

  // 3. The report, issued as a fully redacted statement plus disclosures.
  write_raw(dir / "report.json", sample_report_json(body));
  result = run_tool(
    {"issue",
     "--report-json",
     (dir / "report.json").string(),
     "--private-key",
     (dir / "reporter.key").string(),
     "--leaf-cert",
     (dir / "reporter.pem").string(),
     "--root-cert",
     (dir / "root.pem").string(),
     "--registered",
     (dir / "registered.cose").string(),
     "--disclosures",
     (dir / "disclosures.cbor").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  const auto registered = read_raw_bytes(dir / "registered.cose");
  EXPECT_FALSE(
    scitt_sd::testing::contains(registered, "Heap overflow in parser"));

  // 4. What a transparency service returns: the same statement with a receipt
  // in its unprotected header. Registration itself is not this tool's job.
  write_raw_bytes(
    dir / "transparent.cose",
    scitt_sd::testing::attach_receipts(registered, {{0x52, 0x43, 0x50, 0x54}}));

  result = run_tool(
    {"bundle",
     "create",
     "--registered",
     (dir / "registered.cose").string(),
     "--transparent",
     (dir / "transparent.cose").string(),
     "--disclosures",
     (dir / "disclosures.cbor").string(),
     "--scitt-url",
     "https://transparency.example",
     "--txid",
     "2.14",
     "--output",
     (dir / "bundle.cbor").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;

  // 5. What the bundle currently reveals.
  result = run_tool(
    {"bundle",
     "inspect",
     "--bundle",
     (dir / "bundle.cbor").string(),
     "--json-output",
     (dir / "inspection.json").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  auto inspection = read_json(dir / "inspection.json");
  EXPECT_EQ(
    field_of(inspection, "title").at("value"), "Heap overflow in parser");
  EXPECT_EQ(inspection.at("body").at("chunks").size(), 3U);
  EXPECT_EQ(inspection.at("scitt").at("txid"), "2.14");

  // 6. A redacted presentation.
  write_raw(dir / "selection.json", selection_json({"fingerprint"}, {1}));
  result = run_tool(
    {"bundle",
     "present",
     "--bundle",
     (dir / "bundle.cbor").string(),
     "--selection-json",
     (dir / "selection.json").string(),
     "--output",
     (dir / "presented.cbor").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;

  result = run_tool(
    {"bundle",
     "inspect",
     "--bundle",
     (dir / "presented.cbor").string(),
     "--json-output",
     (dir / "presented-inspection.json").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  inspection = read_json(dir / "presented-inspection.json");
  EXPECT_FALSE(field_of(inspection, "fingerprint").at("disclosed"));
  EXPECT_TRUE(field_of(inspection, "title").at("disclosed"));
  EXPECT_FALSE(inspection.at("body").at("chunks").at(1).at("disclosed"));
  EXPECT_TRUE(inspection.at("body").at("chunks").at(2).at("disclosed"));

  // 7. The exact bytes the official SCITT verifier has to be given.
  result = run_tool(
    {"bundle",
     "extract",
     "--bundle",
     (dir / "presented.cbor").string(),
     "--registered",
     (dir / "extracted-registered.cose").string(),
     "--transparent",
     (dir / "extracted-transparent.cose").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  EXPECT_EQ(read_raw_bytes(dir / "extracted-registered.cose"), registered);
  EXPECT_EQ(
    read_raw_bytes(dir / "extracted-transparent.cose"),
    read_raw_bytes(dir / "transparent.cose"));

  // 8. The four checks this tool owns, on the redacted bundle.
  result = run_tool(
    {"verify",
     "--bundle",
     (dir / "presented.cbor").string(),
     "--msrc-root",
     (dir / "root.pem").string(),
     "--json-output",
     (dir / "verification.json").string()},
    dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;

  const auto verification = read_json(dir / "verification.json");
  EXPECT_EQ(verification.at("overall"), "pass");
  ASSERT_EQ(verification.at("checks").size(), 5U);
  for (const auto& id :
       {"statement_binding", "msrc_chain", "issuer_signature", "disclosures"})
  {
    EXPECT_EQ(check_of(verification, id).at("status"), "pass") << id;
  }
  EXPECT_EQ(check_of(verification, "scitt_receipt").at("status"), "skipped");
}

TEST_F(Tool, ExitsWithTheVerificationCodeAndStillWritesAReport)
{
  const ScratchDir dir("tool_verify_fail");
  const auto files = issue_everything(dir);
  std::ostringstream ignored;
  ASSERT_EQ(
    root_init(
      {dir / "other.key", dir / "other.pem", dir / "other.json"}, ignored),
    EXIT_OK);

  const auto result = run_tool(
    {"verify",
     "--bundle",
     files.bundle.string(),
     "--msrc-root",
     (dir / "other.pem").string(),
     "--json-output",
     (dir / "verification.json").string()},
    dir);

  // The control plane treats a non-zero exit as a verification outcome as
  // long as a report was written, and as a tool failure otherwise.
  EXPECT_EQ(result.exit_code, EXIT_VERIFICATION_FAILED);
  ASSERT_TRUE(fs::is_regular_file(dir / "verification.json"));
  EXPECT_EQ(read_json(dir / "verification.json").at("overall"), "fail");
}

TEST_F(Tool, GeneratesAResearcherKeyThroughTheRealBinary)
{
  const ScratchDir dir("tool_key_generate");
  // The smoke flow's first step: `scitt-sd key generate --output <file>`.
  const auto result = run_tool(
    {"key", "generate", "--output", (dir / "researcher.key").string()}, dir);
  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;

  const auto pem = read_raw(dir / "researcher.key");
  EXPECT_NE(pem.find("BEGIN PRIVATE KEY"), std::string::npos);
  EXPECT_EQ(
    fs::status(dir / "researcher.key").permissions() &
      (fs::perms::group_all | fs::perms::others_all),
    fs::perms::none);

  // The key is immediately usable by the next step of the flow.
  const auto derived = run_tool(
    {"key",
     "public",
     "--private-key",
     (dir / "researcher.key").string(),
     "--output",
     (dir / "researcher.pub").string()},
    dir);
  ASSERT_EQ(derived.exit_code, EXIT_OK) << derived.err;
  const auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(pem));
  EXPECT_EQ(read_raw(dir / "researcher.pub"), key->public_key_pem().str());
  EXPECT_EQ(key->get_curve_id(), ccf::crypto::CurveID::SECP256R1);
}

TEST_F(Tool, RefusesAMalformedKeyGenerateCommandLine)
{
  const ScratchDir dir("tool_key_generate_bad");

  // --output is required.
  EXPECT_EQ(run_tool({"key", "generate"}, dir).exit_code, EXIT_USAGE);

  // --output needs a value.
  EXPECT_EQ(
    run_tool({"key", "generate", "--output"}, dir).exit_code, EXIT_USAGE);

  // It is a subcommand of `key`, not a top level one.
  EXPECT_EQ(
    run_tool({"generate", "--output", (dir / "k.key").string()}, dir).exit_code,
    EXIT_USAGE);

  // An unwritable destination is refused, and nothing is left behind.
  EXPECT_EQ(
    run_tool(
      {"key", "generate", "--output", (dir / "absent" / "k.key").string()}, dir)
      .exit_code,
    EXIT_USAGE);
  EXPECT_FALSE(fs::exists(dir / "absent"));
}

TEST_F(Tool, ExitsWithTheUsageCodeForAMalformedCommandLine)
{
  const ScratchDir dir("tool_usage");

  // No subcommand at all.
  EXPECT_EQ(run_tool({}, dir).exit_code, EXIT_USAGE);

  // An unknown subcommand.
  EXPECT_EQ(run_tool({"frobnicate"}, dir).exit_code, EXIT_USAGE);

  // A known subcommand missing its required options.
  EXPECT_EQ(run_tool({"verify"}, dir).exit_code, EXIT_USAGE);

  // An unknown option.
  EXPECT_EQ(
    run_tool({"key", "public", "--private-key", "a", "--nope", "b"}, dir)
      .exit_code,
    EXIT_USAGE);

  // An option given without its value.
  EXPECT_EQ(
    run_tool({"key", "public", "--private-key"}, dir).exit_code, EXIT_USAGE);

  // A subcommand given without its own subcommand.
  EXPECT_EQ(run_tool({"bundle"}, dir).exit_code, EXIT_USAGE);
}

TEST_F(Tool, ExitsWithTheUsageCodeForAMissingFile)
{
  const ScratchDir dir("tool_missing_file");
  const auto result = run_tool(
    {"key",
     "public",
     "--private-key",
     (dir / "absent.key").string(),
     "--output",
     (dir / "out.pub").string()},
    dir);

  EXPECT_EQ(result.exit_code, EXIT_USAGE);
  EXPECT_NE(result.err.find("scitt-sd:"), std::string::npos);
  EXPECT_FALSE(fs::exists(dir / "out.pub"));
}

TEST_F(Tool, ExitsWithTheUsageCodeForAFileOfTheWrongType)
{
  const ScratchDir dir("tool_wrong_type");
  const auto files = issue_everything(dir);

  // A bundle where a certificate is expected.
  auto result = run_tool(
    {"verify",
     "--bundle",
     files.bundle.string(),
     "--msrc-root",
     files.bundle.string(),
     "--json-output",
     (dir / "verification.json").string()},
    dir);
  EXPECT_EQ(result.exit_code, EXIT_USAGE)
    << "a binary bundle is not text, so it is refused before any check";

  // A certificate where a bundle is expected.
  result = run_tool(
    {"bundle",
     "inspect",
     "--bundle",
     files.root_cert.string(),
     "--json-output",
     (dir / "inspection.json").string()},
    dir);
  EXPECT_EQ(result.exit_code, EXIT_USAGE);
  EXPECT_FALSE(fs::exists(dir / "inspection.json"));
}

TEST_F(Tool, WritesNothingWhenItRefusesACommand)
{
  const ScratchDir dir("tool_no_partial_output");
  const auto files = issue_everything(dir);

  write_raw(dir / "selection.json", selection_json({"not_a_field"}, {}));
  const auto result = run_tool(
    {"bundle",
     "present",
     "--bundle",
     files.bundle.string(),
     "--selection-json",
     (dir / "selection.json").string(),
     "--output",
     (dir / "presented.cbor").string()},
    dir);

  EXPECT_EQ(result.exit_code, EXIT_USAGE);
  EXPECT_FALSE(fs::exists(dir / "presented.cbor"));
}

TEST_F(Tool, AcceptsTheScittTrustOptionWithoutCheckingAnyReceipt)
{
  const ScratchDir dir("tool_scitt_trust");
  const auto files = issue_everything(dir);
  write_raw(dir / "scitt.pem", "never parsed by this tool");

  const auto result = run_tool(
    {"verify",
     "--bundle",
     files.bundle.string(),
     "--msrc-root",
     files.root_cert.string(),
     "--json-output",
     (dir / "verification.json").string(),
     "--scitt-trust",
     (dir / "scitt.pem").string()},
    dir);

  ASSERT_EQ(result.exit_code, EXIT_OK) << result.err;
  EXPECT_EQ(
    check_of(read_json(dir / "verification.json"), "scitt_receipt")
      .at("status"),
    "skipped");
}
