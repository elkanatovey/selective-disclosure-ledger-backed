// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli/commands.h"
#include "cli/files.h"

#include <CLI/CLI.hpp>
#include <exception>
#include <iostream>
#include <string>

#ifndef SCITT_SD_VERSION
#  define SCITT_SD_VERSION "0.0.0-dev"
#endif

namespace
{
  using namespace scitt_sd::cli;

  // What `--version` prints. The demo's launcher and the container image both
  // run it as a liveness check for a binary they have just built or copied, so
  // it must work before any file is touched.
  const std::string VERSION_TEXT = std::string("scitt-sd ") + SCITT_SD_VERSION;

  // Every path option is required and must be given explicitly: this tool is
  // driven by another program, and a defaulted path would silently write
  // somewhere nobody looks.
  CLI::Option* input(
    CLI::App* command,
    const std::string& name,
    fs::path& target,
    const std::string& description)
  {
    return command->add_option(name, target, description)
      ->required()
      ->option_text("FILE");
  }

  CLI::Option* output(
    CLI::App* command,
    const std::string& name,
    fs::path& target,
    const std::string& description)
  {
    return command->add_option(name, target, description)
      ->required()
      ->option_text("FILE");
  }
}

int main(int argc, char** argv)
{
  CLI::App app{
    "Selectively disclosable bug reports: issue, bundle, present and check "
    "the parts of a proof bundle that are not the SCITT receipt."};
  app.require_subcommand(1);
  app.set_help_all_flag("--help-all", "Show every subcommand");
  app.set_version_flag("--version", VERSION_TEXT, "Show the tool version");

  RootInitArgs root_args;
  auto* root = app.add_subcommand("root", "Manage the demo trust anchor");
  root->require_subcommand(1);
  auto* root_init_command =
    root->add_subcommand("init", "Create the demo root key and CA certificate");
  output(
    root_init_command,
    "--private-key",
    root_args.private_key,
    "Where to write the root private key (owner readable only)");
  output(
    root_init_command,
    "--certificate",
    root_args.certificate,
    "Where to write the self-signed root certificate");
  output(
    root_init_command,
    "--issuer-json",
    root_args.issuer_json,
    "Where to write the issuer identity this root endorses");

  KeyGenerateArgs key_generate_args;
  KeyPublicArgs key_args;
  auto* key = app.add_subcommand("key", "Work with reporter keys");
  key->require_subcommand(1);
  auto* key_generate_command =
    key->add_subcommand("generate", "Create a new P-256 signing key");
  output(
    key_generate_command,
    "--output",
    key_generate_args.output,
    "Where to write the private key (owner readable only)");

  auto* key_public_command =
    key->add_subcommand("public", "Derive a public key from a private key");
  input(
    key_public_command,
    "--private-key",
    key_args.private_key,
    "The private key to derive from");
  output(
    key_public_command,
    "--output",
    key_args.output,
    "Where to write the "
    "public key");

  IssueCertArgs issue_cert_args;
  auto* issue_cert_command = app.add_subcommand(
    "issue-cert", "Endorse a reporter public key with the demo CA");
  input(
    issue_cert_command,
    "--root-key",
    issue_cert_args.root_key,
    "The CA private key");
  input(
    issue_cert_command,
    "--root-cert",
    issue_cert_args.root_cert,
    "The CA certificate");
  input(
    issue_cert_command,
    "--public-key",
    issue_cert_args.public_key,
    "The reporter public key to endorse");
  output(
    issue_cert_command,
    "--output",
    issue_cert_args.output,
    "Where to write the endorsed certificate");

  IssueArgs issue_args;
  auto* issue_command = app.add_subcommand(
    "issue", "Issue a report as a redacted statement plus its disclosures");
  input(
    issue_command,
    "--report-json",
    issue_args.report_json,
    "The report document");
  input(
    issue_command,
    "--private-key",
    issue_args.private_key,
    "The reporter private key");
  input(
    issue_command,
    "--leaf-cert",
    issue_args.leaf_cert,
    "The reporter certificate");
  input(
    issue_command, "--root-cert", issue_args.root_cert, "The CA certificate");
  output(
    issue_command,
    "--registered",
    issue_args.registered,
    "Where to write the registered statement");
  output(
    issue_command,
    "--disclosures",
    issue_args.disclosures,
    "Where to write the disclosure set");

  auto* bundle = app.add_subcommand("bundle", "Work with proof bundles");
  bundle->require_subcommand(1);

  BundleCreateArgs bundle_create_args;
  auto* bundle_create_command =
    bundle->add_subcommand("create", "Build a proof bundle");
  input(
    bundle_create_command,
    "--registered",
    bundle_create_args.registered,
    "The registered statement");
  input(
    bundle_create_command,
    "--transparent",
    bundle_create_args.transparent,
    "The transparent statement returned by the transparency service");
  input(
    bundle_create_command,
    "--disclosures",
    bundle_create_args.disclosures,
    "The disclosure set");
  bundle_create_command
    ->add_option(
      "--scitt-url",
      bundle_create_args.scitt_url,
      "The transparency service the statement was registered with")
    ->required();
  bundle_create_command
    ->add_option(
      "--txid",
      bundle_create_args.txid,
      "The transaction id the transparency service assigned")
    ->required();
  output(
    bundle_create_command,
    "--output",
    bundle_create_args.output,
    "Where to write the bundle");

  BundleInspectArgs bundle_inspect_args;
  auto* bundle_inspect_command = bundle->add_subcommand(
    "inspect", "Describe what a bundle currently discloses");
  input(
    bundle_inspect_command,
    "--bundle",
    bundle_inspect_args.bundle,
    "The bundle to inspect");
  output(
    bundle_inspect_command,
    "--json-output",
    bundle_inspect_args.json_output,
    "Where to write the inspection");

  BundleExtractArgs bundle_extract_args;
  auto* bundle_extract_command = bundle->add_subcommand(
    "extract", "Copy the exact statement bytes out of a bundle");
  input(
    bundle_extract_command,
    "--bundle",
    bundle_extract_args.bundle,
    "The bundle to read");
  output(
    bundle_extract_command,
    "--registered",
    bundle_extract_args.registered,
    "Where to write the registered statement");
  output(
    bundle_extract_command,
    "--transparent",
    bundle_extract_args.transparent,
    "Where to write the transparent statement");

  BundlePresentArgs bundle_present_args;
  auto* bundle_present_command =
    bundle->add_subcommand("present", "Drop disclosures from a bundle");
  input(
    bundle_present_command,
    "--bundle",
    bundle_present_args.bundle,
    "The bundle to redact");
  input(
    bundle_present_command,
    "--selection-json",
    bundle_present_args.selection_json,
    "What to redact");
  output(
    bundle_present_command,
    "--output",
    bundle_present_args.output,
    "Where to write the redacted bundle");

  VerifyArgs verify_args;
  fs::path scitt_trust;
  auto* verify_command = app.add_subcommand(
    "verify", "Check everything about a bundle except its SCITT receipt");
  input(verify_command, "--bundle", verify_args.bundle, "The bundle to check");
  input(
    verify_command,
    "--msrc-root",
    verify_args.msrc_root,
    "The separately trusted MSRC root certificate");
  output(
    verify_command,
    "--json-output",
    verify_args.json_output,
    "Where to write the verification report");
  verify_command
    ->add_option(
      "--scitt-trust",
      scitt_trust,
      "Accepted for compatibility and NOT parsed: this tool does not verify "
      "SCITT receipts")
    ->option_text("PATH");

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    // app.exit prints the help, the version or the diagnostic, whichever
    // applies. Its own exit codes are remapped so that this tool only ever
    // reports the three documented ones.
    return app.exit(e) == 0 ? EXIT_OK : EXIT_USAGE;
  }

  try
  {
    if (root_init_command->parsed())
    {
      return root_init(root_args, std::cout);
    }
    if (key_generate_command->parsed())
    {
      return key_generate(key_generate_args, std::cout);
    }
    if (key_public_command->parsed())
    {
      return key_public(key_args, std::cout);
    }
    if (issue_cert_command->parsed())
    {
      return issue_cert(issue_cert_args, std::cout);
    }
    if (issue_command->parsed())
    {
      return issue(issue_args, std::cout);
    }
    if (bundle_create_command->parsed())
    {
      return bundle_create(bundle_create_args, std::cout);
    }
    if (bundle_inspect_command->parsed())
    {
      return bundle_inspect(bundle_inspect_args, std::cout);
    }
    if (bundle_extract_command->parsed())
    {
      return bundle_extract(bundle_extract_args, std::cout);
    }
    if (bundle_present_command->parsed())
    {
      return bundle_present(bundle_present_args, std::cout);
    }
    if (verify_command->parsed())
    {
      if (!scitt_trust.empty())
      {
        verify_args.scitt_trust = scitt_trust;
      }
      return verify(verify_args, std::cout);
    }
  }
  catch (const UsageError& e)
  {
    std::cerr << "scitt-sd: " << e.what() << "\n";
    return EXIT_USAGE;
  }
  catch (const std::exception& e)
  {
    std::cerr << "scitt-sd: " << e.what() << "\n";
    return EXIT_USAGE;
  }

  std::cerr << "scitt-sd: no command was given\n";
  return EXIT_USAGE;
}
