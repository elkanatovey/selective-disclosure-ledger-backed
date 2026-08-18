// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <filesystem>
#include <optional>
#include <ostream>
#include <string>

namespace scitt_sd::cli
{
  // Exit codes. The control plane distinguishes a failed verification, which
  // always comes with a report, from a tool that could not run at all.
  inline constexpr int EXIT_OK = 0;
  inline constexpr int EXIT_VERIFICATION_FAILED = 1;
  inline constexpr int EXIT_USAGE = 2;

  namespace fs = std::filesystem;

  // Create the demo's trust anchor: a P-256 key and the self-signed CA
  // certificate it holds, plus a description of the issuer identity that CA
  // will endorse. The private key is written owner-readable only.
  struct RootInitArgs
  {
    fs::path private_key;
    fs::path certificate;
    fs::path issuer_json;
  };
  int root_init(const RootInitArgs& args, std::ostream& out);

  // Create a fresh P-256 signing key. Nothing else is produced: the key is
  // enrolled by sending only the public half (`key public`) to be certified,
  // so the private key never leaves the machine that generated it. The file
  // is written owner-readable only.
  struct KeyGenerateArgs
  {
    fs::path output;
  };
  int key_generate(const KeyGenerateArgs& args, std::ostream& out);

  // Derive a public key from a private key. The private key never leaves the
  // machine it was created on; this is what is sent for certification.
  struct KeyPublicArgs
  {
    fs::path private_key;
    fs::path output;
  };
  int key_public(const KeyPublicArgs& args, std::ostream& out);

  // Endorse a reporter's public key with the demo CA. The CA never sees the
  // private key.
  struct IssueCertArgs
  {
    fs::path root_key;
    fs::path root_cert;
    fs::path public_key;
    fs::path output;
  };
  int issue_cert(const IssueCertArgs& args, std::ostream& out);

  // Issue a report as a redacted SD-CWT: a registered statement with every
  // content claim hidden, and the disclosure set that can reopen them.
  struct IssueArgs
  {
    fs::path report_json;
    fs::path private_key;
    fs::path leaf_cert;
    fs::path root_cert;
    fs::path registered;
    fs::path disclosures;
  };
  int issue(const IssueArgs& args, std::ostream& out);

  // Combine the registered statement, the transparent statement returned by
  // the transparency service and the disclosure set into one proof bundle.
  struct BundleCreateArgs
  {
    fs::path registered;
    fs::path transparent;
    fs::path disclosures;
    std::string scitt_url;
    std::string txid;
    fs::path output;
  };
  int bundle_create(const BundleCreateArgs& args, std::ostream& out);

  // Describe what a bundle currently reveals. This checks the issuer's own
  // signature and the disclosures so that nothing meaningless is rendered; it
  // makes NO trust decision and does not look at the receipt.
  struct BundleInspectArgs
  {
    fs::path bundle;
    fs::path json_output;
  };
  int bundle_inspect(const BundleInspectArgs& args, std::ostream& out);

  // Copy the exact statement bytes out of a bundle, unchanged: they are what
  // the official SCITT verifier has to be given.
  struct BundleExtractArgs
  {
    fs::path bundle;
    fs::path registered;
    fs::path transparent;
  };
  int bundle_extract(const BundleExtractArgs& args, std::ostream& out);

  // Drop the selected disclosures from a bundle. The statements are carried
  // over byte for byte: redaction removes disclosures and nothing else.
  struct BundlePresentArgs
  {
    fs::path bundle;
    fs::path selection_json;
    fs::path output;
  };
  int bundle_present(const BundlePresentArgs& args, std::ostream& out);

  // Check the four things this tool owns: the registered/transparent binding,
  // the MSRC certificate chain and did:x509, the issuer's signature and the
  // disclosures. The SCITT receipt is NOT checked here and is always reported
  // as skipped; the official SCITT verifier owns it.
  //
  // Writes a report whether verification passes or fails, and returns
  // EXIT_VERIFICATION_FAILED when it fails.
  struct VerifyArgs
  {
    fs::path bundle;
    fs::path msrc_root;
    fs::path json_output;
    // Accepted for compatibility with callers that pass the SCITT trust
    // material, and deliberately not parsed: this tool does not verify
    // receipts. Only its existence is checked, so a caller that believes it
    // supplied trust material is told when it did not.
    std::optional<fs::path> scitt_trust;
  };
  int verify(const VerifyArgs& args, std::ostream& out);
}
