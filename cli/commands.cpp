// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli/commands.h"

#include "cli/disclosure_set.h"
#include "cli/files.h"
#include "cli/identity.h"
#include "cli/report_json.h"
#include "core/bundle.h"
#include "core/profile.h"
#include "core/report.h"
#include "core/text_chunks.h"
#include "core/verify.h"

#include <algorithm>
#include <array>
#include <ccf/_private/crypto/certs.h>
#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ec_public_key.h>
#include <ccf/crypto/verifier.h>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <utility>

namespace scitt_sd::cli
{
  namespace
  {
    using nlohmann::ordered_json;

    // The five report fields a viewer renders, in the order it renders them.
    // The body is rendered separately, chunk by chunk.
    constexpr std::array<std::pair<int64_t, std::string_view>, 5>
      DISPLAY_FIELDS = {
        {{report::label::TITLE, "Title"},
         {report::label::COMPONENT, "Component"},
         {report::label::SEVERITY, "Severity"},
         {report::label::FINGERPRINT, "Fingerprint"},
         {report::label::REFERENCES, "References"}}};

    ccf::crypto::Pem read_pem(
      const fs::path& path, std::string_view description)
    {
      const auto text = read_text_file(path, MAX_PEM_BYTES, description);
      try
      {
        return {text};
      }
      catch (const std::exception& e)
      {
        throw UsageError(
          std::string(description) + " '" + path.string() +
          "' is not a PEM document: " + e.what());
      }
    }

    ccf::crypto::ECKeyPairPtr read_key(
      const fs::path& path, std::string_view description)
    {
      const auto pem = read_pem(path, description);
      try
      {
        return ccf::crypto::make_ec_key_pair(pem);
      }
      catch (const std::exception& e)
      {
        throw UsageError(
          std::string(description) + " '" + path.string() +
          "' is not an EC private key: " + e.what());
      }
    }

    std::vector<uint8_t> read_cert_der(
      const fs::path& path, std::string_view description)
    {
      const auto pem = read_pem(path, description);
      try
      {
        return ccf::crypto::cert_pem_to_der(pem);
      }
      catch (const std::exception& e)
      {
        throw UsageError(
          std::string(description) + " '" + path.string() +
          "' is not an X.509 certificate: " + e.what());
      }
    }

    void write_json(const fs::path& path, const ordered_json& document)
    {
      write_text_file(path, document.dump(2) + "\n");
    }

    ordered_json read_json_object(
      const fs::path& path, std::string_view description)
    {
      const auto text = read_text_file(path, MAX_JSON_BYTES, description);
      ordered_json parsed;
      try
      {
        parsed = ordered_json::parse(text);
      }
      catch (const nlohmann::json::exception& e)
      {
        throw UsageError(
          std::string(description) + " '" + path.string() +
          "' is not valid JSON: " + e.what());
      }
      if (!parsed.is_object())
      {
        throw UsageError(
          std::string(description) + " '" + path.string() +
          "' must be a JSON object");
      }
      return parsed;
    }

    // A fingerprint is opaque to the profile: it is shown as text when it is
    // text, and as hex when it is not, rather than being guessed at.
    std::string fingerprint_text(const std::vector<uint8_t>& fingerprint)
    {
      std::string text(fingerprint.begin(), fingerprint.end());
      if (text.find('\0') == std::string::npos)
      {
        try
        {
          text::validate_utf8(text);
          return text;
        }
        catch (const std::exception&)
        {
          // Not text: fall through to hex.
        }
      }
      static constexpr std::string_view HEX = "0123456789abcdef";
      std::string out;
      out.reserve(fingerprint.size() * 2);
      for (const auto byte : fingerprint)
      {
        out.push_back(HEX[byte >> 4U]);
        out.push_back(HEX[byte & 0x0FU]);
      }
      return out;
    }

    std::string join_disclosed(const std::map<size_t, std::string>& items)
    {
      std::string out;
      for (const auto& [index, text] : items)
      {
        if (!out.empty())
        {
          out += "\n";
        }
        out += text;
      }
      return out;
    }

    // The value a viewer shows for a whole claim, or nothing when the claim
    // was not disclosed.
    std::optional<std::string> field_value(
      int64_t claim_label, const verify::DisclosedReport& disclosed)
    {
      switch (claim_label)
      {
        case report::label::TITLE:
          return disclosed.title;
        case report::label::COMPONENT:
          return disclosed.component;
        case report::label::SEVERITY:
          return disclosed.severity;
        case report::label::FINGERPRINT:
          if (!disclosed.fingerprint.has_value())
          {
            return std::nullopt;
          }
          return fingerprint_text(*disclosed.fingerprint);
        case report::label::REFERENCES:
          if (!disclosed.references_disclosed)
          {
            return std::nullopt;
          }
          return join_disclosed(disclosed.references);
        default:
          return std::nullopt;
      }
    }

    ordered_json inspection_document(
      const bundle::ProofBundle& proof, const verify::Result& result)
    {
      const auto& disclosed = result.disclosed;

      auto fields = ordered_json::array();
      for (const auto& [claim_label, display] : DISPLAY_FIELDS)
      {
        const auto value = field_value(claim_label, disclosed);
        ordered_json field;
        field["name"] = report::field_name(claim_label);
        field["label"] = display;
        field["disclosed"] = value.has_value();
        if (value.has_value())
        {
          field["value"] = *value;
        }
        else
        {
          field["value"] = nullptr;
        }
        fields.push_back(std::move(field));
      }

      // A hidden body hides how long it is too, so there is nothing to lay out
      // until the body claim itself is disclosed.
      auto chunks = ordered_json::array();
      for (size_t index = 0; index < disclosed.body_chunk_count; ++index)
      {
        const auto found = disclosed.body_chunks.find(index);
        const bool shown = found != disclosed.body_chunks.end();
        ordered_json chunk;
        chunk["index"] = index;
        chunk["text"] = shown ? found->second : std::string();
        chunk["disclosed"] = shown;
        chunks.push_back(std::move(chunk));
      }

      auto notes = ordered_json::array();
      notes.push_back(
        "Issuer identity as claimed by the statement: " + result.issuer_did);
      notes.push_back("Signing certificate subject: " + result.leaf_subject);
      notes.push_back(
        "The issuer signature and the disclosures were checked so that only "
        "authentic content is shown. No trust anchor was consulted and no "
        "SCITT receipt was verified: run 'scitt-sd verify' and the official "
        "SCITT verifier for that.");
      if (!disclosed.body_disclosed)
      {
        notes.push_back("The body is not disclosed in this bundle.");
      }
      if (
        disclosed.references_disclosed &&
        disclosed.references.size() < disclosed.reference_count)
      {
        notes.push_back(
          "This bundle discloses " +
          std::to_string(disclosed.references.size()) + " of " +
          std::to_string(disclosed.reference_count) + " references.");
      }

      ordered_json document;
      document["chunk_size"] = text::TEXT_CHUNK_SIZE;
      document["fields"] = std::move(fields);
      document["body"] = ordered_json{
        {"chunk_size", text::TEXT_CHUNK_SIZE},
        {"disclosed", disclosed.body_disclosed},
        {"chunks", std::move(chunks)}};
      document["scitt"] =
        ordered_json{{"url", proof.scitt_url}, {"txid", proof.txid}};
      document["notes"] = std::move(notes);
      return document;
    }

    // --- verify report ------------------------------------------------------

    struct CheckReport
    {
      std::string_view id;
      std::string_view label;
      verify::Check check;
      std::string_view passed;
    };

    // The four checks this tool owns, in the order the core performs them.
    const std::array<CheckReport, 4> OWNED_CHECKS = {{
      {"statement_binding",
       "Registered statement binding",
       verify::Check::StatementBinding,
       "The transparent statement is the registered statement with a receipt "
       "attached: same protected header, payload and signature."},
      {"msrc_chain",
       "MSRC certificate chain",
       verify::Check::MsrcChain,
       "The certificate chain ends at the supplied MSRC root, and the issuer "
       "did:x509 pins that same root."},
      {"issuer_signature",
       "Issuer signature",
       verify::Check::IssuerSignature,
       "The COSE_Sign1 signature verifies under the signing certificate."},
      {"disclosures",
       "Disclosure consistency",
       verify::Check::Disclosures,
       "Every presented disclosure is committed to by the registered "
       "statement."},
    }};

    // Why this tool never reports a receipt result, in the report itself.
    constexpr std::string_view SCITT_SKIPPED_DETAIL =
      "Not checked here. This tool does not verify SCITT receipts or Merkle "
      "proofs; the official SCITT verifier must be run separately against the "
      "registered statement before this bundle can be treated as transparent.";

    ordered_json check_entry(
      const CheckReport& check,
      std::string_view status,
      const std::string& detail)
    {
      return ordered_json{
        {"id", check.id},
        {"label", check.label},
        {"status", status},
        {"detail", detail}};
    }

    ordered_json scitt_entry()
    {
      return ordered_json{
        {"id", "scitt_receipt"},
        {"label", "SCITT receipt (official pyscitt)"},
        {"status", "skipped"},
        {"detail", SCITT_SKIPPED_DETAIL}};
    }

    ordered_json verification_document(
      const std::optional<verify::Check>& failed,
      const std::string& reason,
      const std::vector<std::string>& notes,
      const std::vector<std::string>& details)
    {
      auto checks = ordered_json::array();
      bool reached = true;
      for (size_t i = 0; i < OWNED_CHECKS.size(); ++i)
      {
        const auto& check = OWNED_CHECKS.at(i);
        if (failed.has_value() && *failed == check.check)
        {
          checks.push_back(check_entry(check, "fail", reason));
          reached = false;
          continue;
        }
        if (!reached)
        {
          checks.push_back(check_entry(
            check, "skipped", "Not reached: an earlier check failed."));
          continue;
        }
        checks.push_back(check_entry(
          check,
          "pass",
          i < details.size() && !details.at(i).empty() ?
            details.at(i) :
            std::string(check.passed)));
      }
      checks.push_back(scitt_entry());

      ordered_json document;
      document["overall"] = failed.has_value() ? "fail" : "pass";
      document["checks"] = std::move(checks);
      document["detail"] = failed.has_value() ?
        "One of the four checks this tool owns failed." :
        "The four checks this tool owns passed. The SCITT receipt is not one "
        "of them.";
      document["notes"] = notes;
      return document;
    }

    // A failure this tool can describe without the core having looked at the
    // bundle at all, e.g. one that does not decode.
    int report_failure(
      const VerifyArgs& args,
      verify::Check failed,
      const std::string& reason,
      std::vector<std::string> notes,
      std::ostream& out)
    {
      notes.emplace_back(
        "The SCITT receipt was not verified: run the official SCITT verifier "
        "separately.");
      write_json(
        args.json_output, verification_document(failed, reason, notes, {}));
      out << "verification failed: " << reason << "\n";
      return EXIT_VERIFICATION_FAILED;
    }

    // --- presentation -------------------------------------------------------

    struct SelectionDocument
    {
      std::set<std::string> fields;
      std::set<size_t> body_chunks;
    };

    SelectionDocument parse_selection(const fs::path& path)
    {
      const auto document = read_json_object(path, "the selection");
      for (const auto& [key, unused] : document.items())
      {
        (void)unused;
        if (
          key != "version" && key != "redact_fields" &&
          key != "redact_body_chunks")
        {
          throw UsageError(
            "the selection carries an unknown field '" + key + "'");
        }
      }
      const auto version = document.find("version");
      if (version != document.end())
      {
        if (!version->is_number_unsigned() || version->get<uint64_t>() != 1)
        {
          throw UsageError("unsupported selection version");
        }
      }

      SelectionDocument selection;
      const auto fields = document.find("redact_fields");
      if (fields != document.end())
      {
        if (!fields->is_array())
        {
          throw UsageError("'redact_fields' must be an array of field names");
        }
        for (const auto& field : *fields)
        {
          if (!field.is_string())
          {
            throw UsageError("every redacted field must be named by a string");
          }
          auto name = field.get<std::string>();
          const auto known = std::any_of(
            report::CONTENT_LABELS.begin(),
            report::CONTENT_LABELS.end(),
            [&name](int64_t claim_label) {
              return report::field_name(claim_label) == name;
            });
          if (!known)
          {
            throw UsageError(
              "'" + name + "' is not a field of the report profile");
          }
          selection.fields.insert(std::move(name));
        }
      }

      const auto chunks = document.find("redact_body_chunks");
      if (chunks != document.end())
      {
        if (!chunks->is_array())
        {
          throw UsageError(
            "'redact_body_chunks' must be an array of chunk indices");
        }
        for (const auto& chunk : *chunks)
        {
          if (!chunk.is_number_unsigned())
          {
            throw UsageError(
              "every redacted body chunk must be a non-negative integer");
          }
          selection.body_chunks.insert(chunk.get<size_t>());
        }
      }
      return selection;
    }

    // Whether the disclosure at `path` must be dropped. Dropping a parent
    // drops its children too: a body chunk whose body is no longer disclosed
    // cannot be opened, so leaving it in would make the bundle unreadable.
    bool drop_disclosure(
      const sdcwt::Path& path, const SelectionDocument& selection)
    {
      if (path.empty())
      {
        return false;
      }
      const auto* claim_label = std::get_if<int64_t>(&path.front());
      if (claim_label == nullptr)
      {
        return false;
      }
      const auto name = report::field_name(*claim_label);
      if (name.empty())
      {
        return false;
      }
      if (selection.fields.count(name) != 0)
      {
        return true;
      }
      if (path.size() == 2 && *claim_label == report::label::BODY)
      {
        const auto* index = std::get_if<int64_t>(&path.at(1));
        if (index != nullptr && *index >= 0)
        {
          return selection.body_chunks.count(static_cast<size_t>(*index)) != 0;
        }
      }
      return false;
    }
  }

  int root_init(const RootInitArgs& args, std::ostream& out)
  {
    auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    const auto valid_from = x509_time_from_now();
    const auto certificate = ccf::crypto::create_self_signed_cert(
      key,
      std::string(profile::ROOT_SUBJECT),
      {},
      valid_from,
      profile::ROOT_VALIDITY_DAYS);
    const auto der = ccf::crypto::cert_pem_to_der(certificate);

    write_text_file(
      args.private_key, key->private_key_pem().str(), Access::Private);
    write_text_file(args.certificate, certificate.str());

    ordered_json issuer;
    issuer["version"] = 1;
    issuer["certificate_subject"] = profile::ROOT_SUBJECT;
    issuer["reporter_subject"] = profile::REPORTER_SUBJECT;
    issuer["reporter_common_name"] = profile::REPORTER_COMMON_NAME;
    issuer["ca_fingerprint_alg"] = "sha256";
    issuer["ca_fingerprint"] = did_x509_ca_fingerprint(der);
    issuer["issuer_did"] = make_subject_did(der);
    issuer["report_subject"] = profile::REPORT_SUBJECT;
    issuer["valid_from"] = valid_from;
    issuer["validity_days"] = profile::ROOT_VALIDITY_DAYS;
    issuer["leaf_validity_seconds"] = profile::LEAF_VALIDITY_SECONDS;
    write_json(args.issuer_json, issuer);

    out << "root certificate: " << profile::ROOT_SUBJECT << "\n";
    out << "issuer did: " << make_subject_did(der) << "\n";
    return EXIT_OK;
  }

  int key_generate(const KeyGenerateArgs& args, std::ostream& out)
  {
    // The same curve every other key in the demo uses: a statement signed
    // with ES256 has to be verifiable by the profile's single algorithm.
    const auto key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    write_text_file(args.output, key->private_key_pem().str(), Access::Private);
    out << "private key written to " << args.output.string()
        << " (owner readable only)\n";
    return EXIT_OK;
  }

  int key_public(const KeyPublicArgs& args, std::ostream& out)
  {
    const auto key = read_key(args.private_key, "the private key");
    write_text_file(args.output, key->public_key_pem().str());
    out << "public key written to " << args.output.string() << "\n";
    return EXIT_OK;
  }

  int issue_cert(const IssueCertArgs& args, std::ostream& out)
  {
    const auto root_key = read_pem(args.root_key, "the root private key");
    const auto root_cert = read_pem(args.root_cert, "the root certificate");
    const auto public_key = read_pem(args.public_key, "the public key");
    // The supplied PEM has to be a public key: endorsing anything else would
    // silently produce a certificate nobody holds the key for.
    try
    {
      (void)ccf::crypto::make_ec_public_key(public_key);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the public key '" + args.public_key.string() +
        "' is not a public key: " + e.what());
    }

    ccf::crypto::Pem certificate;
    try
    {
      certificate = ccf::crypto::create_endorsed_cert(
        public_key,
        std::string(profile::REPORTER_SUBJECT),
        {},
        x509_time_from_now(),
        x509_time_from_now(
          static_cast<int64_t>(profile::LEAF_VALIDITY_SECONDS)),
        root_key,
        root_cert,
        false);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        std::string("could not endorse the public key: ") + e.what());
    }
    write_text_file(args.output, certificate.str());

    out << "certificate subject: " << profile::REPORTER_SUBJECT << "\n";
    out << "valid for " << profile::LEAF_VALIDITY_SECONDS << " seconds\n";
    return EXIT_OK;
  }

  int issue(const IssueArgs& args, std::ostream& out)
  {
    const auto document =
      read_text_file(args.report_json, MAX_JSON_BYTES, "the report");
    const auto input = parse_report_json(document, now_seconds());

    const auto key = read_key(args.private_key, "the private key");
    const auto leaf_der = read_cert_der(args.leaf_cert, "the leaf certificate");
    const auto root_der = read_cert_der(args.root_cert, "the root certificate");

    // Signing with a key the certificate does not belong to produces a
    // statement that can never verify, so it is refused here instead.
    try
    {
      if (
        ccf::crypto::public_key_pem_from_cert(leaf_der) !=
        key->public_key_pem())
      {
        throw UsageError(
          "the leaf certificate '" + args.leaf_cert.string() +
          "' does not certify the supplied private key");
      }
    }
    catch (const UsageError&)
    {
      throw;
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the leaf certificate '" + args.leaf_cert.string() +
        "' has no usable public key: " + e.what());
    }

    IssuerIdentity issuer;
    issuer.issuer_did = make_subject_did(root_der);
    issuer.subject = profile::REPORT_SUBJECT;
    issuer.x5chain_der = {leaf_der, root_der};

    report::IssuedReport issued;
    try
    {
      issued = report::issue(input, issuer, *key);
    }
    catch (const std::exception& e)
    {
      throw UsageError(std::string("could not issue the report: ") + e.what());
    }

    std::vector<disclosure_set::Entry> entries;
    entries.reserve(issued.disclosures.size());
    for (const auto& disclosure : issued.disclosures)
    {
      entries.push_back({disclosure.path, disclosure.encoded});
    }

    write_file(args.registered, issued.statement);
    write_file(args.disclosures, disclosure_set::encode(entries));

    out << "registered statement: " << issued.statement.size() << " bytes\n";
    out << "disclosures: " << entries.size() << " (" << issued.body_chunk_count
        << " body chunks, " << issued.reference_count << " references)\n";
    out << "issuer did: " << issuer.issuer_did << "\n";
    return EXIT_OK;
  }

  int bundle_create(const BundleCreateArgs& args, std::ostream& out)
  {
    bundle::ProofBundle proof;
    proof.version = bundle::VERSION;
    proof.registered_statement = read_file(
      args.registered, MAX_STATEMENT_BYTES, "the registered statement");
    proof.transparent_statement = read_file(
      args.transparent, MAX_STATEMENT_BYTES, "the transparent statement");
    proof.scitt_url = args.scitt_url;
    proof.txid = args.txid;
    proof.timestamp = now_seconds();

    const auto encoded_set = read_file(
      args.disclosures, MAX_DISCLOSURE_SET_BYTES, "the disclosure set");
    std::vector<disclosure_set::Entry> entries;
    try
    {
      entries = disclosure_set::decode(encoded_set);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the disclosure set '" + args.disclosures.string() +
        "' could not be read: " + e.what());
    }
    proof.disclosures.reserve(entries.size());
    for (auto& entry : entries)
    {
      proof.disclosures.push_back(std::move(entry.encoded));
    }

    std::vector<uint8_t> encoded;
    try
    {
      encoded = bundle::encode(proof);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        std::string("could not build the proof bundle: ") + e.what());
    }
    write_file(args.output, encoded);

    out << "bundle: " << encoded.size() << " bytes, "
        << proof.disclosures.size() << " disclosures\n";
    return EXIT_OK;
  }

  int bundle_inspect(const BundleInspectArgs& args, std::ostream& out)
  {
    const auto encoded =
      read_file(args.bundle, MAX_BUNDLE_BYTES, "the proof bundle");
    bundle::ProofBundle proof;
    try
    {
      proof = bundle::decode(encoded);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the proof bundle '" + args.bundle.string() +
        "' could not be read: " + e.what());
    }

    verify::Result result;
    try
    {
      result = verify::inspect_bundle(proof);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the proof bundle '" + args.bundle.string() +
        "' cannot be displayed: " + e.what());
    }

    write_json(args.json_output, inspection_document(proof, result));
    out << "inspection written to " << args.json_output.string() << "\n";
    return EXIT_OK;
  }

  int bundle_extract(const BundleExtractArgs& args, std::ostream& out)
  {
    const auto encoded =
      read_file(args.bundle, MAX_BUNDLE_BYTES, "the proof bundle");
    bundle::ProofBundle proof;
    try
    {
      proof = bundle::decode(encoded);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the proof bundle '" + args.bundle.string() +
        "' could not be read: " + e.what());
    }

    // Verbatim: these are the bytes a receipt is bound to.
    write_file(args.registered, proof.registered_statement);
    write_file(args.transparent, proof.transparent_statement);

    out << "registered statement: " << proof.registered_statement.size()
        << " bytes\n";
    out << "transparent statement: " << proof.transparent_statement.size()
        << " bytes\n";
    return EXIT_OK;
  }

  int bundle_present(const BundlePresentArgs& args, std::ostream& out)
  {
    const auto selection = parse_selection(args.selection_json);

    const auto encoded =
      read_file(args.bundle, MAX_BUNDLE_BYTES, "the proof bundle");
    bundle::ProofBundle proof;
    try
    {
      proof = bundle::decode(encoded);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the proof bundle '" + args.bundle.string() +
        "' could not be read: " + e.what());
    }

    // The paths come from the core, which resolved each disclosure against the
    // statement's own commitments: nothing here has to guess what a byte
    // string discloses.
    verify::Result before;
    try
    {
      before = verify::inspect_bundle(proof);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        "the proof bundle '" + args.bundle.string() +
        "' cannot be presented: " + e.what());
    }

    bundle::ProofBundle presented = proof;
    presented.disclosures.clear();
    size_t dropped = 0;
    for (size_t i = 0; i < proof.disclosures.size(); ++i)
    {
      if (drop_disclosure(before.disclosure_paths.at(i), selection))
      {
        ++dropped;
        continue;
      }
      presented.disclosures.push_back(proof.disclosures.at(i));
    }

    std::vector<uint8_t> output;
    try
    {
      output = bundle::encode(presented);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        std::string("could not build the presented bundle: ") + e.what());
    }

    // Never hand out a bundle that cannot be read back: a presentation that
    // left a child without its parent would be unreadable, not merely smaller.
    try
    {
      (void)verify::inspect_bundle(presented);
    }
    catch (const std::exception& e)
    {
      throw UsageError(
        std::string("the presented bundle would not be readable: ") + e.what());
    }
    write_file(args.output, output);

    out << "dropped " << dropped << " of " << proof.disclosures.size()
        << " disclosures\n";
    return EXIT_OK;
  }

  int verify(const VerifyArgs& args, std::ostream& out)
  {
    if (args.scitt_trust.has_value())
    {
      // Deliberately not parsed: this tool has no opinion about receipts. A
      // caller that passed nothing useful is told so rather than being left to
      // believe a receipt was considered.
      const auto& path = *args.scitt_trust;
      std::error_code error;
      const auto status = fs::status(path, error);
      if (error || status.type() == fs::file_type::not_found)
      {
        throw UsageError(
          "the SCITT trust material '" + path.string() + "' does not exist");
      }
      const bool empty = fs::is_directory(status) ?
        fs::is_empty(path, error) :
        fs::file_size(path, error) == 0;
      if (error || empty)
      {
        throw UsageError(
          "the SCITT trust material '" + path.string() + "' is empty");
      }
    }

    const auto encoded =
      read_file(args.bundle, MAX_BUNDLE_BYTES, "the proof bundle");
    bundle::ProofBundle proof;
    try
    {
      proof = bundle::decode(encoded);
    }
    catch (const std::exception& e)
    {
      return report_failure(
        args,
        verify::Check::StatementBinding,
        std::string("the proof bundle could not be read: ") + e.what(),
        {},
        out);
    }

    verify::Params params;
    // CCF's certificate API cannot add an Extended Key Usage extension, so the
    // demo profile pins the leaf subject in the did:x509 instead. The DID's CA
    // fingerprint pin and its policies are still enforced by the core.
    params.required_eku = "";
    const auto root =
      read_text_file(args.msrc_root, MAX_PEM_BYTES, "the MSRC root");
    try
    {
      params.trusted_root = ccf::crypto::Pem(root);
    }
    catch (const std::exception& e)
    {
      return report_failure(
        args,
        verify::Check::MsrcChain,
        std::string("the MSRC root is not a PEM document: ") + e.what(),
        {},
        out);
    }

    verify::Result result;
    try
    {
      result = verify::verify_bundle(proof, params);
    }
    catch (const verify::VerificationError& e)
    {
      return report_failure(args, e.check(), e.reason(), {}, out);
    }
    catch (const std::exception& e)
    {
      return report_failure(
        args,
        verify::Check::StatementBinding,
        std::string("the proof bundle could not be checked: ") + e.what(),
        {},
        out);
    }

    const std::vector<std::string> details = {
      std::string(OWNED_CHECKS.at(0).passed),
      std::string(OWNED_CHECKS.at(1).passed) +
        " Signing certificate: " + result.leaf_subject + ".",
      std::string(OWNED_CHECKS.at(2).passed),
      std::to_string(proof.disclosures.size()) +
        " disclosures resolved against the registered statement."};

    const std::vector<std::string> notes = {
      "Issuer: " + result.issuer_did,
      "Statement subject: " + result.subject,
      "The SCITT receipt was not verified: run the official SCITT verifier "
      "separately against the registered statement."};

    write_json(
      args.json_output,
      verification_document(std::nullopt, {}, notes, details));
    out << "the four checks this tool owns passed; the SCITT receipt was not "
           "checked\n";
    return EXIT_OK;
  }
}
