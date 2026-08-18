// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "native/api.h"

#include "core/bundle.h"
#include "core/profile.h"
#include "core/report.h"
#include "core/text_chunks.h"
#include "core/verify.h"
#include "native/disclosure_set.h"
#include "native/identity.h"
#include "native/report_json.h"
#include "native/secrets.h"

#include <algorithm>
#include <array>
#include <ccf/_private/crypto/certs.h>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ec_public_key.h>
#include <ccf/crypto/verifier.h>
#include <exception>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <utility>

namespace scitt_sd::native
{
  namespace
  {
    using nlohmann::ordered_json;

    // ES256 over P-256: the raw r||s signature is always two 32-byte
    // coordinates, and this profile has no other algorithm.
    constexpr size_t ES256_SIGNATURE_BYTES = 64;

    // --- input hygiene ------------------------------------------------------

    void require_size(
      size_t size, size_t max_bytes, std::string_view description)
    {
      if (size > max_bytes)
      {
        throw InvalidInput(
          std::string(description) + " is larger than " +
          std::to_string(max_bytes) + " bytes");
      }
    }

    ccf::crypto::Pem to_pem(
      std::span<const uint8_t> bytes, std::string_view description)
    {
      require_size(bytes.size(), limits::MAX_PEM_BYTES, description);
      try
      {
        return ccf::crypto::Pem(bytes);
      }
      catch (const std::exception& e)
      {
        throw InvalidInput(
          std::string(description) + " is not a PEM document: " + e.what());
      }
    }

    std::vector<uint8_t> to_cert_der(
      std::span<const uint8_t> bytes, std::string_view description)
    {
      const auto pem = to_pem(bytes, description);
      try
      {
        return ccf::crypto::cert_pem_to_der(pem);
      }
      catch (const std::exception& e)
      {
        throw InvalidInput(
          std::string(description) +
          " is not an X.509 certificate: " + e.what());
      }
    }

    ccf::crypto::ECKeyPairPtr to_key(
      std::span<const uint8_t> bytes, std::string_view description)
    {
      require_size(bytes.size(), limits::MAX_PEM_BYTES, description);
      const SecretPem secret(bytes, description);
      try
      {
        return ccf::crypto::make_ec_key_pair(secret.pem());
      }
      catch (const std::exception& e)
      {
        throw InvalidInput(
          std::string(description) + " is not an EC private key: " + e.what());
      }
    }

    bundle::ProofBundle decode_bundle(
      std::span<const uint8_t> encoded, std::string_view what_for)
    {
      require_size(
        encoded.size(), limits::MAX_BUNDLE_BYTES, "the proof bundle");
      try
      {
        return bundle::decode(encoded);
      }
      catch (const std::exception& e)
      {
        throw InvalidInput(
          std::string("the proof bundle ") + std::string(what_for) + ": " +
          e.what());
      }
    }

    ordered_json parse_json_object(
      std::string_view document, std::string_view description)
    {
      require_size(document.size(), limits::MAX_JSON_BYTES, description);
      ordered_json parsed;
      try
      {
        parsed = ordered_json::parse(document);
      }
      catch (const nlohmann::json::exception& e)
      {
        throw InvalidInput(
          std::string(description) + " is not valid JSON: " + e.what());
      }
      if (!parsed.is_object())
      {
        throw InvalidInput(std::string(description) + " must be a JSON object");
      }
      return parsed;
    }

    // --- inspection report --------------------------------------------------

    // The five report fields a viewer renders, in the order it renders them.
    // The body is rendered separately, chunk by chunk.
    constexpr std::array<std::pair<int64_t, std::string_view>, 5>
      DISPLAY_FIELDS = {
        {{report::label::TITLE, "Title"},
         {report::label::COMPONENT, "Component"},
         {report::label::SEVERITY, "Severity"},
         {report::label::FINGERPRINT, "Fingerprint"},
         {report::label::REFERENCES, "References"}}};

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
        "SCITT receipt was verified: verify_bundle and a real transparency "
        "service are needed for that.");
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

    // The four checks this API owns, in the order the core performs them.
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

    // Why this API never reports a receipt result, in the report itself.
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

    // A failure describable without the core having looked at the bundle at
    // all, e.g. one that does not decode.
    VerificationOutcome failed_outcome(
      verify::Check failed, const std::string& reason)
    {
      const std::vector<std::string> notes = {
        "The SCITT receipt was not verified: run the official SCITT verifier "
        "separately."};
      VerificationOutcome outcome;
      outcome.passed = false;
      outcome.reason = reason;
      outcome.report_json =
        verification_document(failed, reason, notes, {}).dump(2);
      return outcome;
    }

    // --- presentation -------------------------------------------------------

    struct SelectionDocument
    {
      std::set<std::string> fields;
      std::set<size_t> body_chunks;
    };

    SelectionDocument parse_selection(std::string_view selection_json)
    {
      const auto document = parse_json_object(selection_json, "the selection");
      for (const auto& [key, unused] : document.items())
      {
        (void)unused;
        if (
          key != "version" && key != "redact_fields" &&
          key != "redact_body_chunks")
        {
          throw InvalidInput(
            "the selection carries an unknown field '" + key + "'");
        }
      }
      const auto version = document.find("version");
      if (version != document.end())
      {
        if (!version->is_number_unsigned() || version->get<uint64_t>() != 1)
        {
          throw InvalidInput("unsupported selection version");
        }
      }

      SelectionDocument selection;
      const auto fields = document.find("redact_fields");
      if (fields != document.end())
      {
        if (!fields->is_array())
        {
          throw InvalidInput("'redact_fields' must be an array of field names");
        }
        for (const auto& field : *fields)
        {
          if (!field.is_string())
          {
            throw InvalidInput(
              "every redacted field must be named by a string");
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
            throw InvalidInput(
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
          throw InvalidInput(
            "'redact_body_chunks' must be an array of chunk indices");
        }
        for (const auto& chunk : *chunks)
        {
          if (!chunk.is_number_unsigned())
          {
            throw InvalidInput(
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

  // --- keys and identities ---------------------------------------------------

  Bytes generate_private_key()
  {
    try
    {
      const auto key =
        ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
      return release_secret(key->private_key_pem());
    }
    catch (const std::exception& e)
    {
      throw OperationFailed(
        std::string("could not create a signing key: ") + e.what());
    }
  }

  Bytes derive_public_key(std::span<const uint8_t> private_key_pem)
  {
    const auto key = to_key(private_key_pem, "the private key");
    return key->public_key_pem().raw();
  }

  RootIdentity create_root_identity()
  {
    ccf::crypto::ECKeyPairPtr key;
    ccf::crypto::Pem certificate;
    std::string valid_from;
    std::vector<uint8_t> der;
    try
    {
      key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
      valid_from = x509_time_from_now();
      certificate = ccf::crypto::create_self_signed_cert(
        key,
        std::string(profile::ROOT_SUBJECT),
        {},
        valid_from,
        profile::ROOT_VALIDITY_DAYS);
      der = ccf::crypto::cert_pem_to_der(certificate);
    }
    catch (const std::exception& e)
    {
      throw OperationFailed(
        std::string("could not create the root identity: ") + e.what());
    }

    RootIdentity identity;
    identity.issuer_did = make_subject_did(der);

    ordered_json issuer;
    issuer["version"] = 1;
    issuer["certificate_subject"] = profile::ROOT_SUBJECT;
    issuer["reporter_subject"] = profile::REPORTER_SUBJECT;
    issuer["reporter_common_name"] = profile::REPORTER_COMMON_NAME;
    issuer["ca_fingerprint_alg"] = "sha256";
    issuer["ca_fingerprint"] = did_x509_ca_fingerprint(der);
    issuer["issuer_did"] = identity.issuer_did;
    issuer["report_subject"] = profile::REPORT_SUBJECT;
    issuer["valid_from"] = valid_from;
    issuer["validity_days"] = profile::ROOT_VALIDITY_DAYS;
    issuer["leaf_validity_seconds"] = profile::LEAF_VALIDITY_SECONDS;

    identity.private_key = release_secret(key->private_key_pem());
    identity.certificate = certificate.raw();
    identity.issuer_json = issuer.dump(2);
    return identity;
  }

  Bytes issue_certificate(
    std::span<const uint8_t> root_key_pem,
    std::span<const uint8_t> root_cert_pem,
    std::span<const uint8_t> public_key_pem)
  {
    require_size(
      root_key_pem.size(), limits::MAX_PEM_BYTES, "the root private key");
    const SecretPem root_key(root_key_pem, "the root private key");
    const auto root_cert = to_pem(root_cert_pem, "the root certificate");
    const auto public_key = to_pem(public_key_pem, "the public key");
    // The supplied PEM has to be a public key: endorsing anything else would
    // silently produce a certificate nobody holds the key for.
    try
    {
      (void)ccf::crypto::make_ec_public_key(public_key);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the public key is not a public key: ") + e.what());
    }

    try
    {
      return ccf::crypto::create_endorsed_cert(
               public_key,
               std::string(profile::REPORTER_SUBJECT),
               {},
               x509_time_from_now(),
               x509_time_from_now(
                 static_cast<int64_t>(profile::LEAF_VALIDITY_SECONDS)),
               root_key.pem(),
               root_cert,
               false)
        .raw();
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("could not endorse the public key: ") + e.what());
    }
  }

  // --- statements ------------------------------------------------------------

  IssuedStatement issue_statement(
    std::string_view report_json,
    std::span<const uint8_t> private_key_pem,
    std::span<const uint8_t> leaf_cert_pem,
    std::span<const uint8_t> root_cert_pem)
  {
    require_size(report_json.size(), limits::MAX_JSON_BYTES, "the report");
    const auto input = parse_report_json(report_json, now_seconds());

    const auto key = to_key(private_key_pem, "the private key");
    const auto leaf_der = to_cert_der(leaf_cert_pem, "the leaf certificate");
    const auto root_der = to_cert_der(root_cert_pem, "the root certificate");

    // Signing with a key the certificate does not belong to produces a
    // statement that can never verify, so it is refused here instead.
    try
    {
      if (
        ccf::crypto::public_key_pem_from_cert(leaf_der) !=
        key->public_key_pem())
      {
        throw InvalidInput(
          "the leaf certificate does not certify the supplied private key");
      }
    }
    catch (const InvalidInput&)
    {
      throw;
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the leaf certificate has no usable public key: ") +
        e.what());
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
      throw InvalidInput(
        std::string("could not issue the report: ") + e.what());
    }

    std::vector<disclosure_set::Entry> entries;
    entries.reserve(issued.disclosures.size());
    for (const auto& disclosure : issued.disclosures)
    {
      entries.push_back({disclosure.path, disclosure.encoded});
    }

    IssuedStatement statement;
    statement.registered_statement = std::move(issued.statement);
    try
    {
      statement.disclosure_set = disclosure_set::encode(entries);
    }
    catch (const std::exception& e)
    {
      throw OperationFailed(
        std::string("could not build the disclosure set: ") + e.what());
    }
    statement.disclosure_count = entries.size();
    statement.body_chunk_count = issued.body_chunk_count;
    statement.reference_count = issued.reference_count;
    statement.issuer_did = issuer.issuer_did;
    return statement;
  }

  PreparedStatement prepare_statement(
    std::string_view report_json,
    std::span<const uint8_t> public_key_pem,
    std::span<const uint8_t> leaf_cert_pem,
    std::span<const uint8_t> root_cert_pem,
    std::span<const uint8_t> confirmation_key_pem)
  {
    require_size(report_json.size(), limits::MAX_JSON_BYTES, "the report");
    auto input = parse_report_json(report_json, now_seconds());

    const auto public_key = to_pem(public_key_pem, "the public key");
    const auto leaf_der = to_cert_der(leaf_cert_pem, "the leaf certificate");
    const auto root_der = to_cert_der(root_cert_pem, "the root certificate");

    if (!confirmation_key_pem.empty())
    {
      // Refused here rather than deep in issuance, so a caller that meant to
      // name a discloser is told when it named something unusable.
      const auto confirmation =
        to_pem(confirmation_key_pem, "the confirmation key");
      try
      {
        (void)ccf::crypto::make_ec_public_key(confirmation);
      }
      catch (const std::exception& e)
      {
        throw InvalidInput(
          std::string("the confirmation key is not an EC public key: ") +
          e.what());
      }
      input.confirmation_key_pem.assign(
        confirmation_key_pem.begin(), confirmation_key_pem.end());
    }

    ccf::crypto::ECPublicKeyPtr holder;
    try
    {
      holder = ccf::crypto::make_ec_public_key(public_key);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the public key is not a public key: ") + e.what());
    }

    // Preparing a statement against a key the certificate does not belong to
    // would produce something that can never verify, so it is refused here.
    try
    {
      if (ccf::crypto::public_key_pem_from_cert(leaf_der) != public_key)
      {
        throw InvalidInput(
          "the leaf certificate does not certify the supplied public key");
      }
    }
    catch (const InvalidInput&)
    {
      throw;
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the leaf certificate has no usable public key: ") +
        e.what());
    }

    // The algorithm goes into the signed protected header, so it has to be
    // the one the holder will actually sign with.
    int64_t cose_alg = 0;
    try
    {
      cose_alg = sdcwt::cose_es_alg_for_curve(holder->get_curve_id());
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the public key cannot sign this profile: ") + e.what());
    }

    IssuerIdentity issuer;
    issuer.issuer_did = make_subject_did(root_der);
    issuer.subject = profile::REPORT_SUBJECT;
    issuer.x5chain_der = {leaf_der, root_der};

    report::PreparedReport prepared;
    try
    {
      prepared = report::prepare(input, issuer, cose_alg);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("could not prepare the report: ") + e.what());
    }

    std::vector<disclosure_set::Entry> entries;
    entries.reserve(prepared.disclosures.size());
    for (const auto& disclosure : prepared.disclosures)
    {
      entries.push_back({disclosure.path, disclosure.encoded});
    }

    PreparedStatement out;
    out.to_be_signed = std::move(prepared.to_be_signed);
    out.protected_header = std::move(prepared.protected_header);
    out.payload = std::move(prepared.payload);
    try
    {
      out.disclosure_set = disclosure_set::encode(entries);
    }
    catch (const std::exception& e)
    {
      throw OperationFailed(
        std::string("could not build the disclosure set: ") + e.what());
    }
    out.disclosure_count = entries.size();
    out.body_chunk_count = prepared.body_chunk_count;
    out.reference_count = prepared.reference_count;
    out.issuer_did = issuer.issuer_did;
    return out;
  }

  Bytes attach_signature(
    std::span<const uint8_t> protected_header,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature)
  {
    require_size(
      protected_header.size(),
      limits::MAX_STATEMENT_BYTES,
      "the protected header");
    require_size(payload.size(), limits::MAX_STATEMENT_BYTES, "the payload");
    if (protected_header.empty() || payload.empty())
    {
      throw InvalidInput("the prepared statement is incomplete");
    }
    if (signature.size() != ES256_SIGNATURE_BYTES)
    {
      throw InvalidInput(
        "the signature must be " + std::to_string(ES256_SIGNATURE_BYTES) +
        " bytes of raw r||s");
    }

    try
    {
      return sdcwt::assemble_cose_sign1(protected_header, payload, signature);
    }
    catch (const std::exception& e)
    {
      throw OperationFailed(
        std::string("could not assemble the statement: ") + e.what());
    }
  }

  PreparedRelease prepare_release(
    std::span<const uint8_t> bundle_bytes,
    std::span<const uint8_t> public_key_pem)
  {
    require_size(
      bundle_bytes.size(), limits::MAX_BUNDLE_BYTES, "the proof bundle");
    if (bundle_bytes.empty())
    {
      throw InvalidInput("the proof bundle is empty");
    }
    const auto public_key = to_pem(public_key_pem, "the release public key");

    ccf::crypto::ECPublicKeyPtr holder;
    try
    {
      holder = ccf::crypto::make_ec_public_key(public_key);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the release key is not a public key: ") + e.what());
    }

    try
    {
      const auto alg = sdcwt::cose_es_alg_for_curve(holder->get_curve_id());
      PreparedRelease out;
      out.protected_header = sdcwt::encode_protected_header(alg);
      out.payload.assign(bundle_bytes.begin(), bundle_bytes.end());
      out.to_be_signed =
        sdcwt::cose_to_be_signed(out.protected_header, out.payload);
      return out;
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("could not prepare the release: ") + e.what());
    }
  }

  // --- demo transparency service ---------------------------------------------

  MockRegistration mock_register_statement(
    std::span<const uint8_t> registered_statement,
    std::span<const uint8_t> ledger_key_pem)
  {
    require_size(
      registered_statement.size(),
      limits::MAX_STATEMENT_BYTES,
      "the registered statement");
    if (registered_statement.empty())
    {
      throw InvalidInput("the registered statement is empty");
    }
    const auto key = to_key(ledger_key_pem, "the ledger private key");

    MockRegistration out;
    try
    {
      const auto alg = sdcwt::cose_es_alg_for_curve(key->get_curve_id());
      const auto phdr = sdcwt::encode_protected_header(alg);
      // The receipt's payload is the exact registered statement, so it is
      // bound to those bytes and to nothing else.
      out.receipt = sdcwt::sign_cose_sign1(*key, phdr, registered_statement);
      out.transparent_statement = sdcwt::set_unprotected_bstr_array(
        registered_statement, label::SCITT_RECEIPTS, {out.receipt});
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("could not register the statement: ") + e.what());
    }
    return out;
  }

  // --- proof bundles ---------------------------------------------------------

  CreatedBundle create_bundle(
    std::span<const uint8_t> registered_statement,
    std::span<const uint8_t> transparent_statement,
    std::span<const uint8_t> disclosures,
    std::string_view scitt_url,
    std::string_view txid,
    std::optional<int64_t> timestamp)
  {
    require_size(
      registered_statement.size(),
      limits::MAX_STATEMENT_BYTES,
      "the registered statement");
    require_size(
      transparent_statement.size(),
      limits::MAX_STATEMENT_BYTES,
      "the transparent statement");
    require_size(
      disclosures.size(),
      limits::MAX_DISCLOSURE_SET_BYTES,
      "the disclosure set");

    bundle::ProofBundle proof;
    proof.version = bundle::VERSION;
    proof.registered_statement = {
      registered_statement.begin(), registered_statement.end()};
    proof.transparent_statement = {
      transparent_statement.begin(), transparent_statement.end()};
    proof.scitt_url = scitt_url;
    proof.txid = txid;
    proof.timestamp = timestamp.value_or(now_seconds());

    std::vector<disclosure_set::Entry> entries;
    try
    {
      entries = disclosure_set::decode(disclosures);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the disclosure set could not be read: ") + e.what());
    }
    proof.disclosures.reserve(entries.size());
    for (auto& entry : entries)
    {
      proof.disclosures.push_back(std::move(entry.encoded));
    }

    CreatedBundle created;
    created.disclosure_count = proof.disclosures.size();
    try
    {
      created.bundle = bundle::encode(proof);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("could not build the proof bundle: ") + e.what());
    }
    return created;
  }

  std::string inspect_bundle(std::span<const uint8_t> bundle_bytes)
  {
    const auto proof = decode_bundle(bundle_bytes, "could not be read");

    verify::Result result;
    try
    {
      result = verify::inspect_bundle(proof);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the proof bundle cannot be displayed: ") + e.what());
    }
    return inspection_document(proof, result).dump(2);
  }

  Statements extract_statements(std::span<const uint8_t> bundle_bytes)
  {
    auto proof = decode_bundle(bundle_bytes, "could not be read");
    // Verbatim: these are the bytes a receipt is bound to.
    Statements statements;
    statements.registered_statement = std::move(proof.registered_statement);
    statements.transparent_statement = std::move(proof.transparent_statement);
    return statements;
  }

  PresentedBundle present_bundle(
    std::span<const uint8_t> bundle_bytes, std::string_view selection_json)
  {
    const auto selection = parse_selection(selection_json);
    const auto proof = decode_bundle(bundle_bytes, "could not be read");

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
      throw InvalidInput(
        std::string("the proof bundle cannot be presented: ") + e.what());
    }

    bundle::ProofBundle presented = proof;
    presented.disclosures.clear();
    PresentedBundle result;
    result.total = proof.disclosures.size();
    for (size_t i = 0; i < proof.disclosures.size(); ++i)
    {
      if (drop_disclosure(before.disclosure_paths.at(i), selection))
      {
        ++result.dropped;
        continue;
      }
      presented.disclosures.push_back(proof.disclosures.at(i));
    }

    try
    {
      result.bundle = bundle::encode(presented);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
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
      throw InvalidInput(
        std::string("the presented bundle would not be readable: ") + e.what());
    }
    return result;
  }

  VerificationOutcome verify_bundle(
    std::span<const uint8_t> bundle_bytes,
    std::span<const uint8_t> msrc_root_pem,
    const std::optional<std::span<const uint8_t>>& scitt_trust)
  {
    if (scitt_trust.has_value())
    {
      // Deliberately not parsed: this API has no opinion about receipts. A
      // caller that passed nothing useful is told so rather than being left to
      // believe a receipt was considered.
      require_size(
        scitt_trust->size(),
        limits::MAX_TRUST_MATERIAL_BYTES,
        "the SCITT trust material");
      if (scitt_trust->empty())
      {
        throw InvalidInput("the SCITT trust material is empty");
      }
    }

    require_size(
      bundle_bytes.size(), limits::MAX_BUNDLE_BYTES, "the proof bundle");
    require_size(msrc_root_pem.size(), limits::MAX_PEM_BYTES, "the MSRC root");

    bundle::ProofBundle proof;
    try
    {
      proof = bundle::decode(bundle_bytes);
    }
    catch (const std::exception& e)
    {
      return failed_outcome(
        verify::Check::StatementBinding,
        std::string("the proof bundle could not be read: ") + e.what());
    }

    verify::Params params;
    // CCF's certificate API cannot add an Extended Key Usage extension, so the
    // demo profile pins the leaf subject in the did:x509 instead. The DID's CA
    // fingerprint pin and its policies are still enforced by the core.
    params.required_eku = "";
    try
    {
      params.trusted_root = ccf::crypto::Pem(msrc_root_pem);
    }
    catch (const std::exception& e)
    {
      return failed_outcome(
        verify::Check::MsrcChain,
        std::string("the MSRC root is not a PEM document: ") + e.what());
    }

    verify::Result result;
    try
    {
      result = verify::verify_bundle(proof, params);
    }
    catch (const verify::VerificationError& e)
    {
      return failed_outcome(e.check(), e.reason());
    }
    catch (const std::exception& e)
    {
      return failed_outcome(
        verify::Check::StatementBinding,
        std::string("the proof bundle could not be checked: ") + e.what());
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

    VerificationOutcome outcome;
    outcome.passed = true;
    outcome.report_json =
      verification_document(std::nullopt, {}, notes, details).dump(2);
    return outcome;
  }

  Bytes release_payload(std::span<const uint8_t> release_bytes)
  {
    require_size(
      release_bytes.size(), limits::MAX_BUNDLE_BYTES, "the signed release");
    try
    {
      return verify::cose_payload(release_bytes);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string("the release is not a COSE_Sign1: ") + e.what());
    }
  }

  ReleaseOutcome verify_release(
    std::span<const uint8_t> release_bytes,
    std::span<const uint8_t> msrc_root_pem,
    const std::optional<std::span<const uint8_t>>& scitt_trust)
  {
    require_size(
      release_bytes.size(), limits::MAX_BUNDLE_BYTES, "the signed release");
    if (release_bytes.empty())
    {
      throw InvalidInput("the signed release is empty");
    }

    ReleaseOutcome out;
    ordered_json release_check;
    release_check["id"] = "release_signature";
    release_check["label"] = "Release signature";

    Bytes bundle_bytes;
    try
    {
      bundle_bytes = verify::cose_payload(release_bytes);
    }
    catch (const std::exception& e)
    {
      out.reason = std::string("the release is not a COSE_Sign1: ") + e.what();
      release_check["status"] = "fail";
      release_check["detail"] = out.reason;
      ordered_json report;
      report["overall"] = "fail";
      report["checks"] = ordered_json::array({release_check});
      report["detail"] = out.reason;
      out.report_json = report.dump(2);
      return out;
    }

    const auto inner = verify_bundle(bundle_bytes, msrc_root_pem, scitt_trust);

    std::string failure;
    std::string confirmation;
    try
    {
      confirmation = verify::confirmation_key_pem(
        extract_statements(bundle_bytes).registered_statement);
    }
    catch (const std::exception& e)
    {
      failure =
        std::string("the enclosed statement could not be read: ") + e.what();
    }

    if (!failure.empty())
    {
      release_check["status"] = "fail";
      release_check["detail"] = failure;
    }
    else if (confirmation.empty())
    {
      release_check["status"] = "unattributable";
      release_check["detail"] =
        "The statement names no discloser, so nothing binds this release to "
        "anyone. What it contains is still checked below.";
    }
    else
    {
      out.attributable = true;
      bool verified = false;
      try
      {
        auto verifier = ccf::crypto::make_cose_verifier_from_key(
          ccf::crypto::Pem(confirmation));
        std::span<uint8_t> authenticated;
        verified = verifier->verify(release_bytes, authenticated);
      }
      catch (const std::exception&)
      {
        verified = false;
      }
      release_check["status"] = verified ? "pass" : "fail";
      release_check["detail"] = verified ?
        "Signed by the key the statement names in cnf, so this release is the "
        "act of the party the issuer nominated." :
        "Not signed by the key the statement names in cnf.";
      if (!verified)
      {
        failure = "the release is not signed by the key named in cnf";
      }
    }

    ordered_json report;
    try
    {
      report = ordered_json::parse(inner.report_json);
    }
    catch (const std::exception&)
    {
      report = ordered_json::object();
      report["checks"] = ordered_json::array();
    }

    auto checks = ordered_json::array({release_check});
    for (const auto& check : report["checks"])
    {
      checks.push_back(check);
    }
    report["checks"] = checks;

    out.passed = inner.passed && release_check["status"] != "fail";
    report["overall"] = out.passed ? "pass" : "fail";
    if (!out.passed)
    {
      out.reason = failure.empty() ? inner.reason : failure;
      report["detail"] = out.reason;
    }
    out.report_json = report.dump(2);
    return out;
  }
}
