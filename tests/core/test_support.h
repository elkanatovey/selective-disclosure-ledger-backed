// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// Shared helpers for the core tests. Every key and certificate is produced by
// the CCF crypto APIs (or, for the one case CCF cannot express, by the
// documented test-only fixture in eku_test_certs.h); the tests never implement
// cryptography of their own.

#include "core/bundle.h"
#include "core/profile.h"
#include "core/report.h"
#include "core/sd_cwt.h"
#include "core/sd_cwt_internal.h"
#include "core/verify.h"
#include "tests/core/eku_test_certs.h"

#include <algorithm>
#include <ccf/_private/crypto/certs.h>
#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/verifier.h>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace scitt_sd::testing
{
  inline std::string to_hex(std::span<const uint8_t> bytes)
  {
    static constexpr std::string_view DIGITS = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
      out.push_back(DIGITS[byte >> 4U]);
      out.push_back(DIGITS[byte & 0x0FU]);
    }
    return out;
  }

  inline bool contains(
    std::span<const uint8_t> haystack, std::span<const uint8_t> needle)
  {
    return std::search(
             haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
      haystack.end();
  }

  inline bool contains(std::span<const uint8_t> haystack, std::string_view text)
  {
    const std::span<const uint8_t> needle(
      reinterpret_cast<const uint8_t*>(text.data()), text.size());
    return contains(haystack, needle);
  }

  // A deterministic, reproducible randomness source for issuance tests: byte i
  // of the n-th draw is seed + n + i. It exists only behind the internal
  // detail:: entry points, so it cannot reach a production caller.
  inline sdcwt::RandomSource counting_random_source(uint8_t seed = 0)
  {
    auto counter = std::make_shared<uint8_t>(seed);
    return [counter](size_t size) {
      std::vector<uint8_t> out(size);
      for (size_t i = 0; i < size; ++i)
      {
        out[i] = static_cast<uint8_t>(*counter + i);
      }
      ++*counter;
      return out;
    };
  }

  // A certificate chain plus the keys behind it.
  struct Chain
  {
    ccf::crypto::ECKeyPairPtr root_key;
    ccf::crypto::Pem root_pem;
    std::vector<uint8_t> root_der;
    ccf::crypto::ECKeyPairPtr leaf_key;
    ccf::crypto::Pem leaf_pem;
    std::vector<uint8_t> leaf_der;

    [[nodiscard]] std::vector<std::vector<uint8_t>> x5chain() const
    {
      return {leaf_der, root_der};
    }
  };

  // A chain built entirely with the CCF certificate helpers. Those helpers
  // cannot add an Extended Key Usage extension, so this chain is used with
  // did:x509 subject policies (and to drive the EKU negative tests).
  inline Chain make_ccf_chain(
    const std::string& leaf_cn = "test-issuer",
    const std::string& valid_from = "20240101000000Z",
    size_t validity_days = 3650)
  {
    Chain chain;
    chain.root_key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    chain.root_pem = ccf::crypto::create_self_signed_cert(
      chain.root_key, "CN=test-root", {}, valid_from, validity_days);
    chain.root_der = ccf::crypto::cert_pem_to_der(chain.root_pem);

    chain.leaf_key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    chain.leaf_pem = ccf::crypto::create_endorsed_cert(
      chain.leaf_key,
      "CN=" + leaf_cn,
      {},
      valid_from,
      validity_days,
      chain.root_key->private_key_pem(),
      chain.root_pem);
    chain.leaf_der = ccf::crypto::cert_pem_to_der(chain.leaf_pem);
    return chain;
  }

  // The test-only fixture chain whose leaf carries id-kp-codeSigning.
  inline Chain load_eku_chain()
  {
    Chain chain;
    chain.root_pem = ccf::crypto::Pem(EKU_ROOT_CA_PEM);
    chain.root_der = ccf::crypto::cert_pem_to_der(chain.root_pem);
    chain.leaf_pem = ccf::crypto::Pem(EKU_LEAF_CERT_PEM);
    chain.leaf_der = ccf::crypto::cert_pem_to_der(chain.leaf_pem);
    chain.leaf_key =
      ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(EKU_LEAF_KEY_PEM));
    return chain;
  }

  // did:x509 pinning `chain`'s root through a subject policy, for chains whose
  // leaf has no EKU extension.
  inline std::string subject_did(const Chain& chain, const std::string& leaf_cn)
  {
    return "did:x509:0:sha256:" + did_x509_ca_fingerprint(chain.root_der) +
      "::subject:CN:" + leaf_cn;
  }

  inline report::ReportInput sample_report()
  {
    report::ReportInput input;
    input.issued_at = 1700000000;
    input.title = "Heap overflow in parser";
    input.body = "Twelve chars";
    input.component = "parser";
    input.severity = "high";
    input.fingerprint = {0xDE, 0xAD, 0xBE, 0xEF};
    input.references = {"CVE-2024-0001", "internal-1234"};
    return input;
  }

  // Attach SCITT receipts (unprotected header 394) to a statement, the way a
  // transparency service does: only the unprotected header changes.

  // The four COSE_Sign1 parts, copied out of the borrowed parse tree.
  struct Sign1Parts
  {
    std::vector<uint8_t> protected_header;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    std::vector<int64_t> unprotected_labels;
  };

  inline std::vector<uint8_t> copy_bytes(const ccf::cbor::Value& value)
  {
    const auto span = value->as_bytes();
    return {span.begin(), span.end()};
  }

  inline Sign1Parts parse_sign1(std::span<const uint8_t> token)
  {
    namespace cbor = ccf::cbor;
    const auto root = cbor::parse(token);
    const auto& parts =
      std::get<cbor::Array>(root->tag_at(cbor::tag::COSE_SIGN_1)->value).items;

    Sign1Parts out;
    out.protected_header = copy_bytes(parts[0]);
    out.payload = copy_bytes(parts[2]);
    out.signature = copy_bytes(parts[3]);
    for (const auto& [key, value] : std::get<cbor::Map>(parts[1]->value).items)
    {
      out.unprotected_labels.push_back(key->as_signed());
    }
    return out;
  }

  inline std::vector<uint8_t> extract_signature(std::span<const uint8_t> token)
  {
    return parse_sign1(token).signature;
  }

  // The byte strings held under an unprotected header label, or an empty
  // vector when the label is absent.
  inline std::vector<std::vector<uint8_t>> unprotected_bstr_array(
    std::span<const uint8_t> token, int64_t header_label)
  {
    namespace cbor = ccf::cbor;
    const auto root = cbor::parse(token);
    const auto& parts =
      std::get<cbor::Array>(root->tag_at(cbor::tag::COSE_SIGN_1)->value).items;

    std::vector<std::vector<uint8_t>> out;
    for (const auto& [key, value] : std::get<cbor::Map>(parts[1]->value).items)
    {
      if (key->as_signed() == header_label)
      {
        for (const auto& item : std::get<cbor::Array>(value->value).items)
        {
          out.push_back(copy_bytes(item));
        }
      }
    }
    return out;
  }

  inline std::vector<uint8_t> attach_receipts(
    std::span<const uint8_t> statement,
    const std::vector<std::vector<uint8_t>>& receipts)
  {
    namespace cbor = ccf::cbor;
    const auto root = cbor::parse(statement);
    const auto& parts =
      std::get<cbor::Array>(root->tag_at(cbor::tag::COSE_SIGN_1)->value).items;

    std::vector<cbor::MapItem> uhdr;
    for (const auto& [key, value] : std::get<cbor::Map>(parts[1]->value).items)
    {
      uhdr.emplace_back(key, value);
    }
    std::vector<cbor::Value> entries;
    entries.reserve(receipts.size());
    for (const auto& receipt : receipts)
    {
      entries.push_back(sdcwt::bytes_value(receipt));
    }
    uhdr.emplace_back(
      cbor::make_signed(label::SCITT_RECEIPTS),
      cbor::make_array(std::move(entries)));

    return cbor::serialize(cbor::make_tagged(
      cbor::tag::COSE_SIGN_1,
      cbor::make_array(
        {parts[0], cbor::make_map(std::move(uhdr)), parts[2], parts[3]})));
  }

  // A receipt verifier that records exactly what it was handed, so a test can
  // assert the registered statement reaches it byte for byte.
  class RecordingReceiptVerifier : public verify::ReceiptVerifier
  {
  public:
    explicit RecordingReceiptVerifier(bool succeed = true) : succeed_(succeed)
    {}

    verify::ReceiptInfo verify(
      std::span<const uint8_t> receipt,
      std::span<const uint8_t> registered_statement) const override
    {
      calls.emplace_back(
        std::vector<uint8_t>(receipt.begin(), receipt.end()),
        std::vector<uint8_t>(
          registered_statement.begin(), registered_statement.end()));
      if (!succeed_)
      {
        throw std::runtime_error("receipt rejected by the test verifier");
      }
      return {"2.14", "did:web:transparency.example"};
    }

    // (receipt bytes, registered statement bytes) for each call, in order.
    mutable std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      calls;

  private:
    bool succeed_;
  };

  // Everything a verification test needs: a chain, an issued report and a
  // bundle carrying a selection of its disclosures.
  struct Scenario
  {
    Chain chain;
    IssuerIdentity issuer;
    report::IssuedReport issued;
    std::vector<uint8_t> receipt{0x52, 0x43, 0x50, 0x54}; // opaque to the core
    bundle::ProofBundle proof;
  };

  inline bundle::ProofBundle make_proof(
    const report::IssuedReport& issued,
    const std::vector<std::vector<uint8_t>>& disclosures,
    const std::vector<uint8_t>& receipt)
  {
    bundle::ProofBundle proof;
    proof.version = bundle::VERSION;
    proof.registered_statement = issued.statement;
    proof.transparent_statement = attach_receipts(issued.statement, {receipt});
    proof.disclosures = disclosures;
    proof.scitt_url = "https://transparency.example";
    proof.txid = "2.14";
    proof.timestamp = 1700000100;
    return proof;
  }

  // A scenario built on the EKU fixture chain: the profile's default
  // did:x509 eku policy therefore holds end to end.
  inline Scenario make_eku_scenario(
    const report::Selection& selection = {{report::label::TITLE}, {}, {}})
  {
    Scenario scenario;
    scenario.chain = load_eku_chain();
    scenario.issuer = {
      make_did_x509(scenario.chain.root_der),
      "bug-report",
      scenario.chain.x5chain()};
    scenario.issued =
      report::issue(sample_report(), scenario.issuer, *scenario.chain.leaf_key);
    scenario.proof = make_proof(
      scenario.issued,
      report::select_disclosures(scenario.issued, selection),
      scenario.receipt);
    return scenario;
  }

  inline verify::Params eku_params(const Chain& chain)
  {
    verify::Params params;
    params.trusted_root = chain.root_pem;
    params.required_eku = std::string(CODE_SIGNING_EKU_OID);
    return params;
  }
}
