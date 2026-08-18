// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/ccf_receipt.h"

#include "core/profile.h"

#include <ccf/_private/crypto/cbor.h>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/sha256.h>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace scitt_sd::verify
{
  namespace
  {
    namespace cbor = ccf::cbor;

    // COSE header labels a CCF receipt uses, beyond the COSE basics.
    constexpr int64_t HEADER_CWT_CLAIMS = 15;
    constexpr int64_t HEADER_VDS = 395;
    constexpr int64_t HEADER_INCLUSION_PROOF = 396;

    // The only verifiable data structure this verifier understands:
    // CCF_LEDGER_SHA256.
    constexpr int64_t VDS_CCF_LEDGER_SHA256 = 2;

    // Inside the 396 header, the proofs for that structure.
    constexpr int64_t PROOF_CCF_LEDGER_SHA256 = -1;

    // Inside one proof: the leaf's three components, and the path to the root.
    constexpr int64_t PROOF_LEAF = 1;
    constexpr int64_t PROOF_PATH = 2;

    constexpr int64_t CWT_ISS = 1;

    constexpr size_t SHA256_BYTES = 32;

    // A path of this length covers a ledger of 2^64 entries; anything longer
    // is a malformed proof trying to make us hash forever.
    constexpr size_t MAX_PATH_ELEMENTS = 64;

    [[noreturn]] void fail(const std::string& why)
    {
      throw VerificationError(why, Check::Receipt);
    }

    void require(bool condition, const std::string& why)
    {
      if (!condition)
      {
        fail(why);
      }
    }

    bool is_bytes(const cbor::Value& value)
    {
      return std::holds_alternative<cbor::Bytes>(value->value);
    }

    std::vector<uint8_t> copy_bytes(const cbor::Value& value)
    {
      const auto bytes = value->as_bytes();
      return {bytes.begin(), bytes.end()};
    }

    // The value for `label`, or nullptr. Rejects a repeated label rather than
    // taking the first: a duplicate would let a second, ignored proof ride
    // along inside the same header.
    const cbor::Value* lookup(const cbor::Map& map, int64_t label)
    {
      const cbor::Value* found = nullptr;
      for (const auto& [key, value] : map.items)
      {
        if (
          !std::holds_alternative<cbor::Signed>(key->value) ||
          key->as_signed() != label)
        {
          continue;
        }
        require(
          found == nullptr,
          "the receipt repeats header " + std::to_string(label));
        found = &value;
      }
      return found;
    }

    const cbor::Value* lookup(const cbor::Map& map, std::string_view label)
    {
      const cbor::Value* found = nullptr;
      for (const auto& [key, value] : map.items)
      {
        if (
          !std::holds_alternative<cbor::String>(key->value) ||
          key->as_string() != label)
        {
          continue;
        }
        require(
          found == nullptr, "the receipt repeats header " + std::string(label));
        found = &value;
      }
      return found;
    }

    const cbor::Map& as_map(const cbor::Value& value, const std::string& what)
    {
      require(
        std::holds_alternative<cbor::Map>(value->value),
        what + " is not a map");
      return std::get<cbor::Map>(value->value);
    }

    const cbor::Array& as_array(
      const cbor::Value& value, const std::string& what)
    {
      require(
        std::holds_alternative<cbor::Array>(value->value),
        what + " is not an array");
      return std::get<cbor::Array>(value->value);
    }

    cbor::Value parse_or_fail(
      std::span<const uint8_t> encoded, const std::string& what)
    {
      try
      {
        return cbor::parse(encoded);
      }
      catch (const std::exception&)
      {
        fail("malformed CBOR in " + what);
      }
    }

    std::vector<uint8_t> sha256(std::span<const uint8_t> data)
    {
      const auto digest = ccf::crypto::sha256(data);
      return {digest.begin(), digest.end()};
    }

    // The parts of a receipt this verifier needs.
    struct Receipt
    {
      std::vector<uint8_t> protected_header;
      cbor::Value unprotected; // borrows from the parsed receipt
    };

    // A COSE_Sign1 whose payload is detached. The signature is left in the
    // envelope: CCF's verifier re-reads it from there.
    Receipt parse_receipt(const cbor::Value& root)
    {
      const cbor::Value* envelope = nullptr;
      try
      {
        envelope = &root->tag_at(cbor::tag::COSE_SIGN_1);
      }
      catch (const std::exception&)
      {
        fail("the receipt is not a tagged COSE_Sign1 (tag 18)");
      }

      const auto& parts = as_array(*envelope, "the receipt").items;
      require(
        parts.size() == 4, "the receipt must have four COSE_Sign1 fields");
      require(
        is_bytes(parts[0]), "the receipt protected header must be a bstr");
      require(is_bytes(parts[3]), "the receipt signature must be a bstr");

      // The payload must be absent: a receipt that carried one would be
      // signing something other than the Merkle root computed below.
      require(
        std::holds_alternative<cbor::Simple>(parts[2]->value) &&
          parts[2]->as_simple() == cbor::SimpleValue::Null,
        "the receipt payload must be detached");

      return {copy_bytes(parts[0]), parts[1]};
    }

    // The Merkle leaf CCF commits to for one transaction.
    std::vector<uint8_t> leaf_digest(
      std::span<const uint8_t> write_set_digest,
      std::string_view commit_evidence,
      std::span<const uint8_t> claims_digest)
    {
      const std::span<const uint8_t> evidence{
        reinterpret_cast<const uint8_t*>(commit_evidence.data()),
        commit_evidence.size()};
      const auto evidence_digest = sha256(evidence);

      std::vector<uint8_t> preimage;
      preimage.reserve(
        write_set_digest.size() + evidence_digest.size() +
        claims_digest.size());
      preimage.insert(
        preimage.end(), write_set_digest.begin(), write_set_digest.end());
      preimage.insert(
        preimage.end(), evidence_digest.begin(), evidence_digest.end());
      preimage.insert(
        preimage.end(), claims_digest.begin(), claims_digest.end());
      return sha256(preimage);
    }

    // Fold the proof path into the leaf. Each element says whether its digest
    // sits to the left of what has been accumulated so far.
    std::vector<uint8_t> fold_path(
      std::vector<uint8_t> current, const cbor::Array& path)
    {
      require(
        path.items.size() <= MAX_PATH_ELEMENTS,
        "the receipt inclusion proof path is implausibly long");

      for (const auto& element : path.items)
      {
        const auto& pair =
          as_array(element, "an inclusion proof element").items;
        require(
          pair.size() == 2,
          "an inclusion proof element must be [left, digest]");
        require(
          std::holds_alternative<cbor::Simple>(pair[0]->value),
          "an inclusion proof element must say which side it is on");
        require(
          is_bytes(pair[1]) && pair[1]->as_bytes().size() == SHA256_BYTES,
          "an inclusion proof element must carry a SHA-256 digest");

        const bool on_the_left = cbor::simple_to_boolean(pair[0]->as_simple());
        const auto sibling = pair[1]->as_bytes();

        std::vector<uint8_t> preimage;
        preimage.reserve(sibling.size() + current.size());
        if (on_the_left)
        {
          preimage.insert(preimage.end(), sibling.begin(), sibling.end());
          preimage.insert(preimage.end(), current.begin(), current.end());
        }
        else
        {
          preimage.insert(preimage.end(), current.begin(), current.end());
          preimage.insert(preimage.end(), sibling.begin(), sibling.end());
        }
        current = sha256(preimage);
      }
      return current;
    }

    // What the receipt says about itself. Read only after the signature has
    // verified, so that nothing unauthenticated is ever reported.
    ReceiptInfo describe(const cbor::Map& protected_header)
    {
      ReceiptInfo info;

      const auto* claims = lookup(protected_header, HEADER_CWT_CLAIMS);
      if (claims != nullptr)
      {
        const auto* issuer =
          lookup(as_map(*claims, "the receipt CWT claims"), CWT_ISS);
        if (
          issuer != nullptr &&
          std::holds_alternative<cbor::String>((*issuer)->value))
        {
          const auto text = (*issuer)->as_string();
          info.issuer = {text.begin(), text.end()};
        }
      }

      const auto* ccf_claims = lookup(protected_header, "ccf.v1");
      if (ccf_claims != nullptr)
      {
        const auto* txid =
          lookup(as_map(*ccf_claims, "the receipt CCF claims"), "txid");
        if (
          txid != nullptr &&
          std::holds_alternative<cbor::String>((*txid)->value))
        {
          const auto text = (*txid)->as_string();
          info.txid = {text.begin(), text.end()};
        }
      }
      return info;
    }
  }

  CcfReceiptVerifier::CcfReceiptVerifier(ccf::crypto::Pem service_certificate) :
    certificate(std::move(service_certificate))
  {}

  ReceiptInfo CcfReceiptVerifier::verify(
    std::span<const uint8_t> receipt,
    std::span<const uint8_t> registered_statement) const
  {
    const auto root_value = parse_or_fail(receipt, "the receipt");
    const auto parsed = parse_receipt(root_value);

    const auto header_value =
      parse_or_fail(parsed.protected_header, "the receipt protected header");
    const auto& protected_header =
      as_map(header_value, "the receipt protected header");

    const auto* vds = lookup(protected_header, HEADER_VDS);
    require(
      vds != nullptr && std::holds_alternative<cbor::Signed>((*vds)->value) &&
        (*vds)->as_signed() == VDS_CCF_LEDGER_SHA256,
      "the receipt is not over a CCF SHA-256 ledger");

    const auto& unprotected =
      as_map(parsed.unprotected, "the receipt unprotected header");
    const auto* proofs = lookup(unprotected, HEADER_INCLUSION_PROOF);
    require(proofs != nullptr, "the receipt carries no inclusion proof");

    const auto* for_this_structure = lookup(
      as_map(*proofs, "the receipt inclusion proof"), PROOF_CCF_LEDGER_SHA256);
    require(
      for_this_structure != nullptr,
      "the receipt carries no CCF SHA-256 inclusion proof");

    const auto& proof_list =
      as_array(*for_this_structure, "the receipt inclusion proofs").items;
    require(
      proof_list.size() == 1,
      "the receipt must carry exactly one inclusion proof");
    require(is_bytes(proof_list[0]), "the inclusion proof must be a bstr");

    const auto proof_value =
      parse_or_fail(proof_list[0]->as_bytes(), "the inclusion proof");
    const auto& proof = as_map(proof_value, "the inclusion proof");

    const auto* leaf = lookup(proof, PROOF_LEAF);
    require(leaf != nullptr, "the inclusion proof has no leaf");
    const auto& components = as_array(*leaf, "the inclusion proof leaf").items;
    require(
      components.size() == 3,
      "the inclusion proof leaf must have three components");
    require(
      is_bytes(components[0]) &&
        components[0]->as_bytes().size() == SHA256_BYTES,
      "the leaf write set digest must be a SHA-256 digest");
    require(
      std::holds_alternative<cbor::String>(components[1]->value),
      "the leaf commit evidence must be a text string");
    require(
      is_bytes(components[2]) &&
        components[2]->as_bytes().size() == SHA256_BYTES,
      "the leaf claims digest must be a SHA-256 digest");

    // The only place the statement enters the proof. Without this the receipt
    // would attest to some transaction, but not to this statement.
    const auto claims_digest = components[2]->as_bytes();
    if (!std::ranges::equal(claims_digest, sha256(registered_statement)))
    {
      fail("the receipt covers a different statement");
    }

    const auto* path = lookup(proof, PROOF_PATH);
    require(path != nullptr, "the inclusion proof has no path");

    const auto merkle_root = fold_path(
      leaf_digest(
        components[0]->as_bytes(), components[1]->as_string(), claims_digest),
      as_array(*path, "the inclusion proof path"));

    bool signed_by_service = false;
    try
    {
      signed_by_service =
        ccf::crypto::make_cose_verifier_from_pem_cert(certificate)
          ->verify_detached(receipt, merkle_root);
    }
    catch (const std::exception& e)
    {
      fail(std::string("the receipt could not be checked: ") + e.what());
    }
    if (!signed_by_service)
    {
      fail(
        "the transparency service did not sign the root this statement leads "
        "to");
    }

    return describe(protected_header);
  }
}
