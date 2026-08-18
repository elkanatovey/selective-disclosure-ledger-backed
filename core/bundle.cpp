// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/bundle.h"

#include "core/cbor_value.h"

#include <ccf/_private/crypto/cbor.h>
#include <stdexcept>

namespace scitt_sd::bundle
{
  namespace
  {
    namespace cbor = ccf::cbor;

    void require(bool condition, const std::string& why)
    {
      if (!condition)
      {
        throw std::invalid_argument("proof bundle: " + why);
      }
    }

    const cbor::Value& require_label(const cbor::Map& map, int64_t wanted)
    {
      const cbor::Value* found = nullptr;
      for (const auto& [key, value] : map.items)
      {
        if (!std::holds_alternative<cbor::Signed>(key->value))
        {
          continue;
        }
        if (key->as_signed() != wanted)
        {
          continue;
        }
        // map_at would return the first match and silently ignore a second
        // entry with the same label, so duplicates are rejected here.
        require(
          found == nullptr,
          "duplicate label " + std::to_string(wanted) + " in bundle");
        found = &value;
      }
      require(found != nullptr, "missing label " + std::to_string(wanted));
      return *found;
    }

    std::vector<uint8_t> decode_bytes(
      const cbor::Value& value, size_t max_size, const std::string& what)
    {
      require(
        std::holds_alternative<cbor::Bytes>(value->value),
        what + " must be a byte string");
      const auto bytes = value->as_bytes();
      require(!bytes.empty(), what + " must not be empty");
      require(bytes.size() <= max_size, what + " is too large");
      return {bytes.begin(), bytes.end()};
    }

    std::string decode_text(
      const cbor::Value& value, size_t max_chars, const std::string& what)
    {
      require(
        std::holds_alternative<cbor::String>(value->value),
        what + " must be a text string");
      const auto text = value->as_string();
      require(!text.empty(), what + " must not be empty");
      require(text.size() <= max_chars, what + " is too long");
      return {text.begin(), text.end()};
    }

    int64_t decode_uint(const cbor::Value& value, const std::string& what)
    {
      require(
        std::holds_alternative<cbor::Signed>(value->value),
        what + " must be an integer");
      const auto number = value->as_signed();
      require(number >= 0, what + " must not be negative");
      return number;
    }

    void validate(const ProofBundle& bundle)
    {
      require(bundle.version == VERSION, "unsupported version");
      require(
        !bundle.registered_statement.empty() &&
          bundle.registered_statement.size() <= MAX_STATEMENT_BYTES,
        "registered statement size out of range");
      require(
        !bundle.transparent_statement.empty() &&
          bundle.transparent_statement.size() <= MAX_STATEMENT_BYTES,
        "transparent statement size out of range");
      require(
        bundle.disclosures.size() <= MAX_DISCLOSURES, "too many disclosures");
      for (const auto& disclosure : bundle.disclosures)
      {
        require(
          !disclosure.empty() && disclosure.size() <= MAX_DISCLOSURE_BYTES,
          "disclosure size out of range");
      }
      require(
        !bundle.scitt_url.empty() && bundle.scitt_url.size() <= MAX_URL_CHARS,
        "SCITT URL length out of range");
      require(
        !bundle.txid.empty() && bundle.txid.size() <= MAX_TXID_CHARS,
        "transaction id length out of range");
      require(bundle.timestamp >= 0, "timestamp must not be negative");
    }
  }

  std::vector<uint8_t> encode(const ProofBundle& bundle)
  {
    validate(bundle);

    std::vector<cbor::Value> disclosures;
    disclosures.reserve(bundle.disclosures.size());
    for (const auto& disclosure : bundle.disclosures)
    {
      disclosures.push_back(sdcwt::bytes_value(disclosure));
    }

    // Labels are emitted in ascending order, which is also CDE order for
    // small unsigned integer keys.
    return cbor::serialize(cbor::make_map(
      {{cbor::make_signed(label::VERSION), cbor::make_signed(bundle.version)},
       {cbor::make_signed(label::REGISTERED_STATEMENT),
        sdcwt::bytes_value(bundle.registered_statement)},
       {cbor::make_signed(label::TRANSPARENT_STATEMENT),
        sdcwt::bytes_value(bundle.transparent_statement)},
       {cbor::make_signed(label::DISCLOSURES),
        cbor::make_array(std::move(disclosures))},
       {cbor::make_signed(label::SCITT_URL),
        cbor::make_string(bundle.scitt_url)},
       {cbor::make_signed(label::TXID), cbor::make_string(bundle.txid)},
       {cbor::make_signed(label::TIMESTAMP),
        cbor::make_signed(bundle.timestamp)}}));
  }

  ProofBundle decode(std::span<const uint8_t> encoded)
  {
    cbor::Value root;
    try
    {
      root = cbor::parse(encoded);
    }
    catch (const std::exception& e)
    {
      throw std::runtime_error(
        std::string("proof bundle: malformed CBOR: ") + e.what());
    }

    require(
      std::holds_alternative<cbor::Map>(root->value),
      "top level item must be a map");
    const auto& map = std::get<cbor::Map>(root->value);
    // An exact entry count plus a per-label duplicate check leaves no room
    // for an unknown or repeated entry.
    require(
      map.items.size() == ENTRY_COUNT,
      "expected " + std::to_string(ENTRY_COUNT) + " entries, got " +
        std::to_string(map.items.size()));

    ProofBundle out;

    out.version = decode_uint(require_label(map, label::VERSION), "version");
    require(out.version == VERSION, "unsupported version");

    out.registered_statement = decode_bytes(
      require_label(map, label::REGISTERED_STATEMENT),
      MAX_STATEMENT_BYTES,
      "registered statement");
    out.transparent_statement = decode_bytes(
      require_label(map, label::TRANSPARENT_STATEMENT),
      MAX_STATEMENT_BYTES,
      "transparent statement");

    const auto& disclosures = require_label(map, label::DISCLOSURES);
    require(
      std::holds_alternative<cbor::Array>(disclosures->value),
      "disclosures must be an array");
    const auto& items = std::get<cbor::Array>(disclosures->value).items;
    require(items.size() <= MAX_DISCLOSURES, "too many disclosures");
    out.disclosures.reserve(items.size());
    for (const auto& item : items)
    {
      out.disclosures.push_back(
        decode_bytes(item, MAX_DISCLOSURE_BYTES, "disclosure"));
    }

    out.scitt_url = decode_text(
      require_label(map, label::SCITT_URL), MAX_URL_CHARS, "SCITT URL");
    out.txid = decode_text(
      require_label(map, label::TXID), MAX_TXID_CHARS, "transaction id");
    out.timestamp =
      decode_uint(require_label(map, label::TIMESTAMP), "timestamp");

    return out;
  }
}
