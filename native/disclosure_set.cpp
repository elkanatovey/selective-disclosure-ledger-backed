// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli/disclosure_set.h"

#include "core/cbor_value.h"

#include <ccf/_private/crypto/cbor.h>
#include <stdexcept>
#include <string>

namespace scitt_sd::cli::disclosure_set
{
  namespace
  {
    namespace cbor = ccf::cbor;

    void require(bool condition, const std::string& why)
    {
      if (!condition)
      {
        throw std::invalid_argument("disclosure set: " + why);
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
        // map_at returns the first match and ignores a second entry with the
        // same label, so duplicates are rejected here instead.
        require(found == nullptr, "duplicate label " + std::to_string(wanted));
        found = &value;
      }
      require(found != nullptr, "missing label " + std::to_string(wanted));
      return *found;
    }

    void validate(const std::vector<Entry>& entries)
    {
      require(entries.size() <= MAX_DISCLOSURES, "too many disclosures");
      for (const auto& entry : entries)
      {
        require(
          !entry.encoded.empty() &&
            entry.encoded.size() <= MAX_DISCLOSURE_BYTES,
          "disclosure size out of range");
        require(!entry.path.empty(), "a disclosure path must not be empty");
        require(
          entry.path.size() <= MAX_PATH_DEPTH, "a disclosure path is too deep");
        for (const auto& element : entry.path)
        {
          if (const auto* text = std::get_if<std::string>(&element))
          {
            require(
              !text->empty() && text->size() <= MAX_PATH_ELEMENT_CHARS,
              "a disclosure path element is out of range");
          }
        }
      }
    }
  }

  std::vector<uint8_t> encode(const std::vector<Entry>& entries)
  {
    validate(entries);

    // The path elements are copied into an owning tree first: a ccf::cbor
    // string BORROWS its characters, so a temporary would dangle.
    std::vector<sdcwt::CborValue> items;
    items.reserve(entries.size());
    for (const auto& entry : entries)
    {
      std::vector<sdcwt::CborValue> path;
      path.reserve(entry.path.size());
      for (const auto& element : entry.path)
      {
        if (const auto* number = std::get_if<int64_t>(&element))
        {
          path.push_back(sdcwt::CborValue::Int(*number));
        }
        else
        {
          path.push_back(
            sdcwt::CborValue::Text(std::get<std::string>(element)));
        }
      }
      items.push_back(sdcwt::CborValue::Map(
        {{label::PATH, sdcwt::CborValue::Array(std::move(path))},
         {label::ENCODED, sdcwt::CborValue::Bytes(entry.encoded)}}));
    }

    return sdcwt::encode_value(sdcwt::CborValue::Map(
      {{label::VERSION, sdcwt::CborValue::Int(VERSION)},
       {label::DISCLOSURES, sdcwt::CborValue::Array(std::move(items))}}));
  }

  std::vector<Entry> decode(std::span<const uint8_t> encoded)
  {
    cbor::Value root;
    try
    {
      root = cbor::parse(encoded);
    }
    catch (const std::exception& e)
    {
      throw std::runtime_error(
        std::string("disclosure set: malformed CBOR: ") + e.what());
    }

    require(
      std::holds_alternative<cbor::Map>(root->value),
      "top level item must be a map");
    const auto& map = std::get<cbor::Map>(root->value);
    // An exact entry count plus a per-label duplicate check leaves no room for
    // an unknown or repeated entry.
    require(
      map.items.size() == ENTRY_COUNT,
      "expected " + std::to_string(ENTRY_COUNT) + " entries, got " +
        std::to_string(map.items.size()));

    const auto& version = require_label(map, label::VERSION);
    require(
      std::holds_alternative<cbor::Signed>(version->value),
      "version must be an integer");
    require(version->as_signed() == VERSION, "unsupported version");

    const auto& disclosures = require_label(map, label::DISCLOSURES);
    require(
      std::holds_alternative<cbor::Array>(disclosures->value),
      "disclosures must be an array");
    const auto& items = std::get<cbor::Array>(disclosures->value).items;
    require(items.size() <= MAX_DISCLOSURES, "too many disclosures");

    std::vector<Entry> out;
    out.reserve(items.size());
    for (const auto& item : items)
    {
      require(
        std::holds_alternative<cbor::Map>(item->value),
        "a disclosure entry must be a map");
      const auto& entry_map = std::get<cbor::Map>(item->value);
      require(
        entry_map.items.size() == ITEM_ENTRY_COUNT,
        "a disclosure entry must carry exactly a path and its bytes");

      Entry entry;

      const auto& path = require_label(entry_map, label::PATH);
      require(
        std::holds_alternative<cbor::Array>(path->value),
        "a disclosure path must be an array");
      const auto& elements = std::get<cbor::Array>(path->value).items;
      require(!elements.empty(), "a disclosure path must not be empty");
      require(
        elements.size() <= MAX_PATH_DEPTH, "a disclosure path is too deep");
      for (const auto& element : elements)
      {
        if (std::holds_alternative<cbor::Signed>(element->value))
        {
          entry.path.emplace_back(element->as_signed());
          continue;
        }
        require(
          std::holds_alternative<cbor::String>(element->value),
          "a disclosure path element must be an integer or a text string");
        const auto text = element->as_string();
        require(
          !text.empty() && text.size() <= MAX_PATH_ELEMENT_CHARS,
          "a disclosure path element is out of range");
        entry.path.emplace_back(std::string(text));
      }

      const auto& bytes = require_label(entry_map, label::ENCODED);
      require(
        std::holds_alternative<cbor::Bytes>(bytes->value),
        "a disclosure must be a byte string");
      const auto span = bytes->as_bytes();
      require(
        !span.empty() && span.size() <= MAX_DISCLOSURE_BYTES,
        "disclosure size out of range");
      entry.encoded.assign(span.begin(), span.end());

      out.push_back(std::move(entry));
    }
    return out;
  }
}
