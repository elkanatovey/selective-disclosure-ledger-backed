// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/sd_cwt.h"

#include "core/cose.h"
#include "core/sd_cwt_internal.h"

#include <algorithm>
#include <ccf/crypto/entropy.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/md_type.h>

namespace sdcwt
{
  namespace
  {
    ccf::crypto::MDType md_for_hash_alg(HashAlg sd_alg)
    {
      switch (sd_alg)
      {
        case HashAlg::SHA_256:
          return ccf::crypto::MDType::SHA256;
        case HashAlg::SHA_384:
          return ccf::crypto::MDType::SHA384;
        case HashAlg::SHA_512:
          return ccf::crypto::MDType::SHA512;
        default:
          throw std::invalid_argument("unsupported sd_alg hash");
      }
    }
  }

  RandomSource default_random_source()
  {
    return [](size_t n) { return ccf::crypto::get_entropy()->random(n); };
  }

  namespace value
  {
    CborValue text(std::string_view s)
    {
      return CborValue::Text(std::string(s));
    }

    CborValue integer(int64_t n)
    {
      return CborValue::Int(n);
    }

    CborValue bytes(std::span<const uint8_t> b)
    {
      return CborValue::Bytes(std::vector<uint8_t>(b.begin(), b.end()));
    }

    CborValue text_array(const std::vector<std::string>& items)
    {
      std::vector<CborValue> elems;
      elems.reserve(items.size());
      for (const auto& item : items)
      {
        elems.push_back(CborValue::Text(item));
      }
      return CborValue::Array(std::move(elems));
    }
  }

  std::vector<uint8_t> disclosure_digest(
    std::span<const uint8_t> encoded, HashAlg sd_alg)
  {
    // draft-08: hash the disclosure wrapped in a CBOR byte string.
    const auto wrapped = ccf::cbor::serialize(bytes_value(encoded));
    return ccf::crypto::make_hash_provider()->hash(
      wrapped.data(), wrapped.size(), md_for_hash_alg(sd_alg));
  }

  std::vector<uint8_t> encode_sdcwt_protected_header(
    int64_t cose_alg, HashAlg sd_alg, const HeaderEntries& extra)
  {
    CborValue header = CborValue::Map({});
    header.map_put(CborKey(COSE_HEADER_ALG), CborValue::Int(cose_alg));
    header.map_put(CborKey(TYP_LABEL), CborValue::Int(SD_CWT_TYP));
    header.map_put(
      CborKey(SD_ALG_LABEL), CborValue::Int(static_cast<int64_t>(sd_alg)));
    append_header_entries(header, extra);
    // encode_value emits map entries in CDE order.
    return encode_value(header);
  }

  namespace
  {
    // cbor([salt, <value>, key]) for a redacted map entry.
    std::vector<uint8_t> encode_map_disclosure(
      std::span<const uint8_t> salt, const CborValue& value, const CborKey& key)
    {
      return ccf::cbor::serialize(ccf::cbor::make_array(
        {ccf::cbor::make_bytes(salt), to_ccf_cbor(value), to_ccf_cbor(key)}));
    }

    // cbor([salt, <value>]) for a redacted array element.
    std::vector<uint8_t> encode_elem_disclosure(
      std::span<const uint8_t> salt, const CborValue& value)
    {
      return ccf::cbor::serialize(ccf::cbor::make_array(
        {ccf::cbor::make_bytes(salt), to_ccf_cbor(value)}));
    }

    // cbor([salt]): a salt-only decoy disclosure that pads the redacted-hash
    // count.
    std::vector<uint8_t> encode_decoy_disclosure(std::span<const uint8_t> salt)
    {
      return ccf::cbor::serialize(
        ccf::cbor::make_array({ccf::cbor::make_bytes(salt)}));
    }

    bool elem_matches_key(const PathElem& e, const CborKey& key)
    {
      if (
        std::holds_alternative<int64_t>(e) &&
        std::holds_alternative<int64_t>(key))
      {
        return std::get<int64_t>(e) == std::get<int64_t>(key);
      }
      if (
        std::holds_alternative<std::string>(e) &&
        std::holds_alternative<std::string>(key))
      {
        return std::get<std::string>(e) == std::get<std::string>(key);
      }
      return false;
    }

    bool elem_matches_index(const PathElem& e, size_t index)
    {
      return std::holds_alternative<int64_t>(e) && std::get<int64_t>(e) >= 0 &&
        static_cast<size_t>(std::get<int64_t>(e)) == index;
    }

    // True if every path element resolves to an existing map entry / in-range
    // array element. A non-matching path would silently redact nothing, so
    // issue() rejects it (fail-closed).
    bool path_resolves(const CborValue& root, const Path& path)
    {
      const CborValue* node = &root;
      for (const auto& elem : path)
      {
        if (node->kind == CborValue::Kind::Map)
        {
          const CborValue* next = nullptr;
          for (size_t i = 0; i < node->map_keys.size(); ++i)
          {
            if (elem_matches_key(elem, node->map_keys[i]))
            {
              next = &node->map_vals[i];
              break;
            }
          }
          if (next == nullptr)
          {
            return false;
          }
          node = next;
        }
        else if (node->kind == CborValue::Kind::Array)
        {
          if (!std::holds_alternative<int64_t>(elem))
          {
            return false;
          }
          const int64_t idx = std::get<int64_t>(elem);
          if (idx < 0 || static_cast<size_t>(idx) >= node->array_v.size())
          {
            return false;
          }
          node = &node->array_v[static_cast<size_t>(idx)];
        }
        else
        {
          return false; // cannot descend into a scalar
        }
      }
      return true;
    }

    // Recursively redact `node` at relative `paths`: a length-1 path redacts
    // the whole entry/element, longer paths recurse first (ancestor-disclosure
    // rule).
    CborValue redact_node(
      const CborValue& node,
      const std::vector<Path>& paths,
      HashAlg sd_alg,
      const RandomSource& rng,
      std::vector<Disclosure>& disclosures,
      const Path& prefix = {})
    {
      if (node.kind == CborValue::Kind::Map)
      {
        CborValue out = CborValue::Map({});
        std::vector<std::vector<uint8_t>> digests;
        for (size_t mi = 0; mi < node.map_keys.size(); ++mi)
        {
          const CborKey& key = node.map_keys[mi];
          const CborValue& value = node.map_vals[mi];
          std::vector<Path> deeper;
          bool direct = false;
          for (const auto& p : paths)
          {
            if (p.empty())
            {
              continue;
            }
            if (!elem_matches_key(p.front(), key))
            {
              continue;
            }
            if (p.size() == 1)
            {
              direct = true;
            }
            else
            {
              deeper.emplace_back(p.begin() + 1, p.end());
            }
          }

          const CborValue child = deeper.empty() ?
            value :
            redact_node(value, deeper, sd_alg, rng, disclosures, [&] {
              Path p = prefix;
              p.push_back(key);
              return p;
            }());

          if (direct)
          {
            Disclosure d;
            d.path = prefix;
            d.path.push_back(key);
            d.salt = rng(SALT_LEN);
            d.encoded = encode_map_disclosure(d.salt, child, key);
            d.digest = disclosure_digest(d.encoded, sd_alg);
            digests.push_back(d.digest);
            disclosures.push_back(std::move(d));
          }
          else
          {
            out.map_put(key, child);
          }
        }
        // Hide real-vs-decoy ordering (salts already randomise the hashes).
        std::sort(digests.begin(), digests.end());
        out.redacted_hashes = std::move(digests);
        return out;
      }

      if (node.kind == CborValue::Kind::Array)
      {
        CborValue out = CborValue::Array({});
        for (size_t i = 0; i < node.array_v.size(); ++i)
        {
          std::vector<Path> deeper;
          bool direct = false;
          for (const auto& p : paths)
          {
            if (p.empty())
            {
              continue;
            }
            if (!elem_matches_index(p.front(), i))
            {
              continue;
            }
            if (p.size() == 1)
            {
              direct = true;
            }
            else
            {
              deeper.emplace_back(p.begin() + 1, p.end());
            }
          }

          const CborValue child = deeper.empty() ?
            node.array_v[i] :
            redact_node(node.array_v[i], deeper, sd_alg, rng, disclosures, [&] {
              Path p = prefix;
              p.push_back(static_cast<int64_t>(i));
              return p;
            }());

          if (direct)
          {
            Disclosure d;
            d.path = prefix;
            d.path.push_back(static_cast<int64_t>(i));
            d.salt = rng(SALT_LEN);
            d.encoded = encode_elem_disclosure(d.salt, child);
            d.digest = disclosure_digest(d.encoded, sd_alg);
            out.array_v.push_back(CborValue::RedactedElem(d.digest));
            disclosures.push_back(std::move(d));
          }
          else
          {
            out.array_v.push_back(child);
          }
        }
        return out;
      }

      throw std::invalid_argument(
        "redaction path descends into a non-container value");
    }
  }

  IssuedToken detail::issue(
    const std::vector<Claim>& claims,
    const std::vector<Path>& redact_paths,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const RandomSource& rng,
    size_t pad_to,
    const HeaderEntries& extra_protected)
  {
    // Reject an unsupported curve up front, before any redaction work.
    const auto cose_alg = cose_es_alg_for_curve(key.get_curve_id());
    // Reject a bad protected header (duplicate label) before signing too.
    const auto phdr =
      encode_sdcwt_protected_header(cose_alg, sd_alg, extra_protected);

    // Insertion order is irrelevant; encode_value sorts to CDE.
    CborValue root = CborValue::Map({});
    for (const auto& claim : claims)
    {
      root.map_put(CborKey(claim.key), claim.value);
    }

    // Every redaction path must resolve, so a mistyped path can't silently
    // under-redact.
    for (const auto& p : redact_paths)
    {
      if (p.empty() || !path_resolves(root, p))
      {
        throw std::invalid_argument(
          "redact_path does not resolve to an existing claim/element");
      }
    }

    std::vector<Disclosure> disclosures;
    CborValue redacted =
      redact_node(root, redact_paths, sd_alg, rng, disclosures);

    // Pad with salt-only decoys up to `pad_to` hashes so the count reveals
    // nothing about how many real claims were redacted.
    while (redacted.redacted_hashes.size() < pad_to)
    {
      Disclosure d;
      d.salt = rng(SALT_LEN);
      d.encoded = encode_decoy_disclosure(d.salt);
      d.digest = disclosure_digest(d.encoded, sd_alg);
      redacted.redacted_hashes.push_back(d.digest);
      disclosures.push_back(std::move(d));
    }
    std::sort(redacted.redacted_hashes.begin(), redacted.redacted_hashes.end());

    const auto payload = encode_value(redacted);

    IssuedToken out;
    out.token = sign_cose_sign1(key, phdr, payload);
    out.disclosures = std::move(disclosures);
    return out;
  }

  IssuedToken issue(
    const std::vector<Claim>& claims,
    const std::vector<Path>& redact_paths,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    size_t pad_to,
    const HeaderEntries& extra_protected)
  {
    return detail::issue(
      claims,
      redact_paths,
      key,
      sd_alg,
      default_random_source(),
      pad_to,
      extra_protected);
  }

  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    namespace cbor = ccf::cbor;

    // Rebuild the COSE_Sign1, replacing only the sd_claims unprotected-header
    // entry. Protected header, payload and signature are re-emitted unchanged
    // so the signature stays valid, and every other unprotected entry (such as
    // a SCITT receipt, label 394) is carried over.
    cbor::Value root;
    const cbor::Value* envelope = nullptr;
    try
    {
      root = cbor::parse(token);
      envelope = &root->tag_at(cbor::tag::COSE_SIGN_1);
    }
    catch (const std::exception&)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }

    if (!std::holds_alternative<cbor::Array>((*envelope)->value))
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    const auto& parts = std::get<cbor::Array>((*envelope)->value).items;
    if (parts.size() != 4)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    if (!std::holds_alternative<cbor::Map>(parts[1]->value))
    {
      throw std::runtime_error("present: malformed unprotected header");
    }

    std::vector<cbor::MapItem> uhdr;
    for (const auto& [label, value] :
         std::get<cbor::Map>(parts[1]->value).items)
    {
      const bool is_sd_claims =
        std::holds_alternative<cbor::Signed>(label->value) &&
        label->as_signed() == SD_CLAIMS_LABEL;
      if (!is_sd_claims)
      {
        uhdr.emplace_back(label, value);
      }
    }
    if (!selected.empty())
    {
      std::vector<cbor::Value> disclosures;
      disclosures.reserve(selected.size());
      for (const auto& d : selected)
      {
        disclosures.push_back(bytes_value(d));
      }
      uhdr.emplace_back(
        cbor::make_signed(SD_CLAIMS_LABEL),
        cbor::make_array(std::move(disclosures)));
    }

    return cbor::serialize(cbor::make_tagged(
      cbor::tag::COSE_SIGN_1,
      cbor::make_array(
        {parts[0], cbor::make_map(std::move(uhdr)), parts[2], parts[3]})));
  }
}
