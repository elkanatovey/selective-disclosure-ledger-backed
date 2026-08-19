// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/profile.h"

#include "core/cbor_value.h"
#include "core/sd_cwt.h"

#include <ccf/_private/crypto/cose.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/sha256.h>
#include <stdexcept>

namespace scitt_sd
{
  namespace
  {
    std::vector<std::string> split(std::string_view s, std::string_view sep)
    {
      std::vector<std::string> parts;
      size_t start = 0;
      while (true)
      {
        const size_t end = s.find(sep, start);
        if (end == std::string_view::npos)
        {
          parts.emplace_back(s.substr(start));
          return parts;
        }
        parts.emplace_back(s.substr(start, end - start));
        start = end + sep.size();
      }
    }
  }

  std::string did_x509_ca_fingerprint(std::span<const uint8_t> root_der)
  {
    if (root_der.empty())
    {
      throw std::invalid_argument("empty trust anchor certificate");
    }
    const auto digest = ccf::crypto::sha256(root_der);
    return ccf::crypto::b64url_from_raw(digest, /*with_padding=*/false);
  }

  std::string make_did_x509(
    std::span<const uint8_t> root_der, std::string_view eku_oid)
  {
    if (eku_oid.empty())
    {
      throw std::invalid_argument("empty EKU OID");
    }
    return "did:x509:0:sha256:" + did_x509_ca_fingerprint(root_der) +
      "::eku:" + std::string(eku_oid);
  }

  DidX509 parse_did_x509(std::string_view did)
  {
    // did:x509:0:<alg>:<fingerprint>::<policy>[::<policy>...]
    const auto top = split(did, "::");
    if (top.size() < 2)
    {
      throw std::invalid_argument("did:x509 has no policy");
    }
    const auto prefix = split(top[0], ":");
    if (prefix.size() != 5 || prefix[0] != "did" || prefix[1] != "x509")
    {
      throw std::invalid_argument("not a did:x509 identifier");
    }
    if (prefix[2] != "0")
    {
      throw std::invalid_argument("unsupported did:x509 version");
    }

    DidX509 out;
    out.fingerprint_alg = prefix[3];
    out.fingerprint = prefix[4];
    if (out.fingerprint.empty())
    {
      throw std::invalid_argument("did:x509 has an empty CA fingerprint");
    }
    for (size_t i = 1; i < top.size(); ++i)
    {
      const auto parts = split(top[i], ":");
      if (parts.size() < 2 || parts[0].empty())
      {
        throw std::invalid_argument("invalid did:x509 policy");
      }
      DidX509Policy policy;
      policy.name = parts[0];
      policy.args.assign(parts.begin() + 1, parts.end());
      out.policies.push_back(std::move(policy));
    }
    return out;
  }

  sdcwt::HeaderEntries scitt_x509_header_entries(const IssuerIdentity& issuer)
  {
    if (issuer.subject.empty())
    {
      throw std::invalid_argument("empty statement subject");
    }
    // Rejects a malformed DID before it is signed over.
    const auto did = parse_did_x509(issuer.issuer_did);
    if (did.fingerprint_alg != "sha256")
    {
      throw std::invalid_argument(
        "unsupported did:x509 CA fingerprint algorithm");
    }
    if (issuer.x5chain_der.size() < 2)
    {
      throw std::invalid_argument(
        "x5chain must contain at least a leaf and a trust anchor");
    }

    // crit = [15, 33]: a verifier that does not understand the CWT claims or
    // the certificate chain must reject the statement.
    sdcwt::CborValue crit = sdcwt::CborValue::Array(
      {sdcwt::CborValue::Int(ccf::cose::header::iana::CWT_CLAIMS),
       sdcwt::CborValue::Int(ccf::cose::header::iana::X5CHAIN)});

    sdcwt::CborValue cwt_claims = sdcwt::CborValue::Map({});
    cwt_claims.map_put(
      sdcwt::CborKey(ccf::cwt::header::iana::ISS),
      sdcwt::CborValue::Text(issuer.issuer_did));
    cwt_claims.map_put(
      sdcwt::CborKey(ccf::cwt::header::iana::SUB),
      sdcwt::CborValue::Text(issuer.subject));

    std::vector<sdcwt::CborValue> chain;
    chain.reserve(issuer.x5chain_der.size());
    for (const auto& der : issuer.x5chain_der)
    {
      if (der.empty())
      {
        throw std::invalid_argument("empty certificate in x5chain");
      }
      chain.push_back(sdcwt::CborValue::Bytes(der));
    }

    return {
      {sdcwt::CborKey(sdcwt::COSE_HEADER_CRIT), std::move(crit)},
      {sdcwt::CborKey(ccf::cose::header::iana::CWT_CLAIMS),
       std::move(cwt_claims)},
      {sdcwt::CborKey(ccf::cose::header::iana::X5CHAIN),
       sdcwt::CborValue::Array(std::move(chain))}};
  }
}
