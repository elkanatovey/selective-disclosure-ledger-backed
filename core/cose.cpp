// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/cose.h"

#include "core/cbor_value.h"

#include <ccf/_private/crypto/cbor.h>
#include <ccf/crypto/curve.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/hash_provider.h>
#include <stdexcept>

namespace sdcwt
{
  int64_t cose_es_alg_for_curve(ccf::crypto::CurveID curve)
  {
    switch (curve)
    {
      case ccf::crypto::CurveID::SECP256R1:
        return COSE_ALG_ES256;
      case ccf::crypto::CurveID::SECP384R1:
        return COSE_ALG_ES384;
      case ccf::crypto::CurveID::SECP521R1:
        return COSE_ALG_ES512;
      case ccf::crypto::CurveID::NONE:
      case ccf::crypto::CurveID::CURVE25519:
      case ccf::crypto::CurveID::X25519:
      default:
        throw std::invalid_argument(
          "unsupported signing curve (expected P-256/P-384/P-521)");
    }
  }

  void append_header_entries(CborValue& header, const HeaderEntries& extra)
  {
    if (header.kind != CborValue::Kind::Map)
    {
      throw std::invalid_argument("protected header must be a map");
    }
    for (const auto& [key, value] : extra)
    {
      for (const auto& existing : header.map_keys)
      {
        if (existing == key)
        {
          throw std::invalid_argument(
            "duplicate protected header label in extra entries");
        }
      }
      header.map_put(key, value);
    }
  }

  std::vector<uint8_t> encode_protected_header(
    int64_t alg, const HeaderEntries& extra)
  {
    CborValue header = CborValue::Map({});
    header.map_put(CborKey(COSE_HEADER_ALG), CborValue::Int(alg));
    append_header_entries(header, extra);
    // encode_value emits map entries in CDE order.
    return encode_value(header);
  }

  std::vector<uint8_t> sign_cose_sign1(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad)
  {
    // Reject an unsupported curve up front, before any signing.
    const auto curve = key.get_curve_id();
    cose_es_alg_for_curve(curve); // validates the curve
    const auto md = ccf::crypto::get_md_for_ec(curve);

    // RFC 9052 Sig_structure for a COSE_Sign1:
    //   [ "Signature1", protected, external_aad, payload ]
    const auto to_be_signed = ccf::cbor::serialize(ccf::cbor::make_array(
      {ccf::cbor::make_string("Signature1"),
       bytes_value(protected_header_cbor),
       bytes_value(external_aad),
       bytes_value(payload)}));

    const auto digest = ccf::crypto::make_hash_provider()->hash(
      to_be_signed.data(), to_be_signed.size(), md);
    const auto der_sig = key.sign_hash(digest.data(), digest.size());
    // COSE requires the raw r||s form, not OpenSSL's DER.
    const auto raw_sig = ccf::crypto::ecdsa_sig_der_to_p1363(der_sig, curve);

    // COSE_Sign1 = 18([ protected, unprotected {}, payload, signature ]).
    return ccf::cbor::serialize(ccf::cbor::make_tagged(
      ccf::cbor::tag::COSE_SIGN_1,
      ccf::cbor::make_array(
        {bytes_value(protected_header_cbor),
         ccf::cbor::make_map({}), // empty unprotected header
         bytes_value(payload),
         bytes_value(raw_sig)})));
  }
}
