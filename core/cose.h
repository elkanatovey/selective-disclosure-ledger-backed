// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/cbor_value.h"

#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ec_public_key.h>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace sdcwt
{
  // COSE ECDSA signing algorithm identifiers (RFC 9053).
  inline constexpr int64_t COSE_ALG_ES256 = -7;
  inline constexpr int64_t COSE_ALG_ES384 = -35;
  inline constexpr int64_t COSE_ALG_ES512 = -36;

  // COSE header parameter labels (RFC 9052).
  inline constexpr int64_t COSE_HEADER_ALG = 1;
  inline constexpr int64_t COSE_HEADER_CRIT = 2;

  // COSE_Key parameters for an EC2 key (RFC 9052 section 7, RFC 9053
  // section 7.1).
  inline constexpr int64_t COSE_KEY_KTY = 1;
  inline constexpr int64_t COSE_KEY_CRV = -1;
  inline constexpr int64_t COSE_KEY_X = -2;
  inline constexpr int64_t COSE_KEY_Y = -3;
  inline constexpr int64_t COSE_KTY_EC2 = 2;

  // Extra protected-header entries supplied by a caller (for example the SCITT
  // X.509 profile headers). Entries are CDE-sorted on encoding, so the order
  // given here is irrelevant.
  using HeaderEntries = std::vector<std::pair<CborKey, CborValue>>;

  // Map an EC curve to its COSE ECDSA signing algorithm id (ES256/384/512).
  // Throws std::invalid_argument for non-ECDSA / unsupported curves.
  int64_t cose_es_alg_for_curve(ccf::crypto::CurveID curve);

  // Map an EC curve to its COSE curve id (P-256 -> 1, P-384 -> 2, P-521 -> 3).
  // Throws std::invalid_argument for an unsupported curve.
  int64_t cose_crv_for_curve(ccf::crypto::CurveID curve);

  // The COSE_Key for an EC public key: {1: 2, -1: crv, -2: x, -3: y}.
  // Throws std::invalid_argument for an unsupported curve.
  CborValue cose_key_ec2(const ccf::crypto::ECPublicKey& key);

  // Append `extra` to a protected-header map, rejecting a label that the
  // framework already set. Throws std::invalid_argument on a duplicate label.
  void append_header_entries(CborValue& header, const HeaderEntries& extra);

  // Encode a protected-header map {1: alg} plus any caller-supplied `extra`
  // entries, in CDE order. Extended by the SD-CWT layer with the `sd_alg` (170)
  // and `typ` (16) headers.
  std::vector<uint8_t> encode_protected_header(
    int64_t alg = COSE_ALG_ES256, const HeaderEntries& extra = {});

  // The RFC 9052 Sig_structure a COSE_Sign1 signature is computed over:
  //   [ "Signature1", protected, external_aad, payload ]
  // Exposed so that the signature can be produced by a holder that never
  // shares its private key, such as a browser using WebCrypto.
  std::vector<uint8_t> cose_to_be_signed(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad = {});

  // Assemble a tagged COSE_Sign1 (CBOR tag 18) from its parts and a signature
  // made elsewhere over cose_to_be_signed(). `signature` must already be the
  // fixed-length r||s (IEEE P1363) form COSE requires, which is exactly what
  // WebCrypto's ECDSA produces.
  std::vector<uint8_t> assemble_cose_sign1(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature);

  // Build and sign a tagged COSE_Sign1 (CBOR tag 18) over `payload`, using the
  // already-CBOR-encoded protected-header bytes and an ECDSA key. The signing
  // algorithm and message digest are derived from the key's curve (P-256 ->
  // ES256/SHA-256, P-384 -> ES384/SHA-384, P-521 -> ES512/SHA-512), so the
  // caller must ensure the protected header advertises the matching `alg` (the
  // SD-CWT layer does this via cose_es_alg_for_curve).
  //
  // The signature is computed over the RFC 9052 Sig_structure and encoded as a
  // fixed-length r||s (IEEE P1363) value, as COSE requires. `external_aad` is
  // the COSE externally-supplied data bound into the signature (empty by
  // default).
  //
  // Throws std::invalid_argument for an unsupported curve, or
  // std::runtime_error on a CBOR encoding failure.
  std::vector<uint8_t> sign_cose_sign1(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad = {});
}
