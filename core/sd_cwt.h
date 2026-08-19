// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "core/cbor_value.h"
#include "core/cose.h"

#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace sdcwt
{
  // --- SD-CWT constants (draft-ietf-spice-sd-cwt-08) ------------------------
  inline constexpr int64_t SD_ALG_LABEL = 170; // protected: redaction hash alg
  inline constexpr int64_t TYP_LABEL = 16; // protected: typ
  inline constexpr int64_t SD_CLAIMS_LABEL = 17; // unprotected: disclosures
  inline constexpr int64_t SD_CWT_TYP = 293; // application/sd-cwt
  inline constexpr uint8_t REDACTED_CLAIM_KEYS = 59; // CBOR simple(59)
  inline constexpr uint64_t REDACTED_ELEMENT_TAG = 60; // CBOR tag(60)
  inline constexpr size_t SALT_LEN = 16; // 128-bit CSPRNG salt

  // CWT claim label used in the clear by the report profile (RFC 8392).
  inline constexpr int64_t CWT_IAT = 6; // issued-at

  // Confirmation claim (RFC 8747): names the key a holder must later prove it
  // controls. Its `1` member carries a COSE_Key.
  inline constexpr int64_t CWT_CNF = 8;
  inline constexpr int64_t CNF_COSE_KEY = 1;

  // Redaction hash algorithm. The enum values are the COSE hash-algorithm
  // identifiers written into the `sd_alg` protected header.
  enum class HashAlg : int64_t
  {
    SHA_256 = -16,
    SHA_384 = -43,
    SHA_512 = -44,
  };

  // --- CBOR value constructors ---------------------------------------------
  namespace value
  {
    CborValue text(std::string_view s);
    CborValue integer(int64_t n);
    CborValue bytes(std::span<const uint8_t> b);
    CborValue text_array(const std::vector<std::string>& items);
  }

  // A single top-level claim: its integer key and its value. Whether a claim is
  // selectively-disclosable is deliberately NOT recorded here - the redaction
  // tree has exactly one representation, `issue`'s `redact_paths`.
  struct Claim
  {
    int64_t key;
    CborValue value;
  };

  // A path element: a map key (int or text) or an array index (int).
  using PathElem = std::variant<int64_t, std::string>;
  // A redaction path from the claims-map root. A length-1 path redacts a whole
  // top-level claim (e.g. {1002}); longer paths redact nested map entries /
  // array elements (e.g. {1006, 1} redacts element 1 of the array claim 1006).
  using Path = std::vector<PathElem>;

  // A generated Salted Disclosed Claim. `path` locates it and is the only
  // identity it carries; the draft-08 salted-entry *shape* is already in
  // `encoded` (arity 3 = map entry `[salt, value, key]`, 2 = array element
  // `[salt, value]`, 1 = decoy `[salt]`), so it is not cached separately.
  struct Disclosure
  {
    // Absolute path from the claims-map root to this disclosure: map keys and
    // array indices, e.g. {1006} for a whole claim or {1006, 0} for element 0.
    // Empty for a synthetic decoy. Enables ancestor-aware selective disclosure.
    Path path;
    std::vector<uint8_t> salt;
    std::vector<uint8_t>
      encoded; // cbor([salt, value, key]), cbor([salt, value]), or cbor([salt])
    std::vector<uint8_t> digest; // sd_alg hash of (bstr .cbor encoded)
  };

  struct IssuedToken
  {
    std::vector<uint8_t> token; // signed COSE_Sign1, NO disclosures attached
    std::vector<Disclosure> disclosures; // all redacted claims
  };

  // An SD-CWT that has been built but not signed. The signature is produced
  // over `to_be_signed` by a holder this library never sees a private key for,
  // and the result is combined with the other parts by assemble().
  struct PreparedToken
  {
    std::vector<uint8_t> protected_header; // CBOR-encoded protected header
    std::vector<uint8_t> payload; // the redacted claims map
    std::vector<uint8_t> to_be_signed; // RFC 9052 Sig_structure
    std::vector<Disclosure> disclosures; // all redacted claims
  };

  // Redacted Claim Hash = `sd_alg` hash of the CBOR byte-string wrapping the
  // encoded salted disclosure array (draft-08 CDDL `bstr .cbor salted-entry`).
  std::vector<uint8_t> disclosure_digest(
    std::span<const uint8_t> encoded, HashAlg sd_alg = HashAlg::SHA_256);

  // Encode the SD-CWT protected header {1: cose_alg, 16: typ, 170: sd_alg},
  // plus any caller-supplied `extra` entries (for example the SCITT X.509
  // profile headers in core/profile.h). Entries are emitted in CDE order.
  // Throws std::invalid_argument if `extra` repeats a framework label.
  std::vector<uint8_t> encode_sdcwt_protected_header(
    int64_t cose_alg, HashAlg sd_alg, const HeaderEntries& extra = {});

  // Build and sign a redacted SD-CWT over the given top-level claims.
  // `redact_paths` is the single, complete description of what is redacted: a
  // length-1 path hides a whole top-level claim, longer paths hide nested map
  // entries / array elements at arbitrary depth, and the two compose (the
  // ancestor-disclosure rule applies - a disclosed parent may reveal a
  // still-redacted child). Redacted map entries become sorted Redacted Claim
  // Hashes under simple(59); redacted array elements become tag(60) hashes.
  // Disclosures are returned separately. The COSE signing algorithm is derived
  // from the key's curve; the redaction hash is `sd_alg` (default SHA-256).
  //
  // `pad_to`, if non-zero, pads the top-level Redacted-Claim-Hash count up to
  // that many entries with indistinguishable salt-only decoy disclosures, so
  // the count does not reveal how many real claims were redacted.
  //
  // `extra_protected` adds caller-supplied protected-header entries, which are
  // therefore covered by the issuer signature.
  //
  // Throws std::invalid_argument (unsupported curve, a duplicate protected
  // header label, or a redact_path that does not resolve to an existing
  // claim/element / descends into a non-container) or std::runtime_error (CBOR
  // failure).
  IssuedToken issue(
    const std::vector<Claim>& claims,
    const std::vector<Path>& redact_paths,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg = HashAlg::SHA_256,
    size_t pad_to = 0,
    const HeaderEntries& extra_protected = {});

  // Build a redacted SD-CWT without signing it. Identical to issue() in every
  // respect except that the caller supplies the COSE algorithm id directly
  // (there is no key to derive it from) and gets back the bytes to sign.
  //
  // Throws the same exceptions as issue().
  PreparedToken prepare(
    const std::vector<Claim>& claims,
    const std::vector<Path>& redact_paths,
    int64_t cose_alg,
    HashAlg sd_alg = HashAlg::SHA_256,
    size_t pad_to = 0,
    const HeaderEntries& extra_protected = {});

  // Combine a prepared token with a signature made over its `to_be_signed`
  // bytes. `signature` must be raw r||s (IEEE P1363), the form COSE requires.
  std::vector<uint8_t> assemble(
    const PreparedToken& prepared, std::span<const uint8_t> signature);

  // Set one unprotected-header entry (`label`) to an array of byte strings,
  // preserving the protected header, payload, signature and every other
  // unprotected entry. An empty `items` removes the entry. This is how a
  // transparency service attaches receipts (label 394) to a statement it has
  // registered without invalidating the issuer's signature.
  //
  // CCF's ccf::cose::edit::set_unprotected_header replaces the whole
  // unprotected header rather than merging into it, so it would drop the
  // disclosures (17) when adding a receipt (394), and vice versa.
  // Throws std::runtime_error on a malformed token.
  std::vector<uint8_t> set_unprotected_bstr_array(
    std::span<const uint8_t> token,
    int64_t label,
    const std::vector<std::vector<uint8_t>>& items);

  // Attach `selected` disclosures (their encoded `[salt, value, key]` bytes) to
  // an issued SD-CWT's unprotected header (sd_claims, label 17), leaving the
  // protected header, payload and signature untouched (no re-signing). Any
  // other unprotected header entry (notably a SCITT receipt, label 394) is
  // preserved. Passing an empty selection omits the sd_claims header entirely.
  // Throws std::runtime_error on a malformed token.
  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected);
}
