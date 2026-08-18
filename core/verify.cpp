// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "core/verify.h"

#include "core/cbor_value.h"
#include "core/report.h"
#include "core/sd_cwt.h"
#include "core/text_chunks.h"

#include <algorithm>
#include <ccf/_private/crypto/cbor.h>
#include <ccf/_private/crypto/cose.h>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/verifier.h>
#include <didx509cpp/didx509cpp.h>
#include <set>
#include <string>

namespace scitt_sd::verify
{
  namespace
  {
    namespace cbor = ccf::cbor;

    [[noreturn]] void fail(const std::string& why)
    {
      throw VerificationError(why);
    }

    void require(bool condition, const std::string& why)
    {
      if (!condition)
      {
        fail(why);
      }
    }

    std::vector<uint8_t> copy_bytes(const cbor::Value& value)
    {
      const auto bytes = value->as_bytes();
      return {bytes.begin(), bytes.end()};
    }

    std::string copy_text(const cbor::Value& value)
    {
      const auto text = value->as_string();
      return {text.begin(), text.end()};
    }

    bool is_signed(const cbor::Value& value)
    {
      return std::holds_alternative<cbor::Signed>(value->value);
    }

    bool is_bytes(const cbor::Value& value)
    {
      return std::holds_alternative<cbor::Bytes>(value->value);
    }

    bool is_text(const cbor::Value& value)
    {
      return std::holds_alternative<cbor::String>(value->value);
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

    // The map entry for `label`, or nullptr. Rejects a repeated label rather
    // than silently taking the first, since a duplicate would let a second,
    // ignored value ride along inside signed bytes.
    const cbor::Value* map_lookup(const cbor::Map& map, int64_t label)
    {
      const cbor::Value* found = nullptr;
      for (const auto& [key, value] : map.items)
      {
        if (!is_signed(key) || key->as_signed() != label)
        {
          continue;
        }
        require(found == nullptr, "duplicate label " + std::to_string(label));
        found = &value;
      }
      return found;
    }

    const cbor::Value& require_label(
      const cbor::Map& map, int64_t label, const std::string& what)
    {
      const auto* found = map_lookup(map, label);
      require(
        found != nullptr, what + " is missing label " + std::to_string(label));
      return *found;
    }

    // --- COSE_Sign1 -------------------------------------------------------

    // The four COSE_Sign1 fields, kept as raw bytes so the exact registered
    // and transparent statement bytes can be compared and re-verified without
    // any re-encoding.
    struct Sign1
    {
      std::vector<uint8_t> protected_header;
      std::vector<uint8_t> payload;
      std::vector<uint8_t> signature;
      size_t unprotected_entry_count = 0;
      bool has_disclosures = false;
      bool has_unknown_unprotected = false;
      std::vector<std::vector<uint8_t>> receipts;
    };

    Sign1 parse_sign1(
      std::span<const uint8_t> statement, const std::string& what)
    {
      const auto root = parse_or_fail(statement, what);

      const cbor::Value* envelope = nullptr;
      try
      {
        envelope = &root->tag_at(cbor::tag::COSE_SIGN_1);
      }
      catch (const std::exception&)
      {
        fail(what + " is not a tagged COSE_Sign1 (tag 18)");
      }

      require(
        std::holds_alternative<cbor::Array>((*envelope)->value),
        what + " is not a COSE_Sign1 array");
      const auto& parts = std::get<cbor::Array>((*envelope)->value).items;
      require(parts.size() == 4, what + " must have four COSE_Sign1 fields");
      require(is_bytes(parts[0]), what + " protected header must be a bstr");
      require(is_bytes(parts[2]), what + " payload must be a bstr");
      require(is_bytes(parts[3]), what + " signature must be a bstr");
      require(
        std::holds_alternative<cbor::Map>(parts[1]->value),
        what + " unprotected header must be a map");

      Sign1 out;
      out.protected_header = copy_bytes(parts[0]);
      out.payload = copy_bytes(parts[2]);
      out.signature = copy_bytes(parts[3]);

      const auto& unprotected = std::get<cbor::Map>(parts[1]->value);
      out.unprotected_entry_count = unprotected.items.size();
      for (const auto& [key, _value] : unprotected.items)
      {
        if (
          !std::holds_alternative<cbor::Signed>(key->value) ||
          (key->as_signed() != label::SD_CLAIMS &&
           key->as_signed() != label::SCITT_RECEIPTS))
        {
          out.has_unknown_unprotected = true;
        }
      }
      const auto* disclosures = map_lookup(unprotected, label::SD_CLAIMS);
      out.has_disclosures = disclosures != nullptr;

      const auto* receipts = map_lookup(unprotected, label::SCITT_RECEIPTS);
      if (receipts != nullptr)
      {
        require(
          std::holds_alternative<cbor::Array>((*receipts)->value),
          what + " receipts header (394) must be an array");
        for (const auto& receipt :
             std::get<cbor::Array>((*receipts)->value).items)
        {
          require(is_bytes(receipt), what + " each receipt must be a bstr");
          out.receipts.push_back(copy_bytes(receipt));
        }
      }
      return out;
    }

    // --- Protected header (the SCITT X.509 profile) -----------------------

    struct ProfileHeader
    {
      int64_t cose_alg = 0;
      sdcwt::HashAlg sd_alg = sdcwt::HashAlg::SHA_256;
      std::string issuer_did;
      std::string subject;
      std::vector<std::vector<uint8_t>> x5chain_der; // leaf first, root last
    };

    sdcwt::HashAlg hash_alg_from_label(int64_t value)
    {
      switch (value)
      {
        case static_cast<int64_t>(sdcwt::HashAlg::SHA_256):
          return sdcwt::HashAlg::SHA_256;
        case static_cast<int64_t>(sdcwt::HashAlg::SHA_384):
          return sdcwt::HashAlg::SHA_384;
        case static_cast<int64_t>(sdcwt::HashAlg::SHA_512):
          return sdcwt::HashAlg::SHA_512;
        default:
          fail("unsupported sd_alg (170) redaction hash");
      }
    }

    size_t digest_size(sdcwt::HashAlg sd_alg)
    {
      switch (sd_alg)
      {
        case sdcwt::HashAlg::SHA_256:
          return 32;
        case sdcwt::HashAlg::SHA_384:
          return 48;
        case sdcwt::HashAlg::SHA_512:
          return 64;
        default:
          fail("unsupported sd_alg (170) redaction hash");
      }
    }

    void check_cose_alg(int64_t alg)
    {
      if (
        alg != sdcwt::COSE_ALG_ES256 && alg != sdcwt::COSE_ALG_ES384 &&
        alg != sdcwt::COSE_ALG_ES512)
      {
        fail("unsupported COSE algorithm (1)");
      }
    }

    // crit (2) must be exactly the profile's [15, 33]: a verifier that did not
    // understand those labels would have to reject the statement, so accepting
    // any other critical label here would be accepting something unchecked.
    void check_crit(const cbor::Value& crit)
    {
      require(
        std::holds_alternative<cbor::Array>(crit->value),
        "crit (2) must be an array");
      const auto& items = std::get<cbor::Array>(crit->value).items;
      require(items.size() == 2, "crit (2) must be [15, 33]");
      bool cwt_claims = false;
      bool x5chain = false;
      for (const auto& item : items)
      {
        require(is_signed(item), "crit (2) entries must be integers");
        const auto value = item->as_signed();
        if (value == ccf::cose::header::iana::CWT_CLAIMS)
        {
          cwt_claims = true;
        }
        else if (value == ccf::cose::header::iana::X5CHAIN)
        {
          x5chain = true;
        }
        else
        {
          fail("unsupported critical header label in crit (2)");
        }
      }
      require(cwt_claims && x5chain, "crit (2) must be [15, 33]");
    }

    ProfileHeader parse_profile_header(std::span<const uint8_t> encoded)
    {
      const auto root = parse_or_fail(encoded, "protected header");
      require(
        std::holds_alternative<cbor::Map>(root->value),
        "protected header must be a map");
      const auto& map = std::get<cbor::Map>(root->value);
      // alg, crit, CWT claims, typ, x5chain, sd_alg and nothing else: an entry
      // this profile does not know is covered by the signature but by no check.
      require(
        map.items.size() == 6,
        "protected header must carry exactly the six profile entries");

      ProfileHeader out;

      const auto& alg =
        require_label(map, sdcwt::COSE_HEADER_ALG, "protected header");
      require(is_signed(alg), "alg (1) must be an integer");
      out.cose_alg = alg->as_signed();
      check_cose_alg(out.cose_alg);

      check_crit(
        require_label(map, sdcwt::COSE_HEADER_CRIT, "protected header"));

      const auto& typ =
        require_label(map, sdcwt::TYP_LABEL, "protected header");
      require(is_signed(typ), "typ (16) must be an integer");
      require(
        typ->as_signed() == sdcwt::SD_CWT_TYP,
        "typ (16) must be 293 (application/sd-cwt)");

      const auto& sd_alg =
        require_label(map, sdcwt::SD_ALG_LABEL, "protected header");
      require(is_signed(sd_alg), "sd_alg (170) must be an integer");
      out.sd_alg = hash_alg_from_label(sd_alg->as_signed());

      const auto& claims = require_label(
        map, ccf::cose::header::iana::CWT_CLAIMS, "protected header");
      require(
        std::holds_alternative<cbor::Map>(claims->value),
        "CWT claims (15) must be a map");
      const auto& claims_map = std::get<cbor::Map>(claims->value);
      require(
        claims_map.items.size() == 2,
        "CWT claims (15) must carry exactly iss and sub");
      const auto& iss = require_label(
        claims_map, ccf::cwt::header::iana::ISS, "CWT claims (15)");
      require(is_text(iss), "CWT iss (15/1) must be a text string");
      out.issuer_did = copy_text(iss);
      const auto& sub = require_label(
        claims_map, ccf::cwt::header::iana::SUB, "CWT claims (15)");
      require(is_text(sub), "CWT sub (15/2) must be a text string");
      out.subject = copy_text(sub);
      require(!out.subject.empty(), "CWT sub (15/2) must not be empty");

      const auto& chain = require_label(
        map, ccf::cose::header::iana::X5CHAIN, "protected header");
      require(
        std::holds_alternative<cbor::Array>(chain->value),
        "x5chain (33) must be an array");
      for (const auto& cert : std::get<cbor::Array>(chain->value).items)
      {
        require(is_bytes(cert), "x5chain (33) entries must be byte strings");
        auto der = copy_bytes(cert);
        require(!der.empty(), "x5chain (33) entries must not be empty");
        out.x5chain_der.push_back(std::move(der));
      }
      require(
        out.x5chain_der.size() >= 2,
        "x5chain (33) must contain a leaf and a trust anchor");
      return out;
    }

    // --- X.509 and did:x509 ----------------------------------------------

    // The leaf's X.509 subject. Parsing only: no trust decision is made here.
    std::string leaf_subject(const ProfileHeader& header)
    {
      try
      {
        auto verifier =
          ccf::crypto::make_unique_verifier(header.x5chain_der.front());
        return verifier->subject();
      }
      catch (const std::exception&)
      {
        fail("x5chain (33) leaf is not a valid certificate");
      }
    }

    std::string leaf_subject_and_check_chain(
      const ProfileHeader& header,
      const Params& params,
      const std::vector<uint8_t>& trusted_root_der)
    {
      // The chain's own last certificate is NOT a trust anchor: only the
      // separately supplied root is, and it must be exactly the one the
      // statement chains to.
      require(
        header.x5chain_der.back() == trusted_root_der,
        "x5chain (33) does not end at the separately trusted root");

      std::vector<ccf::crypto::Pem> intermediates;
      for (size_t i = 1; i + 1 < header.x5chain_der.size(); ++i)
      {
        try
        {
          intermediates.push_back(
            ccf::crypto::cert_der_to_pem(header.x5chain_der[i]));
        }
        catch (const std::exception&)
        {
          fail("x5chain (33) contains a malformed certificate");
        }
      }
      std::vector<const ccf::crypto::Pem*> chain;
      chain.reserve(intermediates.size());
      for (const auto& pem : intermediates)
      {
        chain.push_back(&pem);
      }
      const std::vector<const ccf::crypto::Pem*> trusted{&params.trusted_root};

      try
      {
        auto verifier =
          ccf::crypto::make_unique_verifier(header.x5chain_der.front());
        if (!verifier->verify_certificate(
              trusted, chain, params.ignore_certificate_time))
        {
          fail("certificate chain does not verify against the trusted root");
        }
        return verifier->subject();
      }
      catch (const VerificationError&)
      {
        throw;
      }
      catch (const std::exception&)
      {
        fail("certificate chain does not verify against the trusted root");
      }
    }

    void check_did_x509(
      const ProfileHeader& header,
      const Params& params,
      const std::vector<uint8_t>& trusted_root_der)
    {
      DidX509 did;
      try
      {
        did = parse_did_x509(header.issuer_did);
      }
      catch (const std::exception&)
      {
        fail("CWT iss is not a did:x509 identifier");
      }
      require(
        did.fingerprint_alg == "sha256",
        "unsupported did:x509 CA fingerprint algorithm");
      // The DID must pin the separately trusted root itself, not merely some
      // CA that happens to appear in the presented chain.
      require(
        did.fingerprint == did_x509_ca_fingerprint(trusted_root_der),
        "issuer did:x509 does not pin the trusted root");

      if (!params.required_eku.empty())
      {
        const auto eku = std::find_if(
          did.policies.begin(), did.policies.end(), [](const DidX509Policy& p) {
            return p.name == "eku";
          });
        require(
          eku != did.policies.end() && eku->args.size() == 1 &&
            eku->args.front() == params.required_eku,
          "issuer did:x509 does not pin the required EKU");
      }

      // The did:x509 policies (the EKU the leaf must carry, subject and SAN
      // constraints) are enforced by the did:x509 resolver CCF ships. Its
      // implicit trust in the chain's last certificate is already covered: the
      // chain was pinned to, and verified against, the separately trusted root
      // above.
      std::string chain_pem;
      for (const auto& der : header.x5chain_der)
      {
        try
        {
          chain_pem += ccf::crypto::cert_der_to_pem(der).str();
        }
        catch (const std::exception&)
        {
          fail("x5chain (33) contains a malformed certificate");
        }
      }
      try
      {
        (void)didx509::resolve(
          chain_pem, header.issuer_did, params.ignore_certificate_time);
      }
      catch (const std::exception& e)
      {
        fail(
          std::string("did:x509 policy does not hold for the chain: ") +
          e.what());
      }
    }

    void check_issuer_signature(
      const ProfileHeader& header, const Sign1& statement)
    {
      try
      {
        auto verifier = ccf::crypto::make_cose_verifier_from_der_cert(
          header.x5chain_der.front());
        if (!verifier->verify_decomposed(
              statement.protected_header,
              statement.payload,
              statement.signature,
              header.cose_alg))
        {
          fail("issuer COSE signature does not verify under the leaf key");
        }
      }
      catch (const VerificationError&)
      {
        throw;
      }
      catch (const std::exception&)
      {
        fail("issuer COSE signature does not verify under the leaf key");
      }
    }

    // --- Clear payload and disclosures ------------------------------------

    struct ClearPayload
    {
      int64_t issued_at = 0;
      std::vector<std::vector<uint8_t>> commitments;
      bool names_a_discloser = false; // a cnf claim was present
    };

    // The registered payload must hold `iat`, optionally `cnf`, and nothing
    // else in the clear: every content claim is present only as a Redacted
    // Claim Hash.
    ClearPayload parse_clear_payload(
      std::span<const uint8_t> encoded, sdcwt::HashAlg sd_alg)
    {
      const auto root = parse_or_fail(encoded, "payload");
      require(
        std::holds_alternative<cbor::Map>(root->value),
        "payload must be a map");
      const auto& map = std::get<cbor::Map>(root->value);
      require(
        map.items.size() == 2 || map.items.size() == 3,
        "payload must carry iat, the redacted claim hashes and at most cnf");

      ClearPayload out;
      bool seen_iat = false;
      bool seen_hashes = false;
      for (const auto& [key, value] : map.items)
      {
        if (is_signed(key) && key->as_signed() == sdcwt::CWT_IAT)
        {
          require(!seen_iat, "duplicate iat (6) in payload");
          seen_iat = true;
          require(is_signed(value), "iat (6) must be an integer");
          out.issued_at = value->as_signed();
          require(out.issued_at >= 0, "iat (6) must not be negative");
          continue;
        }
        if (is_signed(key) && key->as_signed() == sdcwt::CWT_CNF)
        {
          require(!out.names_a_discloser, "duplicate cnf (8) in payload");
          require(
            std::holds_alternative<cbor::Map>(value->value),
            "cnf (8) must be a map");
          const auto& confirmation = std::get<cbor::Map>(value->value);
          require(
            confirmation.items.size() == 1,
            "cnf (8) must carry exactly one member");
          require(
            is_signed(confirmation.items[0].first) &&
              confirmation.items[0].first->as_signed() == sdcwt::CNF_COSE_KEY,
            "cnf (8) must carry a COSE_Key (1)");
          require(
            std::holds_alternative<cbor::Map>(
              confirmation.items[0].second->value),
            "the cnf COSE_Key must be a map");
          out.names_a_discloser = true;
          continue;
        }
        if (
          std::holds_alternative<cbor::Simple>(key->value) &&
          key->as_simple() == sdcwt::REDACTED_CLAIM_KEYS)
        {
          require(!seen_hashes, "duplicate redacted claim hashes in payload");
          seen_hashes = true;
          require(
            std::holds_alternative<cbor::Array>(value->value),
            "redacted claim hashes must be an array");
          for (const auto& hash : std::get<cbor::Array>(value->value).items)
          {
            require(is_bytes(hash), "each redacted claim hash must be a bstr");
            auto digest = copy_bytes(hash);
            require(
              digest.size() == digest_size(sd_alg),
              "redacted claim hash has the wrong length for sd_alg");
            out.commitments.push_back(std::move(digest));
          }
          continue;
        }
        fail("payload carries a claim that is not redacted");
      }
      require(
        seen_iat && seen_hashes,
        "payload must carry iat and the redacted claim hashes");
      require(
        out.commitments.size() == report::CONTENT_LABELS.size(),
        "payload does not redact exactly the profile's content claims");
      return out;
    }

    // A commitment still waiting to be opened, with the context that says what
    // a matching disclosure means.
    struct Commitment
    {
      std::vector<uint8_t> digest;
      int64_t parent = 0; // 0 = the claims map, otherwise the parent's label
      size_t index = 0; // array element index, when `array_element`
      bool array_element = false;
    };

    class DisclosureResolver
    {
    public:
      DisclosureResolver(
        sdcwt::HashAlg sd_alg,
        DisclosedReport& out,
        std::vector<sdcwt::Path>& paths) :
        sd_alg(sd_alg),
        report(out),
        resolved_paths(paths)
      {}

      void add_top_level(const std::vector<std::vector<uint8_t>>& digests)
      {
        for (const auto& digest : digests)
        {
          pending.push_back(Commitment{digest, 0, 0, false});
        }
      }

      // Opens disclosures against the pending commitments until no further
      // progress is possible. A child commitment only becomes available once
      // its ancestor has been opened, so a disclosure whose parent was not
      // presented is left over and rejected.
      void resolve(const std::vector<std::vector<uint8_t>>& disclosures)
      {
        std::set<std::vector<uint8_t>> salts;
        std::vector<bool> consumed(disclosures.size(), false);
        resolved_paths.assign(disclosures.size(), sdcwt::Path{});
        bool progress = true;
        while (progress)
        {
          progress = false;
          for (size_t i = 0; i < disclosures.size(); ++i)
          {
            if (consumed[i])
            {
              continue;
            }
            const auto digest =
              sdcwt::disclosure_digest(disclosures[i], sd_alg);
            const auto match = std::find_if(
              pending.begin(), pending.end(), [&digest](const Commitment& c) {
                return c.digest == digest;
              });
            if (match == pending.end())
            {
              continue;
            }
            const Commitment commitment = *match;
            pending.erase(match);
            resolved_paths[i] = open(disclosures[i], commitment, salts);
            consumed[i] = true;
            progress = true;
          }
        }
        for (size_t i = 0; i < disclosures.size(); ++i)
        {
          require(
            consumed[i],
            "a presented disclosure is not committed to by the statement (or "
            "its parent was not disclosed)");
        }
      }

    private:
      // Opens one disclosure and returns the path it resolved to.
      sdcwt::Path open(
        const std::vector<uint8_t>& disclosure,
        const Commitment& commitment,
        std::set<std::vector<uint8_t>>& salts)
      {
        const auto root = parse_or_fail(disclosure, "disclosure");
        require(
          std::holds_alternative<cbor::Array>(root->value),
          "a disclosure must be an array");
        const auto& items = std::get<cbor::Array>(root->value).items;
        require(!items.empty(), "a disclosure must not be empty");
        require(is_bytes(items[0]), "a disclosure salt must be a bstr");
        auto salt = copy_bytes(items[0]);
        require(
          salt.size() == sdcwt::SALT_LEN,
          "a disclosure salt is not " + std::to_string(sdcwt::SALT_LEN) +
            " bytes");
        require(
          salts.insert(std::move(salt)).second,
          "two disclosures reuse the same salt");

        if (commitment.array_element)
        {
          require(
            items.size() == 2,
            "an array element disclosure must be [salt, value]");
          open_child(commitment.parent, commitment.index, items[1]);
          return {commitment.parent, static_cast<int64_t>(commitment.index)};
        }

        if (items.size() == 1)
        {
          // A salt-only decoy: it opens a padding commitment and reveals
          // nothing.
          return {};
        }
        require(
          items.size() == 3,
          "a map entry disclosure must be [salt, value, key]");
        require(
          is_signed(items[2]), "a disclosed claim key must be an integer");
        const auto key = items[2]->as_signed();

        if (commitment.parent == 0)
        {
          open_claim(key, items[1]);
          return {key};
        }
        require(key >= 0, "a disclosed child key must not be negative");
        open_child(commitment.parent, static_cast<size_t>(key), items[1]);
        return {commitment.parent, key};
      }

      void open_claim(int64_t claim_label, const cbor::Value& value)
      {
        switch (claim_label)
        {
          case report::label::TITLE:
            report.title = require_text(value, "title");
            return;
          case report::label::COMPONENT:
            report.component = require_text(value, "component");
            return;
          case report::label::SEVERITY:
            report.severity = require_text(value, "severity");
            return;
          case report::label::FINGERPRINT:
            require(is_bytes(value), "fingerprint must be a byte string");
            report.fingerprint = copy_bytes(value);
            return;
          case report::label::BODY:
            open_body(value);
            return;
          case report::label::REFERENCES:
            open_references(value);
            return;
          default:
            fail(
              "disclosed claim " + std::to_string(claim_label) +
              " is not part of the report profile");
        }
      }

      // The body is a map keyed by stable chunk index: its disclosed entries
      // are chunks in the clear, its simple(59) hashes are chunks still hidden.
      void open_body(const cbor::Value& value)
      {
        require(
          std::holds_alternative<cbor::Map>(value->value),
          "body must be a map of text chunks");
        require(!report.body_disclosed, "body disclosed twice");
        report.body_disclosed = true;
        size_t chunks = 0;
        for (const auto& [key, entry] : std::get<cbor::Map>(value->value).items)
        {
          if (is_signed(key))
          {
            const auto index = key->as_signed();
            require(index >= 0, "a body chunk index must not be negative");
            report.body_chunks[static_cast<size_t>(index)] =
              require_text(entry, "body chunk");
            ++chunks;
            continue;
          }
          require(
            std::holds_alternative<cbor::Simple>(key->value) &&
              key->as_simple() == sdcwt::REDACTED_CLAIM_KEYS,
            "unexpected entry in the body map");
          require(
            std::holds_alternative<cbor::Array>(entry->value),
            "body redacted chunk hashes must be an array");
          for (const auto& hash : std::get<cbor::Array>(entry->value).items)
          {
            require(is_bytes(hash), "a body chunk hash must be a bstr");
            pending.push_back(
              Commitment{copy_bytes(hash), report::label::BODY, 0, false});
            ++chunks;
          }
        }
        report.body_chunk_count = chunks;
      }

      // References are an array: a hidden element stays in place as
      // tag(60, hash), so element indices never shift.
      void open_references(const cbor::Value& value)
      {
        require(
          std::holds_alternative<cbor::Array>(value->value),
          "references must be an array");
        require(!report.references_disclosed, "references disclosed twice");
        report.references_disclosed = true;
        const auto& items = std::get<cbor::Array>(value->value).items;
        report.reference_count = items.size();
        for (size_t i = 0; i < items.size(); ++i)
        {
          if (is_text(items[i]))
          {
            report.references[i] = copy_text(items[i]);
            continue;
          }
          require(
            std::holds_alternative<cbor::Tagged>(items[i]->value),
            "a references element must be text or a redacted element");
          const auto& tagged = std::get<cbor::Tagged>(items[i]->value);
          require(
            tagged.tag == sdcwt::REDACTED_ELEMENT_TAG,
            "a redacted array element must use tag 60");
          require(
            is_bytes(tagged.item),
            "a redacted array element hash must be a bstr");
          pending.push_back(Commitment{
            copy_bytes(tagged.item), report::label::REFERENCES, i, true});
        }
      }

      void open_child(int64_t parent, size_t index, const cbor::Value& value)
      {
        if (parent == report::label::BODY)
        {
          require(
            index < report.body_chunk_count,
            "a disclosed body chunk index is out of range");
          require(
            report.body_chunks.find(index) == report.body_chunks.end(),
            "a body chunk was disclosed twice");
          report.body_chunks[index] = require_text(value, "body chunk");
          return;
        }
        if (parent == report::label::REFERENCES)
        {
          require(
            index < report.reference_count,
            "a disclosed reference index is out of range");
          require(
            report.references.find(index) == report.references.end(),
            "a reference was disclosed twice");
          report.references[index] = require_text(value, "reference");
          return;
        }
        fail("a disclosure names a parent that is not part of the profile");
      }

      std::string require_text(
        const cbor::Value& value, const std::string& what)
      {
        require(is_text(value), what + " must be a text string");
        auto text = copy_text(value);
        try
        {
          text::validate_utf8(text);
        }
        catch (const std::exception&)
        {
          fail(what + " is not well-formed UTF-8");
        }
        return text;
      }

      sdcwt::HashAlg sd_alg;
      DisclosedReport& report;
      std::vector<sdcwt::Path>& resolved_paths;
      std::vector<Commitment> pending;
    };

    // Runs `phase` and re-labels anything it rejects as a failure of `check`,
    // so each group of checks reports its own failures without every
    // individual rejection having to name the group it belongs to.
    template <typename Phase>
    auto in_check(Check check, Phase&& phase) -> decltype(phase())
    {
      try
      {
        return phase();
      }
      catch (const VerificationError& e)
      {
        throw VerificationError(e.reason(), check);
      }
    }

    // The single implementation behind the three entry points. A null `params`
    // means no trust anchor was supplied, so the chain and did:x509 checks are
    // not performed; a null `receipt_verifier` means no receipt is examined.
    Result run_checks(
      const bundle::ProofBundle& proof,
      const Params* params,
      const ReceiptVerifier* receipt_verifier)
    {
      const auto registered = in_check(Check::StatementBinding, [&] {
        require(
          proof.version == bundle::VERSION, "unsupported proof bundle version");
        return parse_sign1(proof.registered_statement, "registered statement");
      });
      const auto transparent = in_check(Check::StatementBinding, [&] {
        return parse_sign1(
          proof.transparent_statement, "transparent statement");
      });

      in_check(Check::StatementBinding, [&] {
        // The transparency service only adds unprotected header entries:
        // anything else means the receipt does not cover the statement being
        // shown.
        require(
          registered.protected_header == transparent.protected_header,
          "registered and transparent protected headers differ");
        require(
          registered.payload == transparent.payload,
          "registered and transparent payloads differ");
        require(
          registered.signature == transparent.signature,
          "registered and transparent signatures differ");
        require(
          !registered.has_disclosures,
          "the registered statement carries disclosures");
        require(
          !registered.has_unknown_unprotected &&
            registered.unprotected_entry_count == 0,
          "the registered statement unprotected header must be empty");
        require(
          !transparent.has_disclosures,
          "the transparent statement carries disclosures (17)");
        // Whether that receipt is valid is a separate check; that one is
        // present at all is a property of the bundle being shown.
        require(
          !transparent.receipts.empty(),
          "the transparent statement carries no receipt (394)");
        require(
          !transparent.has_unknown_unprotected &&
            transparent.unprotected_entry_count == 1,
          "the transparent statement unprotected header must contain only "
          "receipts (394)");
      });

      Result result;

      const auto header = in_check(Check::MsrcChain, [&] {
        return parse_profile_header(registered.protected_header);
      });
      result.issuer_did = header.issuer_did;
      result.subject = header.subject;

      if (params == nullptr)
      {
        result.leaf_subject =
          in_check(Check::MsrcChain, [&] { return leaf_subject(header); });
      }
      else
      {
        result.leaf_subject = in_check(Check::MsrcChain, [&] {
          require(
            !params->trusted_root.empty(),
            "no trusted root certificate was supplied");
          std::vector<uint8_t> trusted_root_der;
          try
          {
            trusted_root_der =
              ccf::crypto::cert_pem_to_der(params->trusted_root);
          }
          catch (const std::exception&)
          {
            fail("the trusted root is not a valid certificate");
          }
          auto subject =
            leaf_subject_and_check_chain(header, *params, trusted_root_der);
          check_did_x509(header, *params, trusted_root_der);
          return subject;
        });
      }

      in_check(Check::IssuerSignature, [&] {
        check_issuer_signature(header, registered);
      });

      in_check(Check::Disclosures, [&] {
        const auto payload =
          parse_clear_payload(registered.payload, header.sd_alg);
        result.issued_at = payload.issued_at;

        DisclosureResolver resolver(
          header.sd_alg, result.disclosed, result.disclosure_paths);
        resolver.add_top_level(payload.commitments);
        resolver.resolve(proof.disclosures);
      });

      if (receipt_verifier != nullptr)
      {
        in_check(Check::Receipt, [&] {
          // The receipt is checked against the EXACT bytes that were
          // registered, not against a re-encoding of the parsed statement.
          for (const auto& receipt : transparent.receipts)
          {
            try
            {
              result.receipts.push_back(
                receipt_verifier->verify(receipt, proof.registered_statement));
            }
            catch (const std::exception& e)
            {
              fail(std::string("receipt verification failed: ") + e.what());
            }
          }
        });
      }
      return result;
    }
  }

  Result verify_bundle(
    const bundle::ProofBundle& proof,
    const Params& params,
    const ReceiptVerifier& receipt_verifier)
  {
    return run_checks(proof, &params, &receipt_verifier);
  }

  Result verify_bundle(const bundle::ProofBundle& proof, const Params& params)
  {
    return run_checks(proof, &params, nullptr);
  }

  Result inspect_bundle(const bundle::ProofBundle& proof)
  {
    return run_checks(proof, nullptr, nullptr);
  }
}
