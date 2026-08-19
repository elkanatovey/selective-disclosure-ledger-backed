// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace scitt_sd::native
{
  // The demo's certificate and identity profile, in one place so that the
  // command that mints a certificate and the command that names the issuer in
  // a statement cannot drift apart.
  namespace profile
  {
    // The self-signed CA `root init` creates. It is the MSRC trust anchor the
    // verifier is separately given; nothing in a bundle can vouch for it.
    inline constexpr std::string_view ROOT_SUBJECT = "CN=MSRC Demo Root CA";
    inline constexpr size_t ROOT_VALIDITY_DAYS = 365;

    // The reporter's leaf certificate. CCF's high-level certificate API
    // creates the CSR itself and offers no way to request an Extended Key
    // Usage extension, so the leaf cannot carry id-kp-codeSigning and the
    // issuer's did:x509 pins this subject instead of an EKU.
    inline constexpr std::string_view REPORTER_COMMON_NAME =
      "MSRC Demo Reporter";
    inline constexpr std::string_view REPORTER_SUBJECT =
      "CN=MSRC Demo Reporter";
    // A reporting key is short-lived: the certificate is valid for one day.
    inline constexpr size_t LEAF_VALIDITY_SECONDS = 24 * 60 * 60;

    // CWT `sub` (claim 2) of every statement this API issues. The subject is
    // in the clear, so it names the KIND of thing being attested and never
    // anything about the report itself.
    inline constexpr std::string_view REPORT_SUBJECT = "urn:msrc-demo:report";
  }

  // Percent-encode a did:x509 policy argument. did:x509 splits an identifier
  // on ':' and unescapes each argument, so an argument containing a space, a
  // colon or a percent sign has to be escaped for the identifier to parse back
  // to the value that was meant.
  std::string percent_encode_did_arg(std::string_view value);

  // did:x509:0:sha256:<base64url(SHA-256(root DER))>::subject:CN:<encoded CN>
  //
  // A subject policy rather than an EKU policy: see REPORTER_COMMON_NAME.
  std::string make_subject_did(
    std::span<const uint8_t> root_der,
    std::string_view common_name = profile::REPORTER_COMMON_NAME);

  // An X.509 time string (YYYYMMDDHHMMSSZ) `offset_seconds` from now.
  std::string x509_time_from_now(int64_t offset_seconds = 0);

  // Seconds since the Unix epoch, for the CWT `iat` claim.
  int64_t now_seconds();
}
