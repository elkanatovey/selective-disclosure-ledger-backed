// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <ccf/crypto/pem.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace scitt_sd::native
{
  // Private key material handling.
  //
  // CCF's own types own key material properly: an ECKeyPair holds an OpenSSL
  // key that OpenSSL frees, and nothing here ever copies it out. What CCF does
  // not offer is a wiping string, and ccf::crypto::Pem is a plain std::string,
  // so any PEM this API holds on the way in or out is overwritten here before
  // it is released. That is memory hygiene, not cryptography: it bounds how
  // long a private key stays legible in this process, and nothing more.

  // Overwrite a buffer, through a volatile pointer so that the writes are not
  // optimised away as dead stores.
  void secure_clear(uint8_t* data, size_t size);
  void secure_clear(std::string& text);
  void secure_clear(std::vector<uint8_t>& bytes);
  void secure_clear(ccf::crypto::Pem& pem);

  // A PEM holding caller-supplied private key material, overwritten when it
  // goes out of scope. Non-copyable and non-movable: exactly one buffer holds
  // the secret, so exactly one buffer has to be cleared.
  class SecretPem
  {
  public:
    // Throws InvalidInput, naming `description`, when the bytes are not a PEM
    // document.
    SecretPem(std::span<const uint8_t> bytes, std::string_view description);
    SecretPem(const SecretPem&) = delete;
    SecretPem& operator=(const SecretPem&) = delete;
    SecretPem(SecretPem&&) = delete;
    SecretPem& operator=(SecretPem&&) = delete;
    ~SecretPem();

    [[nodiscard]] const ccf::crypto::Pem& pem() const
    {
      return pem_;
    }

  private:
    ccf::crypto::Pem pem_;
  };

  // Copy a PEM out to the caller. The source is cleared: it is a temporary
  // this API owns, and the copy the caller now holds is the only one that has
  // to outlive the call.
  std::vector<uint8_t> release_secret(ccf::crypto::Pem&& pem);
}
