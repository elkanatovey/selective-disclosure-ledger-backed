// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "native/secrets.h"

#include "native/errors.h"

#include <exception>
#include <utility>

namespace scitt_sd::native
{
  void secure_clear(uint8_t* data, size_t size)
  {
    if (data == nullptr)
    {
      return;
    }
    volatile uint8_t* cursor = data;
    for (size_t i = 0; i < size; ++i)
    {
      cursor[i] = 0;
    }
  }

  void secure_clear(std::string& text)
  {
    secure_clear(reinterpret_cast<uint8_t*>(text.data()), text.size());
    text.clear();
  }

  void secure_clear(std::vector<uint8_t>& bytes)
  {
    secure_clear(bytes.data(), bytes.size());
    bytes.clear();
  }

  void secure_clear(ccf::crypto::Pem& pem)
  {
    secure_clear(pem.data(), pem.size());
    pem = ccf::crypto::Pem();
  }

  SecretPem::SecretPem(
    std::span<const uint8_t> bytes, std::string_view description)
  {
    try
    {
      pem_ = ccf::crypto::Pem(bytes);
    }
    catch (const std::exception& e)
    {
      throw InvalidInput(
        std::string(description) + " is not a PEM document: " + e.what());
    }
  }

  SecretPem::~SecretPem()
  {
    secure_clear(pem_);
  }

  std::vector<uint8_t> release_secret(ccf::crypto::Pem&& pem)
  {
    ccf::crypto::Pem owned = std::move(pem);
    std::vector<uint8_t> copy = owned.raw();
    secure_clear(owned);
    return copy;
  }
}
