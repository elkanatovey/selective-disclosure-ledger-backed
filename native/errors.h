// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <stdexcept>
#include <string>

namespace scitt_sd::native
{
  // Anything the API refuses because of what it was handed: a malformed
  // document, a key that is not a key, a certificate that does not certify the
  // key it was given with. An invalid input is never a statement about a
  // bundle's trustworthiness, and a caller can always fix it by passing
  // something else.
  //
  // The command line reports it as a usage error, and the Python binding
  // raises ValueError.
  class InvalidInput : public std::runtime_error
  {
  public:
    explicit InvalidInput(const std::string& what) : std::runtime_error(what) {}
  };

  // Anything that failed for a reason the caller did not supply: the crypto
  // stack refusing to produce a key, an artifact that could not be encoded.
  //
  // The command line reports it as a usage error too (it can do nothing else),
  // and the Python binding raises RuntimeError.
  class OperationFailed : public std::runtime_error
  {
  public:
    explicit OperationFailed(const std::string& what) : std::runtime_error(what)
    {}
  };
}
