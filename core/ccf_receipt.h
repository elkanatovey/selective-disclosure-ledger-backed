// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// Verification of a receipt issued by a CCF-backed transparency service.
//
// A real receipt says nothing directly about the registered statement. It is
// a COSE_Sign1 with a DETACHED payload, signed by the service identity over
// the root of the ledger's Merkle tree, and it carries an inclusion proof
// (COSE header 396) that leads from a leaf to that root. The statement is
// bound in only at the very bottom: the leaf's claims digest is the SHA-256
// of the exact registered statement bytes.
//
// Checking a receipt is therefore a walk, not a signature check:
//
//   leaf = SHA-256(write set digest || SHA-256(commit evidence) || claims)
//   root = fold the proof path into the leaf
//   the service's signature over that root must verify
//
// Every step has to hold for the receipt to attest to this statement, and the
// claims digest is what stops a receipt for one statement being replayed onto
// another.

#include "core/verify.h"

#include <ccf/crypto/pem.h>
#include <span>

namespace scitt_sd::verify
{
  // Verifies a CCF receipt against the service identity certificate, which a
  // reader obtains out of band: a receipt checked against a certificate taken
  // from the bundle would establish nothing.
  //
  // Only the CCF_LEDGER_SHA256 verifiable data structure (`vds` 2) is
  // accepted; a receipt built over anything else is refused rather than
  // ignored.
  class CcfReceiptVerifier : public ReceiptVerifier
  {
  public:
    explicit CcfReceiptVerifier(ccf::crypto::Pem service_certificate);

    ReceiptInfo verify(
      std::span<const uint8_t> receipt,
      std::span<const uint8_t> registered_statement) const override;

  private:
    ccf::crypto::Pem certificate;
  };
}
