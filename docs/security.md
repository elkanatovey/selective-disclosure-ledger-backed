<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# Security model

## Claims

The system can prove that:

- a particular signed commitment was accepted by a particular trusted SCITT service at a
  ledger position;
- disclosed values match commitments in that signed statement;
- the statement's signing certificate chained to an MSRC root trusted by the verifier at
  verification time.

It cannot prove that a vulnerability is genuine, that two reports describe the same
underlying flaw, or that an MSRC bounty decision is fair. A production duplicate
decision should itself be an MSRC-signed statement referencing both SCITT transaction
identifiers.

## Trust anchors

An embedded certificate or SCITT key is never trusted merely because it is embedded.
Verification requires:

- an independently obtained MSRC root certificate; and
- independently obtained SCITT service trust material.

Key rotation and recovery require trust-store update and historical endorsement
handling.

## Private keys

The demo imports a researcher private key into the local web backend long enough to
invoke the C++ client. It writes the key only to a restricted temporary directory and
deletes that directory after the request.

Production must move signing into the browser, a native researcher client, a
hardware-backed key store, or another researcher-controlled boundary. The private key
must never be sent to MSRC or SCITT.

MSRC enrollment receives only the public key and returns a short-lived certificate.

## Disclosure privacy

The six-code-point chunks leak:

- approximate report length;
- positions of disclosed text; and
- equality or structure implied by other clear profile fields.

Production should define size buckets and decoy padding. Salts must remain secret until
disclosure and must never be reused. The C++ core obtains salts from CCF's entropy API.

Unprotected headers are mutable. The issuer signature and SCITT receipt bind the
protected header, signed payload, and issuer signature, while disclosures and embedded
receipts are carried separately. Verifiers must hash-match every presented disclosure
and reject unmatched disclosures.

## Implementation boundaries

The shipped application does not implement CBOR, COSE algorithms, certificate
cryptography, or Merkle receipt algorithms:

- CCF's EverCBOR-backed `ccf::cbor` parses and serializes CBOR.
- CCF crypto performs key generation, hashing, X.509 operations, and COSE signatures.
- Existing CCF receipt APIs perform COSE receipt parsing and verification.

The pinned SCITT submodule is an external service with its own implementation and
development tooling. Its permissive local-development governance configuration is not
suitable for production.

## Operational requirements

A production deployment must:

- configure SCITT registration policy for the approved MSRC `did:x509` root and EKU;
- authenticate write requests;
- protect MSRC root and enrollment keys with managed key storage;
- enforce report, bundle, and upload limits at every boundary;
- retain exact registered-statement bytes;
- audit SCITT and MSRC key rotation;
- use TLS without development-mode verification bypasses; and
- define retention, deletion, access-control, and incident-response policies for
  unredacted reports and salts.
