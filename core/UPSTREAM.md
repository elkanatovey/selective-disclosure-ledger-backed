<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# Provenance of `core/`

This directory mixes code ported from an earlier internal prototype with code
written for this repository. Everything here is Microsoft-authored and MIT
licensed; this file records which parts came from where so that a reviewer can
diff against the original and so that fixes can flow back.

## Upstream prototype

The token layer is derived from the **Selective Disclosure Report Ledger**
prototype, a CCF application whose SD-CWT implementation lives under
`app/src/token/`. That prototype is the source of the wire format: the CDE
encoder, the COSE_Sign1 helpers and the SD-CWT redaction/disclosure machinery.

| File here | Upstream file | Relationship |
| --- | --- | --- |
| `cbor_value.h`, `cbor_value.cpp` | `app/src/token/cbor_value.{h,cpp}` | Ported. The value tree, the CDE map-key ordering and the conversion to and from `ccf::cbor` are unchanged in behaviour. |
| `cose.h`, `cose.cpp` | `app/src/token/cose.{h,cpp}` | Ported, then extended: `sign_cose_sign1` accepts additional protected header entries so the SCITT X.509 headers can be added without a second encoder. |
| `sd_cwt.h`, `sd_cwt.cpp`, `sd_cwt_internal.h` | `app/src/token/sd_cwt.{h,cpp}`, `sd_cwt_internal.h` | Ported. Salting, decoys, Redacted Claim Hashes, ancestor resolution and `present()` follow the upstream algorithm. |

Deliberate divergences from the prototype:

- **Key binding removed.** The prototype carried a `cnf` claim and issued Key
  Binding Tokens. This demo verifies statements offline from a proof bundle, so
  there is no holder key and no KBT; the `cnf` claim and the KBT code were
  dropped rather than ported and left unused.
- **Extra protected headers.** `sign_cose_sign1` takes `HeaderEntries
  extra_protected`, which is how `crit`, the CWT claims header and `x5chain`
  reach the signed header. The prototype only ever emitted `alg`, `typ` and
  `sd_alg`.
- **`present()` preserves the rest of the unprotected header.** It replaces
  only label 17 and copies every other entry through, so a receipt in label 394
  survives repeated disclosure edits. The prototype rebuilt the unprotected
  header from scratch because receipts were attached later by the ledger.
- **Content profile.** The prototype's claim set (including `parent`, `patch`
  and `patch_date`) was replaced by the six-claim bug report profile in
  `report.h`.

## Written for this repository

These files have no upstream counterpart:

| File | Purpose |
| --- | --- |
| `text_chunks.h`, `text_chunks.cpp` | UTF-8 validation and six-code-point chunking, so long text can be disclosed a fragment at a time. |
| `profile.h`, `profile.cpp` | The SCITT X.509 profile: `did:x509` construction and parsing, CA fingerprints, and the protected header entries built from a certificate chain. |
| `report.h`, `report.cpp` | The bug report claim profile: issuance with every content claim redacted, and disclosure selection including ancestor resolution. |
| `bundle.h`, `bundle.cpp` | The offline proof bundle: strict encoding and decoding with explicit type, count, size and version checks. |
| `verify.h`, `verify.cpp` | Offline verification: chain and `did:x509` policy, issuer signature, registered/transparent equality, disclosure resolution and receipt hand-off. |

## Third-party code

`core/` contains no vendored third-party source. Everything comes from CCF:

- CBOR is `ccf::cbor` (CCF's EverCBOR binding). There is no CBOR parser or
  encoder in this repository.
- Cryptography is `ccf::crypto`: `Verifier` and `verify_certificate` for X.509,
  `make_cose_verifier_from_der_cert` for COSE signatures, `sha256`, `b64url`
  and `create_entropy` elsewhere. No algorithm is implemented here and OpenSSL
  is never called directly.
- `did:x509` resolution uses `didx509cpp/didx509cpp.h`, which CCF ships in its
  `include/3rdparty` directory (MIT licensed, header only). It is included from
  the CCF prefix, not copied here.

Tests additionally use fixed PEM certificates in `tests/core/eku_test_certs.h`.
Those are test-only artefacts generated for this repository, with their
regeneration commands recorded in the header; they are not upstream material.
