<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# SCITT selective-disclosure reports

A researcher submits a bug report as an X.509-signed SD-CWT. Every content claim is
redacted, so the transparency service registers a statement it cannot read. Only
afterwards does MSRC receive the disclosures.

The signing key is generated in the browser and never leaves it. The backend builds the
statement, hands the browser the exact bytes to sign, and holds no key material at any
point.

## The flow

1. The browser generates a non-extractable P-256 key and sends only the public half.
   Mock MSRC returns a leaf certificate chaining to its root.
2. The backend builds the redacted SD-CWT and returns its RFC 9052 `Sig_structure`.
3. The browser signs those bytes with WebCrypto.
4. The backend attaches the signature, registers the statement with a real SCITT
   transparency service, then sends the full bundle (disclosures and receipt) to mock
   MSRC.
5. MSRC withholds whatever it chooses and signs the release with the key the statement
   named in `cnf`. A reader checks that release against the MSRC root and the
   transparency service certificate, both supplied out of band.

Steps 2, 4 and 5 are the C++ core, in process, through the `_native` extension module.
No CBOR or cryptography is implemented in Python.

## Run it

Needs a CCF 7.0.10 install for `ccfcrypto` and `ccf::cbor`.

Start the transparency service. The first run clones and builds it from the pinned
upstream commit, which takes a while.

```bash
scripts/ledger.sh
```

Then, in another shell:

```bash
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e .
export SCITT_URL=https://127.0.0.1:8000
export SCITT_SERVICE_CERT=$PWD/.ledger/workspace/sandbox_common/service_cert.pem
scripts/run.sh /path/to/ccf/prefix
```

Then open <http://127.0.0.1:8080>.

The ledger starts out accepting any `did:x509` issuer that names a subject. To pin it to
this deployment's MSRC root instead, take the issuer from an enrolment and re-run
governance:

```bash
scripts/ledger_configure.sh .ledger/workspace/sandbox_common 'did:x509:0:sha256:...'
```

## Layout

| Path        | What                                                      |
| ----------- | --------------------------------------------------------- |
| `core/`     | SD-CWT, COSE, CBOR, bundles, verification, CCF receipts   |
| `native/`   | The in-memory API: bytes in, bytes out, no filesystem     |
| `bindings/` | The `_native` Python extension module                     |
| `app/`      | FastAPI pages, the transparency service client, mock MSRC |
| `tests/`    | C++ and extension-module tests (`ctest`)                  |

## Status

A demonstration, not a deployment. The transparency service is real: statements are
appended to a CCF ledger, and a receipt is only accepted once its Merkle inclusion proof
leads from the statement's digest to a root the service signed. MSRC is mocked, issuing
a fresh root on startup, and submission to the ledger is unauthenticated.
