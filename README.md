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
4. The backend attaches the signature, registers the statement with the mock
   transparency service, then sends the full bundle (disclosures and receipt) to mock
   MSRC.

Steps 2 and 4 are the C++ core, in process, through the `_native` extension module. No
CBOR or cryptography is implemented in Python.

## Run it

Needs a CCF 7.0.10 install for `ccfcrypto` and `ccf::cbor`.

```bash
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e .
scripts/run.sh /path/to/ccf/prefix
```

Then open <http://127.0.0.1:8080>.

## Layout

| Path        | What                                                  |
| ----------- | ----------------------------------------------------- |
| `core/`     | SD-CWT, COSE, CBOR, bundles, verification             |
| `native/`   | The in-memory API: bytes in, bytes out, no filesystem |
| `bindings/` | The `_native` Python extension module                 |
| `app/`      | FastAPI researcher page and the two mocks             |
| `tests/`    | C++ and extension-module tests (`ctest`)              |

## Status

A demonstration, not a deployment. The mock transparency service has no log, no
inclusion proof and no consistency proof: its receipt shows only that its key saw those
bytes. Mock MSRC issues a fresh root on startup.
