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

Needs a CCF 7.0.10 install for `ccfcrypto` and `ccf::cbor`. The commands below assume it
is at `/opt/ccf`; pass a different prefix to `scripts/run.sh` and export `CCF_PREFIX` if
it is elsewhere.

**1. Start the transparency service.** The first run fetches and builds the pinned
upstream commit, which takes a while. Leave it running.

```bash
scripts/ledger.sh
```

**2. Build and serve the demo**, in another shell:

```bash
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
export SCITT_URL=https://127.0.0.1:8000
export SCITT_SERVICE_CERT=$PWD/.ledger/workspace/sandbox_common/service_cert.pem
scripts/run.sh /opt/ccf
```

### Walk through it

Three pages, one per role. Open them in this order.

**MSRC, <http://127.0.0.1:8080/msrc>.** Press **Load key** with no file chosen to
generate the key MSRC will sign releases with. Its public half is published so that
statements can name it in `cnf`; the private half stays in the browser. Follow **Publish
the MSRC root certificate** and keep the file: a reader needs it later.

Keep this page open in its own tab. The generated key is non-extractable and lives only
in the tab, so reloading loses it, and generating another one invalidates any statement
that already named the first. To survive a reload, supply your own key instead:
`openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out msrc-release.pem`,
then load that file.

**Researcher, <http://127.0.0.1:8080/>.** Press **Enroll** to generate a key in the
browser and get a certificate for it. Fill in the report and press **Sign and submit**.
The backend hands back the bytes to sign, the browser signs them, and the statement is
registered with the service started in step 1. Every content claim is redacted before it
goes, so the service registers a report it cannot read. Follow **Download the proof
bundle**.

**MSRC again.** Load that bundle. The report appears with its disclosures open. Tick a
field, or click and drag across the body, to withhold parts of it: black bars are what
the release will not open. Press **Sign and export** to get a `.cose` release.

**Reader, <http://127.0.0.1:8080/verify>.** Supply the release, the MSRC root from the
first step, and the service certificate at `$SCITT_SERVICE_CERT`. All six checks should
pass. The withheld text shows as black bars: committed to by the registered statement,
but not opened by this release.

Leave the service certificate out and the receipt is reported as **not checked** rather
than passed, because without it nothing shows the statement was ever registered.

### Check it without a browser

```bash
scripts/demo_test.sh
```

Starts the service, starts the app, runs the whole flow, and asserts that all six checks
pass, that a missing service certificate leaves the receipt unchecked, and that a
tampered release is refused. This is what CI runs.

### Pin the issuer

The service starts out accepting any `did:x509` that names a subject. To pin it to this
deployment's MSRC root instead, take the issuer from the researcher page after enrolling
and re-run governance:

```bash
scripts/ledger_configure.sh .ledger/workspace/sandbox_common 'did:x509:0:sha256:...'
```

Anything else is then refused at registration, before it reaches the log.

## Layout

| Path                   | What                                                      |
| ---------------------- | --------------------------------------------------------- |
| `core/`                | SD-CWT, COSE, CBOR, bundles, verification, CCF receipts   |
| `native/`              | The in-memory API: bytes in, bytes out, no filesystem     |
| `bindings/`            | The `_native` Python extension module                     |
| `app/`                 | FastAPI pages, the transparency service client, mock MSRC |
| `tests/`               | C++ and extension-module tests, and the full-flow test    |
| `scripts/ledger.sh`    | Builds and starts a real scitt-ccf-ledger                 |
| `scripts/demo_test.sh` | The whole flow, end to end, no browser                    |

## Status

A demonstration, not a deployment. The transparency service is real: statements are
appended to a CCF ledger, and a receipt is only accepted once its Merkle inclusion proof
leads from the statement's digest to a root the service signed. MSRC is mocked, issuing
a fresh root on startup, and submission to the ledger is unauthenticated.
