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

Three parties, three processes. The researcher never holds MSRC's CA key, and the
verifier holds nothing at all.

1. The browser generates a non-extractable P-256 key and sends only the public half.
   MSRC returns a leaf certificate chaining to its root.
2. The researcher's agent builds the redacted SD-CWT and returns its RFC 9052
   `Sig_structure`.
3. The browser signs those bytes with WebCrypto.
4. The agent attaches the signature and registers the statement with a real SCITT
   transparency service.
5. **The agent verifies the receipt itself**, against the service identity, before
   anyone else is told. Registration is the service's claim until then, so a report
   whose receipt does not verify is never handed to MSRC at all.
6. Only then does the bundle go to MSRC, which withholds whatever it chooses and signs
   the release with the key the statement named in `cnf`.
7. A reader checks that release against the MSRC root and the service identity, both
   supplied out of band, using a verifier that knows nothing about either party.

Steps 2 and 4 to 7 are the C++ core, in process, through the `_native` extension module.
No CBOR or cryptography is implemented in Python.

Because the researcher verifies the receipt rather than trusting the reply, no browser
ever needs to reach the transparency service. That matters: CCF serves TLS under its own
self-signed service identity, which no browser will trust without being told to.

## Run it

Needs a CCF 7.0.10 install for `ccfcrypto` and `ccf::cbor`. The commands below assume it
is at `/opt/ccf`; pass a different prefix to `scripts/run.sh` and export `CCF_PREFIX` if
it is elsewhere.

**1. Start the transparency service.** The first run fetches and builds the pinned
upstream commit, which takes a while. Leave it running.

```bash
scripts/ledger.sh
```

**2. Build and serve the three roles**, in another shell:

```bash
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
export SCITT_URL=https://127.0.0.1:8000
export SCITT_SERVICE_CERT=$PWD/.ledger/workspace/sandbox_common/service_cert.pem
scripts/run.sh /opt/ccf
```

| Role       | Where                   |
| ---------- | ----------------------- |
| Researcher | <http://127.0.0.1:8080> |
| MSRC       | <http://127.0.0.1:8081> |
| Verify     | <http://127.0.0.1:8082> |

`SCITT_SERVICE_CERT` answers two different questions here, because a CCF sandbox serves
TLS under its own service identity: how to reach the service, and whose signature makes
a receipt worth anything. Set `SCITT_SERVICE_IDENTITY` to separate them.

### Walk through it

Three services, one per role. Open them in this order.

**MSRC, <http://127.0.0.1:8081>.** Press **Load key** with no file chosen to generate
the key MSRC will sign releases with. Its public half is published so that statements
can name it in `cnf`; the private half stays in the browser. Follow **Publish the MSRC
root certificate** and keep the file: a reader needs it later.

Keep this page open in its own tab. The generated key is non-extractable and lives only
in the tab, so reloading loses it, and generating another one invalidates any statement
that already named the first. To survive a reload, supply your own key instead:
`openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out msrc-release.pem`,
then load that file.

**Researcher, <http://127.0.0.1:8080>.** Press **Enroll** to generate a key in the
browser and get a certificate for it from MSRC. Fill in the report and press **Sign and
submit**. The agent hands back the bytes to sign, the browser signs them, the statement
is registered with the service started in step 1, and the agent checks the receipt
before MSRC is told anything. Every content claim is redacted before it goes, so the
service registers a report it cannot read. Follow **Download the proof bundle**.

**MSRC again.** Load that bundle. The report appears with its disclosures open. Tick a
field, or click and drag across the body, to withhold parts of it: black bars are what
the release will not open. Press **Sign and export** to get a `.cose` release.

**Reader, <http://127.0.0.1:8082>.** Supply the release, the MSRC root from the first
step, and the service certificate at `$SCITT_SERVICE_CERT`. All six checks should pass.
The withheld text shows as black bars: committed to by the registered statement, but not
opened by this release.

Leave the service certificate out and the receipt is reported as **not checked** rather
than passed, because without it nothing shows the statement was ever registered.

### Check it without a browser

```bash
scripts/demo_test.sh
```

Starts the service, starts the three roles, runs the whole flow, and asserts that all
six checks pass, that a missing service certificate leaves the receipt unchecked, that a
tampered release is refused, and that a researcher who cannot verify its receipt never
delivers the report at all. This is what CI runs.

### Pin the issuer

The service starts out accepting any `did:x509` that names a subject. To pin it to this
deployment's MSRC root instead, take the issuer from the researcher page after enrolling
and re-run governance:

```bash
scripts/ledger_configure.sh .ledger/workspace/sandbox_common 'did:x509:0:sha256:...'
```

Anything else is then refused at registration, before it reaches the log.

## Layout

| Path                   | What                                                    |
| ---------------------- | ------------------------------------------------------- |
| `core/`                | SD-CWT, COSE, CBOR, bundles, verification, CCF receipts |
| `native/`              | The in-memory API: bytes in, bytes out, no filesystem   |
| `bindings/`            | The `_native` Python extension module                   |
| `app/researcher.py`    | The researcher's agent, which checks its own receipt    |
| `app/msrc.py`          | MSRC: the CA, the intake and the release desk           |
| `app/verify.py`        | The reader's verifier, which knows nothing              |
| `tests/`               | C++ and extension-module tests, and the full-flow test  |
| `scripts/ledger.sh`    | Builds and starts a real scitt-ccf-ledger               |
| `scripts/demo_test.sh` | The whole flow, end to end, no browser                  |

## Status

A demonstration, not a deployment. The transparency service is real: statements are
appended to a CCF ledger, and a receipt is only accepted once its Merkle inclusion proof
leads from the statement's digest to a root the service signed.

MSRC runs as its own service, but what it does there is mocked: it certifies any public
key it is offered, without checking who is asking, and issues a fresh root on startup. A
deployment's entire trust story lives in that decision. Submission to the ledger is
unauthenticated, and none of the three services authenticate anything.
