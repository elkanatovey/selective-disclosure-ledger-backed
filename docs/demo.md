<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# Running the demonstration

The demonstration starts an unmodified, pinned SCITT CCF ledger and two local
application processes:

- the role-based web application at `http://127.0.0.1:8080`;
- the mock MSRC service at `http://127.0.0.1:8081`; and
- the SCITT ledger at `https://127.0.0.1:8000`.

## Prerequisites

- Docker with a reachable daemon and host networking support;
- Git;
- Python 3.12 or newer;
- CMake, Ninja and CCF 7.0.10 when building the C++ client natively; and
- `curl`.

Initialise the pinned submodule before the first run:

```bash
git submodule update --init --recursive
```

## Start the interactive demonstration

```bash
demo/run.sh
```

The launcher:

1. verifies that `third_party/scitt-ccf-ledger` is at commit
   `5d471384ef7808cb0208ac3d141b4910b83cb48f`;
2. builds the EverCBOR/CCF C++ client;
3. builds and starts the upstream SCITT service;
4. creates a demo MSRC root and subject-constrained `did:x509` issuer with the C++
   client;
5. replaces SCITT's permissive development policy with a policy accepting only that
   exact issuer;
6. fetches the SCITT service key set independently;
7. starts the mock MSRC and web processes; and
8. prints the role URLs.

Policy replacement is fail-closed. The role applications are not started if governance
does not accept the restrictive policy.

Press Ctrl+C to stop all processes. By default, the launcher removes only the container,
volume, PIDs and state directory created for that run. Pass `--keep` to retain the run
directory for inspection.

## Automated smoke flow

```bash
demo/run.sh --smoke
```

The smoke flow performs enrollment, creates and registers a fully redacted statement,
delivers the full proof bundle to mock MSRC, produces a reduced presentation, and runs
the local and official SCITT verification paths.

## Role flow

### Researcher

Open `/researcher`.

1. Select a P-256 private key.
2. Enrol the corresponding public key with mock MSRC.
3. Fill in the report.
4. Press Submit once.

The private key is passed only to the local C++ client. Enrollment sends the derived
public key, not the private key. The application first waits for SCITT registration,
then sends the proof bundle and disclosures to mock MSRC.

If MSRC delivery fails after registration, the page reports partial success and offers
the bundle for download and retry. It never reports the two-step operation as wholly
successful in that case.

### MSRC

Open `/msrc`.

Import a proof bundle or select a stored submission. Whole fields can be removed with
controls. Report-body text is shown as stable, indexed chunks of six Unicode code
points; selecting text removes the corresponding disclosure. Export produces a new proof
bundle without the dropped disclosures.

No signing key is required for this operation. The protected header, signed payload and
researcher signature are unchanged.

### Verifier

Open `/verifier`.

Import:

- a proof bundle;
- an independently obtained MSRC root certificate; and
- the SCITT key set fetched from `/.well-known/scitt-keys`.

The result reports independent checks for the MSRC chain and `did:x509`, researcher
signature, disclosure consistency, registered/transparent statement binding, and SCITT
receipt.

The SCITT check is delegated to `pyscitt.verify.verify_transparent_statement` in the
pinned upstream submodule's isolated virtual environment. It receives the exact
registered statement bytes retained in the proof bundle; the statement is not
reconstructed or re-encoded.

## Development-only limitations

- The web backend temporarily handles the imported researcher key. Production signing
  must happen in a researcher-controlled browser, native client, hardware-backed key
  store or equivalent boundary.
- The ledger uses one development node and development TLS handling.
- The mock MSRC root is generated for each run and stored on the local filesystem.
- Subject-constrained `did:x509` is used because the CCF high-level certificate API does
  not expose an EKU extension during demo enrollment. A production deployment can use an
  approved certificate issuance system and an EKU policy.
- Six-code-point chunks leak approximate report length and disclosed positions.
  Production profiles should define padding buckets and decoys.
- A valid receipt proves registration and ordering, not that two vulnerability reports
  are semantically equivalent.

See `architecture.md` and `security.md` for the protocol and trust model.
