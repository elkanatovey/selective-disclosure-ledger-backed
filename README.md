<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# SCITT selective-disclosure reports

This repository demonstrates a bug-report workflow in which:

1. A researcher creates an X.509-signed SD-CWT containing salted commitments to all
   report content.
2. The exact disclosure-free statement is registered with a SCITT transparency service.
3. After SCITT returns a transparent statement and receipt, the application sends a
   proof bundle containing the disclosures to a mock MSRC service.
4. MSRC can remove field or six-code-point text disclosures without the researcher's
   signing key.
5. A verifier independently checks the MSRC trust chain, issuer signature, disclosures,
   and SCITT receipt.

The browser exposes researcher, MSRC, and verifier pages. A single researcher submission
performs the two network operations transparently.

## Status

This is a demonstration, not a production deployment. In particular, the demo backend
handles an imported researcher private key for one request. Production code must perform
SD-CWT creation and signing in the browser or another researcher-controlled client so
the private key never leaves that trust boundary.

## Quick start

Prerequisites:

- Docker with host networking support
- Git submodules
- Python 3.12
- Node.js 22 for repository formatting checks

```bash
git submodule update --init --recursive
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
demo/run.sh
```

The launcher builds and starts the pinned SCITT CCF ledger, applies a registration
policy restricted to the mock MSRC CA, starts the mock MSRC service, and serves the
role-based web application on `http://127.0.0.1:8080`.

Run the non-interactive end-to-end demonstration with:

```bash
demo/run.sh --smoke
```

## Development

Run all local checks:

```bash
scripts/checks.sh
```

Apply supported formatters:

```bash
scripts/checks.sh -f
```

See `docs/architecture.md`, `docs/security.md`, and `docs/demo.md` for the protocol,
trust boundaries, and demo details.
