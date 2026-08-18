<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# Contributing

Contributions must preserve the protocol's trust boundaries and exact-byte SCITT receipt
binding.

Before submitting a change:

1. Run `scripts/checks.sh -f`.
2. Run `scripts/validate_cddl.sh`.
3. Run `demo/run.sh --smoke` when Docker is available.
4. Add tests for behavior changes.

Every first-party text file must carry the Microsoft MIT notice and contain ASCII text
only. Third-party source belongs under `third_party/` or must have its provenance
recorded in `THIRD_PARTY_NOTICES.md`.
