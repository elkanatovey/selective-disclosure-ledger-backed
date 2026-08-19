<!--
  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.
-->

# Security

Do not report security vulnerabilities through a public issue.

Use the security reporting process for the Microsoft organization or contact the
repository maintainers privately. Include reproduction steps and affected versions
without including live credentials, private keys, or undisclosed vulnerability-report
content.

The demo is intentionally not production hardened. The transparency service and MSRC are
both mocks: the mock ledger keeps no log and issues no inclusion proof, and the mock
MSRC root is generated fresh on every start. The researcher's signing key is generated
in the browser and is never sent to the backend.
