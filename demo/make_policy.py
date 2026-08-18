#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Build the SCITT ledger configuration that restricts registration.

``demo/run.sh`` uses this to replace the permissive policy that upstream's
``scitt governance local_development`` installs. The resulting document is fed
to the official ``scitt governance propose_configuration`` command, which runs
in the pinned submodule's own virtual environment.

This script only formats JSON. It performs no cryptography and imports no COSE
or CBOR library.
"""

from __future__ import annotations

import argparse
import json
import sys

# The policy runs inside the ledger. It sees the decoded protected header of a
# submitted statement and returns ``true`` or a rejection string.
POLICY_TEMPLATE = """export function apply(phdr) {
  const expected = %(issuer)s;
  if (phdr.cwt === undefined) { return "Missing CWT claims"; }
  if (phdr.cwt.iss !== expected) { return "Issuer is not the enrolled MSRC root"; }
  if (typeof phdr.cwt.sub !== "string" || phdr.cwt.sub.length === 0) {
    return "Missing CWT subject";
  }
  if (phdr.cwt.sub.length > %(max_subject)d) { return "CWT subject is too long"; }
  return true;
}"""


def build_policy(issuer: str, max_subject: int) -> str:
    """Return the policy script that pins one exact did:x509 issuer."""
    if not issuer.startswith("did:x509:0:"):
        raise ValueError(f"not a did:x509 version 0 identifier: {issuer!r}")
    if "::" not in issuer:
        raise ValueError(f"did:x509 identifier carries no policy: {issuer!r}")
    return POLICY_TEMPLATE % {
        "issuer": json.dumps(issuer),
        "max_subject": max_subject,
    }


def build_configuration(issuer: str, max_subject: int) -> dict[str, object]:
    """Return the full ledger configuration document."""
    return {
        "authentication": {"allowUnauthenticated": True},
        "policy": {"policyScript": build_policy(issuer, max_subject)},
    }


def main(argv: list[str] | None = None) -> int:
    """Write the configuration document requested on the command line."""
    parser = argparse.ArgumentParser(prog="make_policy.py")
    parser.add_argument(
        "--issuer",
        required=True,
        help="the exact did:x509 identifier the ledger must accept",
    )
    parser.add_argument(
        "--max-subject",
        type=int,
        default=256,
        help="maximum accepted length of the CWT subject claim",
    )
    parser.add_argument("--output", help="file to write (defaults to stdout)")
    args = parser.parse_args(argv)

    try:
        document = build_configuration(args.issuer.strip(), args.max_subject)
    except ValueError as error:
        sys.stderr.write(f"error: {error}\n")
        return 2

    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
