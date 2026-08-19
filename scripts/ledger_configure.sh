#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Put the demo's SCITT configuration in place through CCF governance.
#
# Usage: ledger_configure.sh <sandbox_common_dir> [issuer_did]
#
# Without an issuer, any did:x509 naming a subject may register: enough to
# demonstrate disclosure, but not a policy to copy. With one, only that exact
# issuer is accepted, which is what a real deployment would pin.

set -euo pipefail

COMMON=$1
ISSUER_DID=${2:-}

CCF_PREFIX=${CCF_PREFIX:-/opt/ccf}
CCF_URL=${CCF_URL:-https://127.0.0.1:8000}
API="api-version=2024-07-01"

# The sandbox builds this environment on first run; it carries the governance
# signing helper and nothing this repository depends on.
VENV=$(dirname "$COMMON")/../.venv_ccf_sandbox/bin
[ -x "$VENV/ccf_cose_sign1" ] || VENV="$PWD/.venv_ccf_sandbox/bin"
[ -x "$VENV/ccf_cose_sign1" ] || {
  echo "no CCF governance tooling found; start the sandbox first" >&2
  exit 2
}

curlg() { curl -sS --cacert "$COMMON/service_cert.pem" "$@"; }
sign() {
  "$VENV/ccf_cose_sign1" --ccf-gov-msg-created_at "$(date -uIs)" \
    --signing-key "$COMMON/member0_privk.pem" \
    --signing-cert "$COMMON/member0_cert.pem" "$@"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

"$VENV/python" - "$ISSUER_DID" > "$WORK/proposal.json" <<'PY'
import json, sys

issuer = sys.argv[1]
if issuer:
    check = (
        f"  if (phdr.cwt.iss !== {json.dumps(issuer)}) "
        '{ return "Issuer is not the enrolled MSRC root"; }'
    )
else:
    check = (
        '  if (typeof phdr.cwt.iss !== "string" || '
        '!phdr.cwt.iss.startsWith("did:x509:")) '
        '{ return "Issuer is not a did:x509"; }'
    )

policy = "\n".join(
    [
        "export function apply(phdr) {",
        '  if (phdr.cwt === undefined) { return "Missing CWT claims"; }',
        check,
        '  if (typeof phdr.cwt.sub !== "string" || phdr.cwt.sub.length === 0) '
        '{ return "Missing CWT subject"; }',
        "  return true;",
        "}",
    ]
)

configuration = {
    # The demo has no accounts, so submission is open. A deployment would
    # authenticate submitters instead.
    "authentication": {"allowUnauthenticated": True},
    "policy": {"acceptedAlgorithms": ["ES256"], "policyScript": policy},
}
json.dump(
    {"actions": [{"name": "set_scitt_configuration",
                  "args": {"configuration": configuration}}]},
    sys.stdout,
)
PY

sign --ccf-gov-msg-type proposal --content "$WORK/proposal.json" \
  > "$WORK/proposal.cose"
RESP=$(curlg -X POST "$CCF_URL/gov/members/proposals:create?$API" \
  -H 'content-type: application/cose' --data-binary @"$WORK/proposal.cose")

read -r PID MID <<<"$(echo "$RESP" | "$VENV/python" -c '
import json, sys
try:
    r = json.load(sys.stdin)
    print(r["proposalId"], r["proposerId"])
except Exception:
    sys.exit(1)
')" || {
  echo "the configuration proposal was refused: $RESP" >&2
  exit 1
}

echo '{"ballot": "export function vote (rawProposal, proposerId) { return true; }"}' \
  > "$WORK/ballot.json"
sign --ccf-gov-msg-type ballot --ccf-gov-msg-proposal_id "$PID" \
  --content "$WORK/ballot.json" > "$WORK/ballot.cose"

STATE=$(curlg -X POST \
  "$CCF_URL/gov/members/proposals/$PID/ballots/$MID:submit?$API" \
  -H 'content-type: application/cose' --data-binary @"$WORK/ballot.cose" \
  | "$VENV/python" -c 'import json,sys; print(json.load(sys.stdin)["proposalState"])')

if [ "$STATE" != "Accepted" ]; then
  echo "the configuration was not accepted: $STATE" >&2
  exit 1
fi
echo "[ledger] registration policy in force" >&2
