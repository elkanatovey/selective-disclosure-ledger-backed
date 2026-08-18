#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Start a real scitt-ccf-ledger transparency service for the demo, and put a
# registration policy in place through CCF governance.
#
# The service is the upstream implementation, built from the pinned submodule.
# Nothing here fakes a ledger: statements really are appended to a log, and the
# receipts it returns really do carry Merkle inclusion proofs.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
LEDGER=${LEDGER:-$ROOT/third_party/scitt-ccf-ledger}
LEDGER_URL=${LEDGER_URL:-https://github.com/microsoft/scitt-ccf-ledger}
# Pinned: the receipt format this demo verifies is the one this commit emits.
LEDGER_SHA=${LEDGER_SHA:-5d471384ef7808cb0208ac3d141b4910b83cb48f}
CCF_PREFIX=${CCF_PREFIX:-/opt/ccf}
WORKSPACE=${WORKSPACE:-$ROOT/.ledger}
# Pin registration to one issuer by exporting the did:x509 mock MSRC prints on
# its first enrolment. Left unset, any issuer naming a subject is accepted,
# which is enough to demonstrate disclosure but is not a policy to copy.
ISSUER_DID=${ISSUER_DID:-}

COMMON="$WORKSPACE/workspace/sandbox_common"

log() { printf '[ledger] %s\n' "$*" >&2; }

[ -d "$CCF_PREFIX" ] || { log "no CCF install at $CCF_PREFIX"; exit 2; }

# --- fetch the application ---------------------------------------------------

# The checkout may be a worktree, so ask git rather than looking for a .git dir.
# It may also already hold a restored build tree, which rules out git clone.
if ! git -C "$LEDGER" rev-parse --git-dir >/dev/null 2>&1; then
  log "fetching the transparency service at $LEDGER_SHA"
  mkdir -p "$LEDGER"
  git -C "$LEDGER" init --quiet
  git -C "$LEDGER" remote add origin "$LEDGER_URL"
fi
if [ "$(git -C "$LEDGER" rev-parse HEAD 2>/dev/null || echo none)" != "$LEDGER_SHA" ]; then
  log "checking out $LEDGER_SHA"
  git -C "$LEDGER" fetch --quiet --depth 1 origin "$LEDGER_SHA" ||
    git -C "$LEDGER" fetch --quiet origin
  git -C "$LEDGER" checkout --quiet --force "$LEDGER_SHA"
fi

# --- build the application ---------------------------------------------------

if [ ! -x "$LEDGER/build-native/cchost" ]; then
  log "building the transparency service (this takes a while)"
  cmake -S "$LEDGER/app" -B "$LEDGER/build-native" -GNinja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF
  cmake --build "$LEDGER/build-native"
fi

# --- constitution ------------------------------------------------------------

# CCF's sandbox passes four fixed constitution filenames, so the application's
# own governance actions have to ride along inside actions.js or
# set_scitt_configuration will not exist.
CONSTITUTION="$WORKSPACE/constitution"
mkdir -p "$CONSTITUTION"
cp "$LEDGER/app/constitution/validate.js" "$CONSTITUTION/"
cp "$LEDGER/app/constitution/resolve.js" "$CONSTITUTION/"
cp "$LEDGER/app/constitution/apply.js" "$CONSTITUTION/"
cat "$LEDGER/app/constitution/actions.js" "$LEDGER/app/constitution/scitt.js" \
  > "$CONSTITUTION/actions.js"

# --- run ---------------------------------------------------------------------

rm -rf "$COMMON"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

log "starting the transparency service on https://127.0.0.1:8000"
"$CCF_PREFIX/bin/sandbox.sh" \
  --package "$LEDGER/build-native/cchost" \
  --constitution-dir "$CONSTITUTION" \
  --initial-member-count 1 &
SANDBOX=$!
trap 'kill $SANDBOX 2>/dev/null || true' EXIT INT TERM

# The sandbox writes its keys and certificates before the node is listening, so
# readiness means an answered request, not a file on disk.
for _ in $(seq 1 180); do
  if [ -f "$COMMON/service_cert.pem" ] && [ -f "$COMMON/member0_privk.pem" ] &&
    curl -sf --cacert "$COMMON/service_cert.pem" \
      "https://127.0.0.1:8000/app/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -sf --cacert "$COMMON/service_cert.pem" \
  "https://127.0.0.1:8000/app/version" >/dev/null 2>&1 || {
  log "the service did not start"
  exit 1
}

# --- configuration -----------------------------------------------------------

if [ -n "$ISSUER_DID" ]; then
  log "pinning registration to $ISSUER_DID"
else
  log "accepting any did:x509 issuer that names a subject"
fi
"$ROOT/scripts/ledger_configure.sh" "$COMMON" "$ISSUER_DID"

cat >&2 <<EOF

[ledger] ready. In another shell:

  export SCITT_URL=https://127.0.0.1:8000
  export SCITT_SERVICE_CERT=$COMMON/service_cert.pem
  scripts/run.sh $CCF_PREFIX

EOF

wait $SANDBOX
