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
LEDGER="$ROOT/third_party/scitt-ccf-ledger"
CCF_PREFIX=${CCF_PREFIX:-/opt/ccf}
WORKSPACE=${WORKSPACE:-$ROOT/.ledger}
# Pin registration to one issuer by exporting the did:x509 mock MSRC prints on
# its first enrolment. Left unset, any issuer naming a subject is accepted,
# which is enough to demonstrate disclosure but is not a policy to copy.
ISSUER_DID=${ISSUER_DID:-}

COMMON="$WORKSPACE/workspace/sandbox_common"

log() { printf '[ledger] %s\n' "$*" >&2; }

[ -d "$CCF_PREFIX" ] || { log "no CCF install at $CCF_PREFIX"; exit 2; }
[ -f "$LEDGER/CMakeLists.txt" ] || {
  log "submodule missing: git submodule update --init third_party/scitt-ccf-ledger"
  exit 2
}

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

for _ in $(seq 1 120); do
  [ -f "$COMMON/service_cert.pem" ] && [ -f "$COMMON/member0_privk.pem" ] && break
  sleep 1
done
[ -f "$COMMON/service_cert.pem" ] || { log "the service did not start"; exit 1; }

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
