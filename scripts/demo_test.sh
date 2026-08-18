#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# The whole demo, end to end, against a real transparency service: start the
# ledger, start the app, run the flow, then stop everything.
#
# Expects the C++ core and the _native module to be built already (scripts/run.sh
# or scripts/core_tests.sh do that). Set SKIP_LEDGER=1 to reuse a service that is
# already running, in which case SCITT_SERVICE_CERT must point at its certificate.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

CCF_PREFIX=${CCF_PREFIX:-/opt/ccf}
PYTHON=${PYTHON:-.venv/bin/python}
APP_PORT=${APP_PORT:-8090}
WORKSPACE=${WORKSPACE:-$ROOT/.ledger}
SCITT_URL=${SCITT_URL:-https://127.0.0.1:8000}
SCITT_SERVICE_CERT=${SCITT_SERVICE_CERT:-$WORKSPACE/workspace/sandbox_common/service_cert.pem}

LEDGER_PID=""
APP_PID=""

log() { printf '[demo] %s\n' "$*" >&2; }

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
  if [ -n "$LEDGER_PID" ]; then
    # sandbox.sh starts the node as a child, so stop the group.
    kill -- "-$LEDGER_PID" 2>/dev/null || kill "$LEDGER_PID" 2>/dev/null || true
  fi
  pkill -f 'sandbox.sh' 2>/dev/null || true
  pkill -f 'cchost' 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT INT TERM

if [ "${SKIP_LEDGER:-0}" != "1" ]; then
  log "starting the transparency service"
  rm -rf "$WORKSPACE"
  setsid ./scripts/ledger.sh > /tmp/demo-ledger.log 2>&1 &
  LEDGER_PID=$!

  for _ in $(seq 1 900); do
    grep -q 'registration policy in force' /tmp/demo-ledger.log && break
    if ! kill -0 "$LEDGER_PID" 2>/dev/null; then
      log "the transparency service exited"
      tail -40 /tmp/demo-ledger.log >&2
      exit 1
    fi
    sleep 1
  done
  grep -q 'registration policy in force' /tmp/demo-ledger.log || {
    log "the transparency service did not become ready"
    tail -40 /tmp/demo-ledger.log >&2
    exit 1
  }
fi
log "transparency service ready at $SCITT_URL"

log "starting the app"
SCITT_URL="$SCITT_URL" SCITT_SERVICE_CERT="$SCITT_SERVICE_CERT" \
  PYTHONPATH="$ROOT/build" "$PYTHON" -m uvicorn --factory app.main:create_app \
  --host 127.0.0.1 --port "$APP_PORT" > /tmp/demo-app.log 2>&1 &
APP_PID=$!

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$APP_PORT/" -o /dev/null && break
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    log "the app exited"
    tail -40 /tmp/demo-app.log >&2
    exit 1
  fi
  sleep 1
done
curl -sf "http://127.0.0.1:$APP_PORT/" -o /dev/null || {
  log "the app did not start"
  tail -40 /tmp/demo-app.log >&2
  exit 1
}

log "running the flow"
APP_URL="http://127.0.0.1:$APP_PORT" "$PYTHON" tests/integration/full_flow.py
