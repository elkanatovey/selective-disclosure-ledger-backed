#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# The whole demo, end to end, against a real transparency service: start the
# ledger, start the three services, run the flow, then stop everything.
#
# Expects the C++ core and the _native module to be built already (scripts/run.sh
# or scripts/core_tests.sh do that). Set SKIP_LEDGER=1 to reuse a service that is
# already running, in which case SCITT_SERVICE_CERT must point at its certificate.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

CCF_PREFIX=${CCF_PREFIX:-/opt/ccf}
PYTHON=${PYTHON:-.venv/bin/python}
RESEARCHER_PORT=${RESEARCHER_PORT:-8090}
MSRC_PORT=${MSRC_PORT:-8091}
VERIFY_PORT=${VERIFY_PORT:-8092}
UNTRUSTING_PORT=${UNTRUSTING_PORT:-8093}
WORKSPACE=${WORKSPACE:-$ROOT/.ledger}
SCITT_URL=${SCITT_URL:-https://127.0.0.1:8000}
SCITT_SERVICE_CERT=${SCITT_SERVICE_CERT:-$WORKSPACE/workspace/sandbox_common/service_cert.pem}

LEDGER_PID=""
APP_PIDS=()

log() { printf '[demo] %s\n' "$*" >&2; }

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for pid in "${APP_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
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

log "starting the three services"
export PYTHONPATH="$ROOT/build"
export SCITT_URL SCITT_SERVICE_CERT
export MSRC_URL="http://127.0.0.1:$MSRC_PORT"

# serve <module> <port> [receipt anchor]
serve() {
  SCITT_SERVICE_IDENTITY="${3:-$SCITT_SERVICE_CERT}" \
    "$PYTHON" -m uvicorn --factory "app.$1:create_app" \
    --host 127.0.0.1 --port "$2" > "/tmp/demo-$1-$2.log" 2>&1 &
  APP_PIDS+=($!)

  local pid=${APP_PIDS[-1]}
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$2/healthz" -o /dev/null && return 0
    if ! kill -0 "$pid" 2>/dev/null; then
      log "the $1 service on $2 exited"
      tail -40 "/tmp/demo-$1-$2.log" >&2
      exit 1
    fi
    sleep 1
  done
  log "the $1 service on $2 did not start"
  tail -40 "/tmp/demo-$1-$2.log" >&2
  exit 1
}

# MSRC first: the researcher asks it to certify a key before anything else.
serve msrc "$MSRC_PORT"
serve researcher "$RESEARCHER_PORT"
serve verify "$VERIFY_PORT"

# A second researcher whose idea of the service identity is wrong. It can reach
# the service, and registration will succeed, but the receipt cannot verify: it
# exists so the flow can prove that such a report is never handed to MSRC.
curl -sf "http://127.0.0.1:$MSRC_PORT/api/root" -o /tmp/demo-wrong-identity.pem
serve researcher "$UNTRUSTING_PORT" /tmp/demo-wrong-identity.pem

log "running the flow"
RESEARCHER_URL="http://127.0.0.1:$RESEARCHER_PORT" \
  MSRC_URL="http://127.0.0.1:$MSRC_PORT" \
  VERIFY_URL="http://127.0.0.1:$VERIFY_PORT" \
  UNTRUSTING_RESEARCHER_URL="http://127.0.0.1:$UNTRUSTING_PORT" \
  "$PYTHON" tests/integration/full_flow.py
