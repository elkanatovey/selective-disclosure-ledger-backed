#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Build the C++ core and the _native module, then serve the three roles.
#
# They are three processes because they are three parties. The researcher never
# holds MSRC's CA key, and the verifier holds nothing at all: a reader supplies
# every anchor it checks against.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

CCF_PREFIX=${1:-/opt/ccf}
RESEARCHER_PORT=${RESEARCHER_PORT:-8080}
MSRC_PORT=${MSRC_PORT:-8081}
VERIFY_PORT=${VERIFY_PORT:-8082}

if [ ! -d "$CCF_PREFIX" ]; then
  echo "usage: $0 <ccf install prefix>" >&2
  exit 2
fi
if [ -z "${SCITT_URL:-}" ] || [ -z "${SCITT_SERVICE_CERT:-}" ]; then
  echo "set SCITT_URL and SCITT_SERVICE_CERT first; see scripts/ledger.sh" >&2
  exit 2
fi

cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH="$CCF_PREFIX" \
  -DBUILD_PYTHON_MODULE=ON
cmake --build build

PYTHON=${PYTHON:-.venv/bin/python}
export PYTHONPATH="$ROOT/build"
export MSRC_URL="http://127.0.0.1:${MSRC_PORT}"

pids=()
stop() {
  trap - EXIT INT TERM
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
}
trap stop EXIT INT TERM

serve() {
  "$PYTHON" -m uvicorn --factory "app.$1:create_app" \
    --host 127.0.0.1 --port "$2" &
  pids+=($!)
}

# MSRC first: the researcher asks it to certify a key before anything else.
serve msrc "$MSRC_PORT"
serve researcher "$RESEARCHER_PORT"
serve verify "$VERIFY_PORT"

cat <<EOF

  Researcher  http://127.0.0.1:${RESEARCHER_PORT}
  MSRC        http://127.0.0.1:${MSRC_PORT}
  Verify      http://127.0.0.1:${VERIFY_PORT}

EOF

wait
