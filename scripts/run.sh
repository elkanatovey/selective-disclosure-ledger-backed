#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Build the C++ core and the _native module, then serve the researcher page.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

CCF_PREFIX=${1:-/opt/ccf}
PORT=${PORT:-8080}

if [ ! -d "$CCF_PREFIX" ]; then
  echo "usage: $0 <ccf install prefix>" >&2
  exit 2
fi

cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH="$CCF_PREFIX" \
  -DBUILD_PYTHON_MODULE=ON
cmake --build build

PYTHON=${PYTHON:-.venv/bin/python}
PYTHONPATH="$ROOT/build" exec "$PYTHON" -m uvicorn \
  --factory app.main:create_app --host 127.0.0.1 --port "$PORT"
