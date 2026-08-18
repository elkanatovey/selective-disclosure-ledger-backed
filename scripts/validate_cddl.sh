#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

if ! command -v cddl >/dev/null 2>&1; then
  echo "cddl is required; install it with: gem install cddl" >&2
  exit 1
fi

for schema in spec/*.cddl; do
  cddl "$schema" generate 1 >/dev/null
done
