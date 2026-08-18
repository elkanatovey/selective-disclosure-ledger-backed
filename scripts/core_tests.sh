#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
INSTALL_DIR=${INSTALL_DIR:-}
CC=${CC:-clang}
CXX=${CXX:-clang++}

cmake_args=(
  -GNinja
  -S "$ROOT"
  -B "$BUILD_DIR"
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
  -DBUILD_TESTS=ON
)

if [ -n "$INSTALL_DIR" ]; then
  cmake_args+=("-DCMAKE_PREFIX_PATH=$INSTALL_DIR")
fi

cmake "${cmake_args[@]}"
ninja -C "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" --output-on-failure
