#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

FIX=0
if [ "${1:-}" = "-f" ]; then
  FIX=1
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [-f]" >&2
  exit 2
fi

PYTHON_PATHS=(src/scitt_selective_disclosure tests/web scripts demo)
WEB_PATHS=(
  src/scitt_selective_disclosure/static
  src/scitt_selective_disclosure/templates
  docs
  README.md
  SECURITY.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  THIRD_PARTY_NOTICES.md
)

mapfile -t CPP_PATHS < <(
  git ls-files --cached --others --exclude-standard core tests/core |
    awk '/\.(c|cc|cpp|h|hpp)$/'
)

if [ "${#CPP_PATHS[@]}" -gt 0 ]; then
  if [ "$FIX" -eq 1 ]; then
    clang-format-18 -i -style=file "${CPP_PATHS[@]}"
  else
    clang-format-18 -n -Werror -style=file "${CPP_PATHS[@]}"
  fi
fi

if [ "$FIX" -eq 1 ]; then
  black "${PYTHON_PATHS[@]}"
  isort "${PYTHON_PATHS[@]}"
  npx --yes prettier@3.6.2 --write "${WEB_PATHS[@]}"
else
  black --check "${PYTHON_PATHS[@]}"
  isort --check "${PYTHON_PATHS[@]}"
  npx --yes prettier@3.6.2 --check "${WEB_PATHS[@]}"
fi

flake8 --select=F,E9 "${PYTHON_PATHS[@]}"
mypy src/scitt_selective_disclosure
python scripts/notice_check.py
python scripts/ascii_check.py

while IFS= read -r script; do
  shellcheck "$script"
done < <(git ls-files --cached --others --exclude-standard '*.sh')

pytest tests/web --cov --cov-report=term-missing
