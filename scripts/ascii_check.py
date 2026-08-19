# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Reject non-ASCII characters in first-party text files."""

from __future__ import annotations

import sys

from notice_check import EXCLUDE_PREFIXES, first_party_files, prefixes_for, repo_root


def main() -> int:
    """Run the repository ASCII check."""
    root = repo_root()
    failures: list[str] = []
    checked = 0

    for relative_path in first_party_files(root):
        if relative_path.startswith(EXCLUDE_PREFIXES):
            continue
        path = root / relative_path
        if not path.is_file() or prefixes_for(relative_path) is None:
            continue
        checked += 1
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(ord(character) > 127 for character in line):
                failures.append(f"{relative_path}:{line_number}")

    print(f"Checked {checked} first-party files for ASCII-only text.")
    for failure in failures:
        print(f"  non-ASCII text: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
