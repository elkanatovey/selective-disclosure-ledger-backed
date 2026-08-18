# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check every first-party text file for the Microsoft MIT notice."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

NOTICE_LINES = (
    "Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License.",
)
HASH = "\n".join(f"# {line}" for line in NOTICE_LINES)
SLASH = "\n".join(f"// {line}" for line in NOTICE_LINES)
BLOCK = "/*\n" + "\n".join(f" * {line}" for line in NOTICE_LINES) + "\n */"
HTML = "<!--\n" + "\n".join(f"  {line}" for line in NOTICE_LINES) + "\n-->"
SEMICOLON = "\n".join(f"; {line}" for line in NOTICE_LINES)
LICENSE_PREFIX = NOTICE_LINES[0]

PREFIX_BY_SUFFIX = {
    ".c": (SLASH,),
    ".cc": (SLASH,),
    ".cddl": (SEMICOLON,),
    ".cmake": (HASH,),
    ".cpp": (SLASH,),
    ".css": (BLOCK,),
    ".h": (SLASH,),
    ".html": (HTML,),
    ".hpp": (SLASH,),
    ".js": (SLASH,),
    ".md": (HTML,),
    ".py": (HASH,),
    ".sh": (HASH,),
    ".toml": (HASH,),
    ".txt": (HASH,),
    ".yaml": (HASH,),
    ".yml": (HASH,),
}
PREFIX_BY_NAME = {
    ".clang-format": (HASH,),
    ".clangd": (HASH,),
    ".dockerignore": (HASH,),
    ".editorconfig": (HASH,),
    ".gitignore": (HASH,),
    ".gitmodules": (HASH,),
    ".prettierignore": (HASH,),
    ".shellcheckrc": (HASH,),
    "CMakeLists.txt": (HASH,),
    "Dockerfile": (HASH,),
    "LICENSE": (LICENSE_PREFIX,),
}
EXCLUDE_PREFIXES = ("third_party/",)


def repo_root() -> Path:
    """Return the current Git repository root."""
    output = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return Path(output.strip())


def first_party_files(root: Path) -> list[str]:
    """Return tracked and untracked, non-ignored first-party file names."""
    output = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return output.splitlines()


def prefixes_for(relative_path: str) -> tuple[str, ...] | None:
    """Return accepted notice prefixes for a file."""
    name = os.path.basename(relative_path)
    if name in PREFIX_BY_NAME:
        return PREFIX_BY_NAME[name]
    return PREFIX_BY_SUFFIX.get(Path(relative_path).suffix)


def has_notice(path: Path, prefixes: tuple[str, ...]) -> bool:
    """Return whether a text file begins with an accepted notice."""
    text = path.read_text(encoding="utf-8")
    if text.startswith("#!"):
        text = text.partition("\n")[2]
    return text.startswith(prefixes)


def main() -> int:
    """Run the repository notice check."""
    root = repo_root()
    missing: list[str] = []
    unchecked: list[str] = []
    checked = 0

    for relative_path in first_party_files(root):
        if relative_path.startswith(EXCLUDE_PREFIXES):
            continue
        path = root / relative_path
        if not path.is_file():
            continue
        prefixes = prefixes_for(relative_path)
        if prefixes is None:
            unchecked.append(relative_path)
            continue
        checked += 1
        if not has_notice(path, prefixes):
            missing.append(relative_path)

    print(f"Checked {checked} first-party files for the MIT notice.")
    for relative_path in sorted(missing):
        print(f"  missing notice: {relative_path}")
    for relative_path in sorted(unchecked):
        print(f"  unsupported file type: {relative_path}")
    return 1 if missing or unchecked else 0


if __name__ == "__main__":
    sys.exit(main())
