# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Protocol describing how the control plane executes the command line tool."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CliResult:
    """The captured outcome of one command line tool invocation."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CliRunner(Protocol):
    """Executes the selective-disclosure tool and returns captured output.

    Implementations must reject non-zero exit codes and timeouts by raising
    ``CliError`` or ``CliTimeoutError`` so that no caller can mistake a failed
    invocation for a successful one.
    """

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CliResult:
        """Run the tool with ``args`` and return its captured output.

        When ``check`` is false the caller takes responsibility for inspecting
        ``CliResult.returncode``. This is only used for ``verify``, where a
        non-zero exit is a verification outcome rather than a tool failure.
        """
        raise NotImplementedError
