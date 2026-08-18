# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Subprocess based implementation of the command line tool runner."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

from ..config import Settings
from ..errors import CliError, CliTimeoutError, truncate_detail
from .client import CliClient
from .protocol import CliResult

STDERR_LIMIT = 2000


class SubprocessCliRunner:
    """Runs the configured executable without a shell and checks its result."""

    def __init__(self, executable: Path, *, default_timeout: float = 60.0) -> None:
        self.executable = executable
        self.default_timeout = default_timeout

    @property
    def available(self) -> bool:
        """Return whether the configured executable looks runnable."""
        return self.executable.is_file()

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CliResult:
        """Run the tool, raising on a missing binary, timeout or failure."""
        command = [str(self.executable), *args]
        effective_timeout = timeout if timeout is not None else self.default_timeout
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argument vector
                command,
                cwd=str(cwd) if cwd is not None else None,
                capture_output=True,
                timeout=effective_timeout,
                check=False,
                text=True,
                errors="replace",
            )
        except FileNotFoundError as error:
            raise CliError(
                "The selective-disclosure tool is not available.",
                detail=(
                    f"Executable '{self.executable}' was not found. Build the C++ "
                    "tool or set SDC_CLI to its path."
                ),
            ) from error
        except PermissionError as error:
            raise CliError(
                "The selective-disclosure tool is not executable.",
                detail=f"Executable '{self.executable}' cannot be run.",
            ) from error
        except subprocess.TimeoutExpired as error:
            raise CliTimeoutError(
                "The selective-disclosure tool timed out.",
                detail=(
                    f"Command '{args[0] if args else ''}' exceeded "
                    f"{effective_timeout:g} seconds."
                ),
            ) from error

        result = CliResult(
            args=tuple(str(item) for item in args),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if result.returncode != 0 and check:
            raise CliError(
                "The selective-disclosure tool reported an error.",
                detail=(
                    f"Command '{' '.join(result.args[:2])}' exited with "
                    f"{result.returncode}: "
                    f"{truncate_detail(result.stderr, STDERR_LIMIT) or 'no output'}"
                ),
                returncode=result.returncode,
            )
        return result


def build_cli_client(settings: Settings) -> CliClient:
    """Return a CLI client bound to the configured executable."""
    runner = SubprocessCliRunner(
        settings.cli_path, default_timeout=settings.cli_timeout
    )
    return CliClient(runner, timeout=settings.cli_timeout)
