# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Service container shared by the web and mock MSRC applications."""

from __future__ import annotations

from dataclasses import dataclass

from .cli import CliClient, build_cli_client
from .config import Settings
from .msrc_client import MsrcClient
from .scitt import ScittClient
from .scitt_verify import OfficialVerifier, ScittVerifier
from .storage import Store


@dataclass(frozen=True)
class Services:
    """Collaborators resolved once per application instance."""

    settings: Settings
    cli: CliClient
    store: Store
    scitt: ScittClient
    msrc: MsrcClient
    official_verifier: OfficialVerifier


def build_services(
    settings: Settings | None = None,
    *,
    cli: CliClient | None = None,
    store: Store | None = None,
    scitt: ScittClient | None = None,
    msrc: MsrcClient | None = None,
    official_verifier: OfficialVerifier | None = None,
) -> Services:
    """Build the service container, allowing tests to inject fakes."""
    resolved = settings if settings is not None else Settings.from_env()
    return Services(
        settings=resolved,
        cli=cli if cli is not None else build_cli_client(resolved),
        store=(
            store
            if store is not None
            else Store(resolved.data_dir, max_records=resolved.max_records)
        ),
        scitt=scitt if scitt is not None else ScittClient.from_settings(resolved),
        msrc=msrc if msrc is not None else MsrcClient.from_settings(resolved),
        official_verifier=(
            official_verifier
            if official_verifier is not None
            else ScittVerifier.from_settings(resolved)
        ),
    )
