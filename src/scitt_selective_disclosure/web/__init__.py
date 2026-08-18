# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Role based web control plane for the selective-disclosure demo."""

from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]
