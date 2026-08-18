# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Run the web control plane with uvicorn."""

from __future__ import annotations

import os

import uvicorn

from .app import create_app


def main() -> None:
    """Serve the web application on the configured host and port."""
    host = os.environ.get("SDC_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("SDC_WEB_PORT", "8080"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
