# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Control-plane and user interface for the selective-disclosure demo.

This package is a thin control plane. It never parses or produces CBOR, COSE,
or X.509 structures: every cryptographic operation is delegated to the C++
command line tool configured by ``SDC_CLI``. Security artifacts are handled as
opaque byte strings.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
