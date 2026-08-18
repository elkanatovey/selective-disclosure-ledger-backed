# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Configuration validation tests."""

import pytest

from scitt_selective_disclosure.config import Settings


@pytest.mark.parametrize("value", ["maybe", "2", "-1"])
def test_invalid_boolean_setting_is_rejected(value: str) -> None:
    """Unknown boolean spellings must not silently disable verification."""
    with pytest.raises(ValueError, match="SDC_SCITT_INSECURE"):
        Settings.from_env({"SDC_SCITT_INSECURE": value})


@pytest.mark.parametrize("value", ["invalid", "0", "-1"])
def test_invalid_timeout_is_rejected(value: str) -> None:
    """Invalid timeouts must not silently use a different value."""
    with pytest.raises(ValueError, match="SDC_SCITT_TIMEOUT"):
        Settings.from_env({"SDC_SCITT_TIMEOUT": value})


@pytest.mark.parametrize("value", ["1.5", "0", "-1"])
def test_invalid_size_is_rejected(value: str) -> None:
    """Invalid byte limits must not silently use a different value."""
    with pytest.raises(ValueError, match="SDC_MAX_BUNDLE_BYTES"):
        Settings.from_env({"SDC_MAX_BUNDLE_BYTES": value})
