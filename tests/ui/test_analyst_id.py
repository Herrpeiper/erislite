"""Tests for analyst ID display handling.

Regression coverage for v1.4.1: migrated profiles store analyst_id as
None, which previously rendered as the string "None" in every header.
"""

import pytest

from erislite.accounts.profile import _migrate
from erislite.ui.utils import get_analyst_id


@pytest.mark.parametrize(
    "profile",
    [
        {"analyst_id": None},
        {},
        {"analyst_id": ""},
        {"analyst_id": "   "},
        {"analyst_id": 0},
        {"analyst_id": "0"},
        {"analyst_id": "None"},
        {"analyst_id": "null"},
        {"analyst_id": "N/A"},
    ],
    ids=[
        "none",
        "missing",
        "empty",
        "whitespace",
        "zero-int",
        "zero-string",
        "none-string",
        "null-string",
        "na-string",
    ],
)
def test_unset_analyst_id_returns_none(profile):
    assert get_analyst_id(profile) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("A-17", "A-17"),
        ("  A-17  ", "A-17"),
        (42, "42"),
    ],
)
def test_set_analyst_id_is_returned_as_text(value, expected):
    assert get_analyst_id({"analyst_id": value}) == expected


def test_migrated_legacy_profile_hides_analyst_id():
    profile, changed = _migrate({"analyst_id": 0})

    assert changed is True
    assert profile["analyst_id"] is None
    assert get_analyst_id(profile) is None