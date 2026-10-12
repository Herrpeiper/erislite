import pytest

from erislite.response.rapid_response.menu import parse_action_selection


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", []),
        ("0", []),
        ("none", []),
        ("all", [0, 1, 2, 3, 4]),
        ("1", [0]),
        ("1,3", [0, 2]),
        ("2-4", [1, 2, 3]),
        ("5, 1-2", [0, 1, 4]),
        ("1,1", [0]),
    ],
)
def test_parse_action_selection_valid(raw, expected):
    assert parse_action_selection(raw, 5) == expected


@pytest.mark.parametrize("raw", ["6", "0-2", "3-1", "a", "1;2", "1-2-3", "-1"])
def test_parse_action_selection_invalid(raw):
    assert parse_action_selection(raw, 5) is None
