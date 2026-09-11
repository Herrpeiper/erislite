import pytest

from erislite.results import make_result, validate_result


@pytest.mark.parametrize(
    "status",
    [
        "ok",
        "warning",
        "issue",
        "error",
        "unsupported",
    ],
)
def test_make_result_accepts_valid_statuses(status):
    result = make_result(status)

    assert result == {
        "status": status,
        "details": [],
        "tags": [],
    }


def test_make_result_normalizes_status_case():
    result = make_result("WARNING")

    assert result["status"] == "warning"


def test_make_result_preserves_details_and_tags():
    result = make_result(
        "warning",
        details=["Suspicious listener detected"],
        tags=["suspicious_listener"],
    )

    assert result["details"] == ["Suspicious listener detected"]
    assert result["tags"] == ["suspicious_listener"]


def test_make_result_rejects_invalid_status():
    with pytest.raises(ValueError):
        make_result("banana")


def test_validate_result_accepts_valid_result():
    result = {
        "status": "ok",
        "details": [],
        "tags": [],
    }

    assert validate_result(result) is True


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        {},
        {
            "status": "invalid",
            "details": [],
            "tags": [],
        },
        {
            "status": "ok",
            "details": "not-a-list",
            "tags": [],
        },
        {
            "status": "ok",
            "details": [],
            "tags": "not-a-list",
        },
    ],
)
def test_validate_result_rejects_invalid_results(result):
    assert validate_result(result) is False