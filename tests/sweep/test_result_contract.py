import pytest


def assert_result_contract(result):
    assert isinstance(result, dict)

    assert "status" in result
    assert isinstance(result["status"], str)

    assert "details" in result
    assert isinstance(result["details"], list)

    assert "tags" in result
    assert isinstance(result["tags"], list)


@pytest.mark.parametrize(
    "result",
    [
        {
            "status": "ok",
            "details": [],
            "tags": [],
        },
        {
            "status": "warning",
            "details": ["Example finding"],
            "tags": ["example_tag"],
        },
        {
            "status": "error",
            "details": ["Unable to inspect resource"],
            "tags": [],
        },
        {
            "status": "unsupported",
            "details": ["Feature unavailable"],
            "tags": [],
        },
    ],
)
def test_valid_result_contract(result):
    assert_result_contract(result)


def test_missing_status_fails_contract():
    result = {
        "details": [],
        "tags": [],
    }

    with pytest.raises(AssertionError):
        assert_result_contract(result)


def test_details_must_be_list():
    result = {
        "status": "ok",
        "details": "No findings",
        "tags": [],
    }

    with pytest.raises(AssertionError):
        assert_result_contract(result)


def test_tags_must_be_list():
    result = {
        "status": "warning",
        "details": [],
        "tags": "suspicious",
    }

    with pytest.raises(AssertionError):
        assert_result_contract(result)
