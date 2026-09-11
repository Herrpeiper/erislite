from erislite.response.guidance import (
    DEFAULT_GUIDANCE,
    get_guidance,
    has_guidance,
)
from erislite.sweep.viewer import _guidance_for_result


def test_get_guidance_returns_known_tag_guidance():
    guidance = get_guidance("uid0_clone")

    assert guidance["severity"] == "high"
    assert guidance["investigate"]
    assert has_guidance("uid0_clone") is True


def test_get_guidance_returns_default_for_unknown_tag():
    guidance = get_guidance("unknown_test_tag")

    assert guidance == DEFAULT_GUIDANCE
    assert has_guidance("unknown_test_tag") is False


def test_guidance_for_result_returns_known_tags_only():
    result = {
        "status": "warning",
        "details": ["Multiple indicators detected"],
        "tags": [
            "uid0_clone",
            "unknown_test_tag",
            "firewall_disabled",
        ],
    }

    guidance_items = _guidance_for_result(result)

    assert [tag for tag, _ in guidance_items] == [
        "uid0_clone",
        "firewall_disabled",
    ]