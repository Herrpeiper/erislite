"""
ErisLITE shared result schema helpers.
"""

from typing import Iterable


VALID_STATUSES = {
    "ok",
    "warning",
    "issue",
    "error",
    "unsupported",
}


def make_result(
    status: str,
    details: Iterable[str] | None = None,
    tags: Iterable[str] | None = None,
) -> dict:
    normalized_status = status.lower()

    if normalized_status not in VALID_STATUSES:
        raise ValueError(f"Invalid result status: {status}")

    return {
        "status": normalized_status,
        "details": list(details or []),
        "tags": list(tags or []),
    }


def validate_result(result: dict) -> bool:
    if not isinstance(result, dict):
        return False

    if result.get("status") not in VALID_STATUSES:
        return False

    if not isinstance(result.get("details"), list):
        return False

    if not isinstance(result.get("tags"), list):
        return False

    return True
