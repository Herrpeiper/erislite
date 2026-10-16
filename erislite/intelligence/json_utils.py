# Project: ErisLITE
# Module: json_utils.py
# Version: 1.6.0
# License: MIT
# Description: Defensive JSON parsing for intelligence records.

import json
from typing import Any, List, Tuple

MAX_RECORD_BYTES = 64 * 1024


def _reject_duplicate_keys(
    pairs: List[Tuple[str, Any]],
) -> dict:
    """Reject duplicate keys at every JSON object level."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")

        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    """Reject non-standard JSON numeric constants."""
    raise ValueError(f"Invalid JSON numeric constant: {value}")


def load_intelligence_json(payload: str) -> Any:
    """Parse a size-limited JSON intelligence record."""
    if not isinstance(payload, str):
        raise ValueError("Intelligence JSON must be a string")

    try:
        payload_size = len(payload.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("Intelligence JSON contains invalid Unicode") from exc

    if payload_size > MAX_RECORD_BYTES:
        raise ValueError("Intelligence JSON exceeds size limit")

    try:
        return json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid intelligence JSON") from exc
