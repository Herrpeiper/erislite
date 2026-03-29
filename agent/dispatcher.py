from typing import Any, Dict
import traceback

from core.network_scan import get_network_listeners_data


def run_network_listeners(args: Dict[str, Any]) -> Dict[str, Any]:
    result = get_network_listeners_data()

    if not isinstance(result, dict):
        raise ValueError(
            f"network.listeners returned non-dict result: {type(result).__name__}"
        )

    result.setdefault("module", "network.listeners")
    result.setdefault("status", "success")
    result.setdefault("errors", [])
    result.setdefault("results", [])
    result.setdefault("summary", {})

    return result


def run_security_audit(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "module": "security.audit",
        "status": "success",
        "errors": [],
        "results": [],
        "summary": {
            "status": "warning",
            "issues": 3,
        },
    }


MODULE_MAP = {
    "network.listeners": run_network_listeners,
    "security.audit": run_security_audit,
}


def execute_job(module: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if action != "run":
        raise ValueError(f"Unsupported action: {action}")

    handler = MODULE_MAP.get(module)
    if not handler:
        return {
            "module": module,
            "status": "error",
            "errors": [f"Unknown module: {module}"],
            "results": [],
            "summary": {},
        }

    try:
        return handler(args or {})
    except Exception as exc:
        return {
            "module": module,
            "status": "error",
            "errors": [
                f"Exception while executing module '{module}': {exc}",
                traceback.format_exc(),
            ],
            "results": [],
            "summary": {},
        }