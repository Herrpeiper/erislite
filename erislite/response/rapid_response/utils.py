# Project: ErisLITE
# Module: utils.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shared Rapid Response utility functions and runtime paths.

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
LOG_DIR = REPO_ROOT / "data" / "logs" / "rapid_response"


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_cmd(args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_path() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return LOG_DIR / f"rapid_response_{timestamp}.json"
