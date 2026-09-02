# Project: ErisLITE
# Module: security_log.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Security audit log writer for structured ErisLITE findings.

from __future__ import annotations  # FIX #11: enables List[str] shorthand on Python 3.9

import os
from datetime import datetime
from typing import List

from erislite.config.settings import SECURITY_LOG_DIR

LOG_DIR = SECURITY_LOG_DIR

def write_audit_log(profile: dict, results: List[str]) -> str:
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = profile.get("hostname", "unknown-host")
    analyst = profile.get("analyst_id", "N/A")

    filename = f"{LOG_DIR}/security_audit_{hostname}_{timestamp}.txt"

    with open(filename, "w") as log:
        log.write(f"Timestamp: {timestamp}\n")
        log.write(f"Hostname: {hostname}\n")
        log.write(f"Analyst ID: {analyst}\n")
        log.write(f"{'-' * 40}\n\n")

        if results:
            log.write("Audit Findings:\n")
            for line in results:
                log.write(f" - {line}\n")
        else:
            log.write("No issues found.\n")

    return filename
