# Project: ErisLITE
# Module: security_log.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module handles logging of security audit results. It creates a log file for each audit, storing details 
#   such as the hostname, analyst ID, timestamp, and the findings of the audit. The logs are saved in a structured 
#   format for easy review by analysts.

import os

from datetime import datetime

LOG_DIR = "data/logs"

# Writes the audit results to a log file in the data/logs directory. The filename includes the hostname and timestamp for easy identification.
def write_audit_log(profile: dict, results: list[str]) -> str:
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = profile.get("hostname", "unknown-host")
    analyst = profile.get("analyst_id", "N/A")

    filename = f"{LOG_DIR}/security_audit_{hostname}_{timestamp}.txt"

    with open(filename, "w") as log:
        log.write(f"ErisLite Security Audit Log\n")
        log.write(f"Timestamp: {timestamp}\n")
        log.write(f"Hostname: {hostname}\n")
        log.write(f"Analyst ID: {analyst}\n")
        log.write(f"{'-'*40}\n\n")

        if results:
            log.write("Audit Findings:\n")
            for line in results:
                log.write(f" - {line}\n")
        else:
            log.write("No issues found.\n")

    return filename  # Can be shown to analyst in console
