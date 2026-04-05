# Project: ErisLITE
# Module: agent_loop.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: HTTP polling agent loop: registers, heartbeats, polls jobs, submits results.

from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path
from typing import Tuple

import psutil

from agent.basalt_client import BasaltClient
from agent.dispatcher import execute_job

CONTROLLER = os.getenv("BASALT_CONTROLLER_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_KEY  = os.getenv("BASALT_AGENT_KEY")

HEARTBEAT_INTERVAL = int(os.getenv("BASALT_HEARTBEAT_INTERVAL", "10"))
TASK_POLL_INTERVAL = int(os.getenv("BASALT_TASK_POLL_INTERVAL", "5"))


def _load_agent_id() -> str:
    """
    Resolve the agent ID in priority order:
      1. BASALT_AGENT_ID env var (explicit override)
      2. hostname from user_profile.json (consistent with the rest of the app)
      3. System hostname as a last resort
    """
    env_id = os.getenv("BASALT_AGENT_ID", "").strip()
    if env_id:
        return env_id

    profile_path = Path(__file__).resolve().parent.parent / "data" / "user_profile.json"
    if profile_path.exists():
        try:
            with open(profile_path) as f:
                profile = json.load(f)
            hostname = profile.get("hostname", "").strip()
            if hostname:
                return f"erislite-{hostname.lower().replace(' ', '-')}"
        except Exception:
            pass

    import socket
    return f"erislite-{socket.gethostname()}"


def _load_profile() -> dict:
    """Load user_profile.json for registration metadata."""
    profile_path = Path(__file__).resolve().parent.parent / "data" / "user_profile.json"
    if profile_path.exists():
        try:
            with open(profile_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# FIX #10: was tuple[float, float, int] which requires Python 3.10+
def _heartbeat_payload() -> Tuple[float, float, int]:
    cpu    = psutil.cpu_percent()
    mem    = psutil.virtual_memory().percent
    uptime = int(time.time() - psutil.boot_time())
    return cpu, mem, uptime


def run():
    agent_id = _load_agent_id()
    profile  = _load_profile()

    client = BasaltClient(
        CONTROLLER,
        agent_id,
        agent_key=AGENT_KEY,
        profile=profile,
    )

    response = client.register()
    if not response.ok:
        print(f"[Basalt Agent] Register failed ({response.status_code}); not starting agent loop.")
        return

    print(f"[Basalt Agent] Registered as {agent_id}")

    last_heartbeat = 0.0
    last_job_poll  = 0.0

    while True:
        now = time.time()

        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            try:
                cpu, mem, uptime = _heartbeat_payload()
                client.heartbeat(cpu, mem, uptime)
                last_heartbeat = now
            except Exception as exc:
                print(f"[Basalt Agent] Heartbeat error: {exc}")

        if now - last_job_poll >= TASK_POLL_INTERVAL:
            try:
                job = client.fetch_next_job()

                if job:
                    job_id      = job.get("job_id")
                    module_name = job.get("module")
                    action      = job.get("action", "run")
                    args        = job.get("args", {})

                    print(f"[Basalt Agent] Received job {job_id}: {module_name} ({action})")

                    result = execute_job(module_name, action, args)

                    if result.get("status") == "error":
                        client.submit_job_result(
                            job_id=job_id,
                            status="failed",
                            result=result,
                            error="Module execution returned error status",
                        )
                    else:
                        client.submit_job_result(
                            job_id=job_id,
                            status="complete",
                            result=result,
                        )

                last_job_poll = now

            except Exception as exc:
                print(f"[Basalt Agent] Job poll/execute error: {exc}")
                print(traceback.format_exc())

        time.sleep(1)


if __name__ == "__main__":
    run()