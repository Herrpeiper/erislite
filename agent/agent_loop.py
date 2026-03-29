# Project: ErisLITE
# Module: agent_loop.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-27
# Description:
#  Main loop for the ErisLITE agent. Registers with the Basalt controller,
#  sends periodic heartbeats, polls for queued jobs, executes supported modules,
#  and submits job results back to the controller.

import os
import time
import traceback

import psutil

from agent.basalt_client import BasaltClient
from agent.dispatcher import execute_job

CONTROLLER = os.getenv("BASALT_CONTROLLER_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = os.getenv("BASALT_AGENT_ID", "erislite-legion")
AGENT_KEY = os.getenv("BASALT_AGENT_KEY")

HEARTBEAT_INTERVAL = int(os.getenv("BASALT_HEARTBEAT_INTERVAL", "10"))
TASK_POLL_INTERVAL = int(os.getenv("BASALT_TASK_POLL_INTERVAL", "5"))


def _heartbeat_payload() -> tuple[float, float, int]:
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    uptime = int(time.time() - psutil.boot_time())
    return cpu, mem, uptime


def run():
    client = BasaltClient(CONTROLLER, AGENT_ID, agent_key=AGENT_KEY)

    response = client.register()
    if not response.ok:
        print("Register failed; not starting agent loop.")
        return

    print(f"[Basalt Agent] Registered as {AGENT_ID}")

    last_heartbeat = 0.0
    last_job_poll = 0.0

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
                    job_id = job.get("job_id")
                    module_name = job.get("module")
                    action = job.get("action", "run")
                    args = job.get("args", {})

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