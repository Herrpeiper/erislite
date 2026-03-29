# agent/job_worker.py

import time
import requests

from agent.dispatcher import execute_job

BASE_URL = "http://localhost:8000"
AGENT_ID = "erislite-legion"


def fetch_next_job():
    r = requests.get(f"{BASE_URL}/api/jobs/next/{AGENT_ID}", timeout=10)
    r.raise_for_status()
    return r.json().get("job")


def submit_result(job_id, status, result=None, error=None):
    payload = {
        "status": status,
        "result": result,
        "error": error,
    }

    r = requests.post(
        f"{BASE_URL}/api/jobs/{job_id}/result",
        json=payload,
        timeout=15,
    )
    r.raise_for_status()


def worker_loop(interval=5):
    while True:
        try:
            job = fetch_next_job()

            if not job:
                time.sleep(interval)
                continue

            print(f"[AGENT] Executing: {job['module']}")

            try:
                result = execute_job(
                    module=job["module"],
                    action=job["action"],
                    args=job.get("args", {}),
                )

                submit_result(job["job_id"], "complete", result=result)

            except Exception as e:
                submit_result(job["job_id"], "failed", error=str(e))

        except Exception as e:
            print(f"[AGENT ERROR] {e}")

        time.sleep(interval)