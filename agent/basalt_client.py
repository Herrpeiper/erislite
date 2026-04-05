# Project: ErisLITE
# Module: basalt_client.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: HTTP client for all Basalt Controller communication.

from __future__ import annotations

import os
import platform as py_platform
import socket
from typing import Optional

import requests


class BasaltClient:
    def __init__(self, controller_url: str, agent_id: str,
                 agent_key: Optional[str] = None,
                 auth: Optional[str] = None,
                 profile: Optional[dict] = None):
        self.controller_url = controller_url.rstrip("/")
        self.agent_id       = agent_id
        self.hostname       = socket.gethostname()
        self.agent_key      = agent_key
        self.auth           = auth
        self._profile       = profile or {}
        self.debug          = os.getenv("BASALT_DEBUG", "0") == "1"
        self.log_empty_polls = os.getenv("BASALT_LOG_EMPTY_POLLS", "0") == "1"

    def _log(self, *parts):
        if self.debug:
            print(*parts)

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.agent_key:
            headers["X-Agent-Key"] = self.agent_key
        if self.auth:
            headers["Authorization"] = self.auth
        self._log(
            "DEBUG headers:",
            {k: ("<set>" if k != "Content-Type" else v) for k, v in headers.items()},
        )
        return headers

    def _request(self, method: str, url: str, *,
                 json=None, timeout: int = 10, label: Optional[str] = None):
        response = requests.request(
            method=method,
            url=url,
            json=json,
            headers=self._headers(),
            timeout=timeout,
        )
        if self.debug and label:
            self._log(f"{label}:", response.status_code, response.text[:200])
        return response

    def register(self):
        url = f"{self.controller_url}/api/agents/register"

        segment = self._profile.get("segment", "default")
        role    = self._profile.get("role", "workstation")

        payload = {
            "agent_id":     self.agent_id,
            "hostname":     self.hostname,
            "protocol":     {"version": 1},
            "platform": {
                "os":       py_platform.system().lower(),
                "arch":     py_platform.machine().lower(),
                "version":  1,
                "protocol": {"version": 1},
            },
            "display_name": os.getenv("BASALT_DISPLAY_NAME", self.agent_id),
            "segment":      segment,
            "role":         role,
            "tags":         ["erislite"],
            "capabilities": {
                "integrity":       True,
                "listeners":       True,
                "process":         False,
                "kernel_modules":  True,
                "cron_timers":     True,
                "logs":            True,
                "cve":             True,
            },
        }

        return self._request("POST", url, json=payload, timeout=5, label="REGISTER")

    def heartbeat(self, cpu=None, mem=None, uptime=None):
        url = f"{self.controller_url}/api/agents/heartbeat"
        payload = {
            "agent_id":  self.agent_id,
            "protocol":  {"version": 1},
            "cpu_pct":   cpu,
            "mem_pct":   mem,
            "uptime_s":  uptime,
        }
        return self._request("POST", url, json=payload, timeout=5, label="HEARTBEAT")

    def submit_result(self, module: str, result: dict):
        """Legacy result submission path — kept for older controller flows."""
        url = f"{self.controller_url}/api/results"
        payload = {
            "agent_id": self.agent_id,
            "module":   module,
            "result":   result,
        }
        return self._request("POST", url, json=payload, timeout=10, label="SUBMIT RESULT")

    def fetch_next_job(self):
        """Poll the controller for the next queued job for this agent."""
        url = f"{self.controller_url}/api/jobs/next/{self.agent_id}"
        response = self._request("GET", url, timeout=10, label=None)
        response.raise_for_status()

        data = response.json()
        job  = data.get("job")

        if self.debug and (job is not None or self.log_empty_polls):
            self._log("FETCH NEXT JOB:", response.status_code, response.text[:200])

        return job

    def submit_job_result(self, job_id: str, status: str,
                          result=None, error: Optional[str] = None):
        """Submit completion status for a job. status: 'complete' | 'failed'"""
        url = f"{self.controller_url}/api/jobs/{job_id}/result"
        payload = {"status": status, "result": result, "error": error}
        response = self._request("POST", url, json=payload, timeout=15, label="SUBMIT JOB RESULT")
        response.raise_for_status()
        return response