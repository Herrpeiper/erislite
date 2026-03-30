# Project: ErisLITE
# Module: agent_ws_loop.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: WebSocket agent loop: lower-latency alternative to the HTTP polling loop.

from __future__ import annotations

import asyncio
import json
import os
import traceback

import websockets

from agent.dispatcher import execute_job, MODULE_MAP
from agent.agent_loop import _load_agent_id

CONTROLLER = os.getenv("BASALT_CONTROLLER_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_KEY  = os.getenv("BASALT_AGENT_KEY", "")

WS_URL = (
    CONTROLLER
    .replace("http://", "ws://")
    .replace("https://", "wss://")
    + "/ws/agent"
)


def _ws_url_with_key() -> str:
    if AGENT_KEY:
        return f"{WS_URL}?key={AGENT_KEY}"
    return WS_URL


def execute_command(command: str, args: dict = None) -> dict:
    """Route a WS command through the dispatcher."""
    return execute_job(module=command, action="run", args=args or {})


async def run_ws_agent() -> None:
    agent_id = _load_agent_id()

    while True:
        try:
            async with websockets.connect(_ws_url_with_key()) as ws:
                await ws.send(json.dumps({
                    "type":     "register",
                    "agent_id": agent_id,
                }))

                async for raw in ws:
                    msg      = json.loads(raw)
                    msg_type = msg.get("type")

                    if msg_type == "registered":
                        print(f"[Basalt WS Agent] Registered as {agent_id}")
                        continue

                    if msg_type == "pong":
                        continue

                    if msg_type == "ping":
                        await ws.send(json.dumps({"type": "pong"}))
                        continue

                    if msg_type != "job":
                        continue

                    job_id  = msg.get("job_id")
                    command = msg.get("command")
                    args    = msg.get("args") or {}

                    await ws.send(json.dumps({
                        "type":    "job_ack",
                        "job_id":  job_id,
                        "command": command,
                    }))

                    result = execute_command(command, args)

                    await ws.send(json.dumps({
                        "type":    "job_result",
                        "job_id":  job_id,
                        "command": command,
                        "result":  result,
                    }))

        except Exception as exc:
            print(f"[Basalt WS Agent] Connection error: {exc}")

        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(run_ws_agent())