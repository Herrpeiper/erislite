# Project: ErisLite
# Module: agent_ws_loop.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#  This module implements a WebSocket-based agent loop for ErisLITE. It connects
#  to the Basalt controller using WebSockets, registers itself, and listens for
#  incoming job commands. When a command is received, it executes the corresponding
#  handler from the MODULE_REGISTRY and sends the results back to the controller.

from __future__ import annotations

import asyncio
import json
import os
import traceback

import websockets

from core.network_scan import get_network_listeners_data

CONTROLLER = os.getenv("BASALT_CONTROLLER_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = os.getenv("BASALT_AGENT_ID", "erislite-legion")

WS_URL = CONTROLLER.replace("http://", "ws://").replace("https://", "wss://") + "/ws/agent"

MODULE_REGISTRY = {
    "network.listeners": get_network_listeners_data,
}

# Executes a command by looking it up in the MODULE_REGISTRY and calling the handler.
def execute_command(command: str) -> dict:
    handler = MODULE_REGISTRY.get(command)
    if not handler:
        return {
            "module": command,
            "status": "error",
            "errors": [f"Unknown command: {command}"],
            "results": [],
            "summary": {},
        }

    try:
        result = handler()
        if not isinstance(result, dict):
            return {
                "module": command,
                "status": "error",
                "errors": [f"Handler returned non-dict result: {type(result).__name__}"],
                "results": [],
                "summary": {},
            }
        return result
    except Exception as exc:
        return {
            "module": command,
            "status": "error",
            "errors": [
                f"Execution error: {exc}",
                traceback.format_exc(),
            ],
            "results": [],
            "summary": {},
        }

# Main WS loop
async def run_ws_agent() -> None:
    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                await ws.send(json.dumps({
                    "type": "register",
                    "agent_id": AGENT_ID,
                }))

                async for raw in ws:
                    msg = json.loads(raw)
                    msg_type = msg.get("type")

                    if msg_type == "registered":
                        print(f"[Basalt Agent] WS registered as {AGENT_ID}")
                        continue

                    if msg_type == "pong":
                        continue

                    if msg_type != "job":
                        continue

                    job_id = msg.get("job_id")
                    command = msg.get("command")
                    args = msg.get("args") or {}

                    await ws.send(json.dumps({
                        "type": "job_ack",
                        "job_id": job_id,
                        "command": command,
                    }))

                    result = execute_command(command)

                    await ws.send(json.dumps({
                        "type": "job_result",
                        "job_id": job_id,
                        "command": command,
                        "result": result,
                    }))

        except Exception as exc:
            print(f"[Basalt Agent] WS connection error: {exc}")

        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(run_ws_agent())