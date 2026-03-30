# Project: ErisLITE
# Module: job_worker.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Compatibility shim — delegates to agent_loop.run().

# agent/job_worker.py
# NOTE: This file is kept only as a compatibility shim.
#
# job_worker.py was an early prototype that duplicated the logic now in
# agent_loop.py. It had two problems:
#   - AGENT_ID and BASE_URL were fully hardcoded (no env var support)
#   - It skipped heartbeating entirely
#
# agent_loop.py is the canonical implementation. Use that instead:
#
#   python -m agent.agent_loop
#
# If something in the codebase still imports from job_worker, those call
# sites should be updated to import from agent.agent_loop or agent.dispatcher.

from agent.agent_loop import run

if __name__ == "__main__":
    run()