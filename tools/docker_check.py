# Project: ErisLITE
# Module: docker_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Docker security check: privileged containers and exposed sockets.

import subprocess, json
from rich.console import Console
from rich.table import Table
from rich.align import Align
from ui.utils import clear_screen, show_header, pause_return

console = Console()

# Get list of running Docker containers
def get_running_containers():
    try:
        # Get container IDs
        output = subprocess.check_output(["docker", "ps", "-q"], text=True)
        container_ids = output.strip().splitlines()
        return container_ids
    except Exception:
        return []

# Inspect a container for its configuration
def inspect_container(container_id):
    try:
        output = subprocess.check_output(["docker", "inspect", container_id], text=True)
        data = json.loads(output)[0]
        return data
    except Exception:
        return {}

# Main function to run the Docker security scan
def run_docker_scan(silent=False):
    containers = get_running_containers()
    flagged = []
    tags = set()

    for cid in containers:
        data = inspect_container(cid)
        name = data.get("Name", "").lstrip("/")
        config = data.get("HostConfig", {})
        mounts = data.get("Mounts", [])
        privileged = config.get("Privileged", False)
        binds = config.get("Binds", [])
        flags = []

        if privileged:
            flags.append("Privileged")
            tags.add("docker_privileged")

        # Risky mount destinations
        for m in mounts:
            dst = m.get("Destination", "")
            if dst == "/":
                flags.append("Mounts /")
                tags.add("docker_mount_root")
            elif dst == "/etc":
                flags.append("Mounts /etc")
                tags.add("docker_mount_etc")
            elif dst == "/root":
                flags.append("Mounts /root")
                tags.add("docker_mount_root_home")

        # Socket exposure
        for b in binds:
            if "/var/run/docker.sock" in b:
                flags.append("Docker Socket")
                tags.add("docker_sock_exposed")

        if flags:
            flagged.append({"id": cid, "name": name, "flags": flags})

    result = {
        "status": "warning" if flagged else "ok",
        "details": [f"{len(flagged)} container(s) with risky config"] if flagged else [],
        "tags": sorted(list(tags)) if tags else []
    }

    if silent:
        return result

    # Interactive output
    clear_screen()
    show_header("DOCKER SECURITY CHECK")

    if not containers:
        console.print("[green]No running containers detected.[/]")
        pause_return()
        return {
            "status": "ok",
            "details": ["No running containers detected."],
            "tags": []
        }

    table = Table(title="Detected Docker Containers", show_lines=True)
    table.add_column("Name", style="cyan")
    table.add_column("Container ID", style="magenta")
    table.add_column("Flags", style="yellow")

    for c in flagged:
        table.add_row(c["name"], c["id"], ", ".join(c["flags"]))

    if flagged:
        console.print(Align.center(table))
        console.print(f"\n[bold red]⚠️ {len(flagged)} risky container(s) detected.[/]")
    else:
        console.print("[green]✅ All running containers appear safe.[/]")

    pause_return()
    return result
