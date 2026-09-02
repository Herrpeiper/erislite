# Project: ErisLITE
# Module: docker.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Docker security check: privileged containers and risky host exposure.

import json
import shutil
import subprocess

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

DOCKER_SOCKET = "/var/run/docker.sock"

RISKY_MOUNT_DESTINATIONS = {
    "/": "Mounts host root",
    "/etc": "Mounts /etc",
    "/root": "Mounts /root",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect running Docker containers for privileged execution and risky host exposure[/]"
            ),
            title="[bold cyan]DOCKER SECURITY CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def get_running_containers():
    if not _docker_available():
        return [], "Docker CLI is not available"

    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            error = (
                result.stderr.strip()
                or f"docker ps exited with code {result.returncode}"
            )
            return [], error

        return result.stdout.strip().splitlines(), None

    except subprocess.TimeoutExpired:
        return [], "docker ps timed out"

    except Exception as exc:
        return [], str(exc)


def inspect_container(container_id: str):
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return None

        payload = json.loads(result.stdout)

        if not payload:
            return None

        return payload[0]

    except Exception:
        return None


def _analyze_container(container_id: str, data: dict) -> dict:
    name = data.get("Name", "").lstrip("/") or container_id[:12]
    host_config = data.get("HostConfig") or {}
    mounts = data.get("Mounts") or []
    binds = host_config.get("Binds") or []

    flags = []
    tags = set()

    if host_config.get("Privileged", False):
        flags.append("Privileged")
        tags.add("docker_privileged")

    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")

        if destination in RISKY_MOUNT_DESTINATIONS:
            flags.append(
                RISKY_MOUNT_DESTINATIONS[destination]
            )

            if destination == "/":
                tags.add("docker_mount_root")
            elif destination == "/etc":
                tags.add("docker_mount_etc")
            elif destination == "/root":
                tags.add("docker_mount_root_home")

        if (
            source == DOCKER_SOCKET
            or destination == DOCKER_SOCKET
        ):
            flags.append("Docker Socket")
            tags.add("docker_sock_exposed")

    for bind in binds:
        if DOCKER_SOCKET in bind:
            flags.append("Docker Socket")
            tags.add("docker_sock_exposed")

    return {
        "id": container_id,
        "name": name,
        "flags": sorted(set(flags)),
        "tags": tags,
    }


def run_docker_scan(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Docker Security Check is only supported on Linux.[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return {
            "status": "unsupported",
            "details": [],
            "tags": [],
        }

    containers, collection_error = get_running_containers()

    if collection_error:
        result = {
            "status": "unsupported",
            "details": [collection_error],
            "tags": [],
        }

        if silent:
            return result

        clear_screen()
        _header()

        console.print(
            Panel.fit(
                f"[yellow]Docker inspection is unavailable.[/]\n"
                f"[dim]{collection_error}[/]",
                title="[bold yellow]UNAVAILABLE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    inspected = []
    flagged = []
    failed_inspections = 0
    tags = set()

    for container_id in containers:
        data = inspect_container(container_id)

        if data is None:
            failed_inspections += 1
            continue

        analyzed = _analyze_container(
            container_id,
            data,
        )

        inspected.append(analyzed)

        if analyzed["flags"]:
            flagged.append(analyzed)
            tags.update(analyzed["tags"])

    details = []

    if flagged:
        details.append(
            f"{len(flagged)} container(s) with risky configuration"
        )

    if failed_inspections:
        details.append(
            f"{failed_inspections} container inspection(s) failed"
        )

    status = (
        "warning"
        if flagged or failed_inspections
        else "ok"
    )

    result = {
        "status": status,
        "details": details,
        "tags": sorted(tags),
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Running:[/] [white]{len(containers)}[/]   "
            f"[dim]Inspected:[/] [white]{len(inspected)}[/]   "
            f"[dim]Review:[/] "
            f"[{'yellow' if flagged else 'green'}]{len(flagged)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if not containers:
        console.print(
            Panel.fit(
                "[green]No running Docker containers detected.[/]\n"
                "[dim]No active container workloads were available for inspection.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    if inspected:
        table = Table(
            title="[italic cyan]Running Containers[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        table.add_column(
            "Name",
            style="cyan",
            no_wrap=True,
        )
        table.add_column(
            "Container ID",
            style="white",
            no_wrap=True,
        )
        table.add_column(
            "Status",
            no_wrap=True,
        )
        table.add_column(
            "Signals",
            style="dim",
        )

        for container in inspected:
            is_flagged = bool(container["flags"])

            table.add_row(
                container["name"],
                container["id"][:12],
                (
                    "[yellow]REVIEW[/]"
                    if is_flagged
                    else "[green]OK[/]"
                ),
                (
                    ", ".join(container["flags"])
                    if container["flags"]
                    else "-"
                ),
            )

        console.print(table)
        console.print()

    if flagged:
        console.print(
            Panel.fit(
                f"[yellow]{len(flagged)} container(s) require review.[/]\n"
                "[dim]Validate privileged mode, host mounts, and Docker socket exposure.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif failed_inspections:
        console.print(
            Panel.fit(
                f"[yellow]{failed_inspections} container inspection(s) failed.[/]\n"
                "[dim]Results may be incomplete; verify Docker permissions and daemon access.[/]",
                title="[bold yellow]INCOMPLETE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No risky Docker configuration detected.[/]\n"
                "[dim]No privileged containers, sensitive host mounts, or Docker socket exposure were identified.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result