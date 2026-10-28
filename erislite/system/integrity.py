# Project: ErisLITE
# Module: integrity.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-14
# Description: SHA-256 file integrity baseline creation and change detection.

import errno
import hashlib
import json
import os
import re
import stat
from datetime import datetime
from typing import Optional, Tuple

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import (
    APP_NAME,
    APP_VERSION,
    INTEGRITY_BASELINE_FILE,
)
from erislite.results import make_result
from erislite.security.safe_io import write_private_json
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return, prompt_option


def get_baseline_path(profile: str) -> str:
    base_dir = os.path.dirname(INTEGRITY_BASELINE_FILE)

    return os.path.join(
        base_dir,
        f"integrity_baseline_{profile}.json",
    )


def _baseline_unavailable_paths(metadata: dict) -> set:
    """Recover paths explicitly marked unavailable at baseline creation."""
    monitored = metadata.get("monitored", [])
    entries = metadata.get("unavailable", [])

    if not isinstance(monitored, list) or not isinstance(entries, list):
        return set()

    paths = set()

    for path in monitored:
        if not isinstance(path, str):
            continue

        # Existing baselines store entries as:
        # "/path/to/file: permission denied: ..."
        prefix = f"{path}: "

        if any(isinstance(entry, str) and entry.startswith(prefix) for entry in entries):
            paths.add(path)

    return paths


MONITORED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]

SCAN_PROFILES = {
    "critical": MONITORED_FILES,
    "system": [
        "/etc/ssh/",
        "/etc/systemd/",
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/pam.d/",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/etc/crontab",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/usr/bin/",
        "/usr/sbin/",
    ],
    "user": [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.ssh/authorized_keys"),
        os.path.expanduser("~/.profile"),
    ],
}


def _header(title: str, subtitle: str) -> None:
    console.print(
        Panel(
            Text.from_markup(f"[dim]{subtitle}[/]"),
            title=f"[bold cyan]{title}[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def get_sha256(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Hash a regular file without following symlinks or blocking on FIFOs."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = -1

    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)

        if not stat.S_ISREG(before.st_mode):
            return None, "not a regular file"

        digest = hashlib.sha256()

        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)

        after = os.fstat(fd)

        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            return None, "file changed during hashing"

        return digest.hexdigest(), None

    except FileNotFoundError:
        return None, "missing"

    except PermissionError as exc:
        return None, f"permission denied: {exc}"

    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "symbolic link refused"

        return None, f"read failed: {exc}"

    finally:
        if fd != -1:
            os.close(fd)


def _reject_duplicate_json_keys(pairs):
    """Reject duplicate JSON object keys rather than silently overwriting."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value

    return result


def _path_in_profile(path: str, profile: str) -> bool:
    """Check whether a path belongs to a configured integrity profile."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return False

    if os.path.normpath(path) != path:
        return False

    configured = SCAN_PROFILES.get(profile)

    if configured is None:
        return False

    for entry in configured:
        if entry.endswith(os.sep):
            directory = os.path.normpath(entry)

            try:
                if os.path.commonpath((directory, path)) == directory:
                    return True
            except ValueError:
                continue

        elif path == entry:
            return True

    return False


def check_baseline_integrity(profile: str = "critical") -> dict:
    """Validate baseline structure, membership, and SHA-256 records."""
    baseline_path = get_baseline_path(profile)

    if not os.path.exists(baseline_path):
        return make_result(
            "error",
            details=[f"{profile.capitalize()} baseline file missing"],
            tags=["baseline_missing"],
        )

    try:
        with open(baseline_path, "r", encoding="utf-8") as file:
            data = json.load(
                file,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
    except (ValueError, TypeError) as exc:
        return make_result(
            "warning",
            details=[f"Baseline JSON validation failed: {exc}"],
            tags=["baseline_tamper"],
        )
    except (OSError, UnicodeError) as exc:
        return make_result(
            "error",
            details=[f"Failed to read baseline: {exc}"],
            tags=["baseline_check_error"],
        )

    issues = []

    if not isinstance(data, dict):
        return make_result(
            "warning",
            details=["Baseline root must be a JSON object"],
            tags=["baseline_tamper"],
        )

    metadata = data.get("_metadata")
    hashes = data.get("hashes")

    if not isinstance(metadata, dict):
        issues.append("Baseline metadata is malformed")
        metadata = {}

    if not isinstance(hashes, dict):
        issues.append("Baseline hash data is malformed")
        hashes = {}

    if not isinstance(metadata.get("created_at"), str) or not metadata.get("created_at"):
        issues.append("Baseline creation metadata is missing")

    if metadata.get("algorithm") != "SHA-256":
        issues.append("Baseline hashing algorithm is invalid")

    baseline_profile = metadata.get("profile")

    if baseline_profile not in SCAN_PROFILES:
        issues.append(f"Baseline profile is invalid: {baseline_profile}")
    elif baseline_profile != profile:
        issues.append(
            f"Baseline profile '{baseline_profile}' does not match expected profile '{profile}'"
        )

    monitored = metadata.get("monitored")
    expected_absent = metadata.get("expected_absent")
    unavailable = metadata.get("unavailable")

    if not isinstance(monitored, list):
        issues.append("Monitored paths must be a list")
        monitored = []

    if not isinstance(expected_absent, list):
        issues.append("Expected-absent paths must be a list")
        expected_absent = []

    if not isinstance(unavailable, list):
        issues.append("Unavailable records must be a list")
        unavailable = []

    if any(not isinstance(p, str) or not p for p in monitored):
        issues.append("Monitored paths contain invalid entries")

    if any(not isinstance(p, str) or not p for p in expected_absent):
        issues.append("Expected-absent paths contain invalid entries")

    valid_monitored = [p for p in monitored if isinstance(p, str) and p]
    valid_absent = [p for p in expected_absent if isinstance(p, str) and p]

    if len(valid_monitored) != len(set(valid_monitored)):
        issues.append("Duplicate monitored paths detected")

    if len(valid_absent) != len(set(valid_absent)):
        issues.append("Duplicate expected-absent paths detected")

    monitored_set = set(valid_monitored)
    absent_set = set(valid_absent)
    hash_paths = set(hashes)

    for path, digest in hashes.items():
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            issues.append(f"Invalid SHA-256 digest: {path}")

    if not hash_paths.issubset(monitored_set):
        issues.append("Hash entries contain unmonitored paths")

    if not absent_set.issubset(monitored_set):
        issues.append("Expected-absent entries contain unmonitored paths")

    unavailable_paths = set()

    for entry in unavailable:
        if not isinstance(entry, str):
            issues.append("Malformed unavailable record")
            continue

        matches = [path for path in monitored_set if entry.startswith(f"{path}: ")]

        if len(matches) != 1:
            issues.append("Unavailable record has invalid path membership")
            continue

        path = matches[0]

        if path in unavailable_paths:
            issues.append(f"Duplicate unavailable record: {path}")

        unavailable_paths.add(path)

    if hash_paths & absent_set or hash_paths & unavailable_paths or absent_set & unavailable_paths:
        issues.append("Baseline classification sets overlap")

    classified = hash_paths | absent_set | unavailable_paths

    if classified != monitored_set:
        issues.append("Baseline monitored-path coverage is inconsistent")

    if not hash_paths:
        issues.append("Baseline contains no readable file hashes")

    for path in monitored_set:
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            issues.append(f"Invalid monitored path: {path}")
        elif not _path_in_profile(path, profile):
            issues.append(f"Monitored path outside {profile} profile: {path}")

    return make_result(
        "warning" if issues else "ok",
        details=issues,
        tags=["baseline_tamper"] if issues else [],
    )


COPY_SCAN_ROOTS = (
    "/tmp",
    "/dev/shm",
    "/home",
    "/run",
    "/var/tmp",
)

COPY_SCAN_KEYWORDS = (
    "passwd",
    "shadow",
    "sudoers",
    "sshd_config",
    "hosts",
)

# Bound copy scanning to avoid excessive file reads.
MAX_COPY_BYTES = 4 * 1024 * 1024
MAX_COPY_CANDIDATES = 2000


def _hash_regular_file(path: str, max_bytes: int) -> Optional[str]:
    """Hash a regular file without following symlinks or blocking on FIFOs."""

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return None

        digest = hashlib.sha256()

        with os.fdopen(fd, "rb") as file:
            fd = -1

            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)

        return digest.hexdigest()
    except OSError:
        return None
    finally:
        if fd != -1:
            os.close(fd)


def scan_for_copies(
    baseline: dict,
    roots=COPY_SCAN_ROOTS,
    keywords=COPY_SCAN_KEYWORDS,
    max_candidates: int = MAX_COPY_CANDIDATES,
):
    """Find exact copies of monitored files in locations users can write to.

    The walk never follows symlinks and stays on the filesystem of each
    root. Any account that can write to /tmp could otherwise plant a
    symlink loop or a link to / and stall the scan indefinitely.
    """

    wanted = {}

    for base_path, base_hash in baseline.items():
        for keyword in keywords:
            if keyword in base_path.lower() and base_hash:
                wanted.setdefault(keyword, set()).add(base_hash)

    if not wanted:
        return []

    flagged = []
    examined = 0

    for root in roots:
        try:
            root_dev = os.stat(root).st_dev
        except OSError:
            continue

        for current, dirs, files in os.walk(root, followlinks=False):
            # Prune mount points so /home or /run never walks another filesystem.
            kept = []

            for name in dirs:
                try:
                    if os.lstat(os.path.join(current, name)).st_dev == root_dev:
                        kept.append(name)
                except OSError:
                    continue

            dirs[:] = kept

            for name in files:
                lowered = name.lower()
                matched = [keyword for keyword in wanted if keyword in lowered]

                if not matched:
                    continue

                examined += 1

                if examined > max_candidates:
                    flagged.append(
                        (
                            root,
                            f"Copy scan stopped after {max_candidates} candidate files",
                        )
                    )
                    return flagged

                path = os.path.join(current, name)
                copy_hash = _hash_regular_file(path, MAX_COPY_BYTES)

                if copy_hash and any(copy_hash in wanted[keyword] for keyword in matched):
                    flagged.append((path, "Exact copy of monitored file"))

    return flagged


def create_baseline(profile: str = "critical") -> None:
    baseline_path = get_baseline_path(profile)

    clear_screen()
    _header(
        "FILE INTEGRITY",
        f"Create a SHA-256 baseline • Profile: {profile.capitalize()}",
    )

    targets, target_errors = _collect_targets(profile)

    baseline = {}
    unavailable = []
    expected_absent = []
    collection_errors = list(target_errors)

    for path in targets:
        hash_value, hash_error = get_sha256(path)

        if hash_value:
            baseline[path] = hash_value

        elif hash_error == "missing":
            expected_absent.append(path)

        else:
            unavailable.append(f"{path}: {hash_error or 'unavailable'}")

    payload = {
        "_metadata": {
            "created_at": datetime.now().isoformat(),
            "algorithm": "SHA-256",
            "profile": profile,
            "monitored": targets,
            "expected_absent": expected_absent,
            "unavailable": unavailable,
            "collection_errors": collection_errors,
        },
        "hashes": baseline,
    }

    write_private_json(baseline_path, payload)

    console.print(
        Panel.fit(
            f"[green]Baseline created successfully.[/]\n"
            f"[dim]Profile:[/] "
            f"[white]{profile.capitalize()}[/]   "
            f"[dim]Files Recorded:[/] "
            f"[white]{len(baseline)}[/]   "
            f"[dim]Unavailable:[/] "
            f"[white]{len(unavailable)}[/]\n"
            f"[dim]Path:[/] "
            f"[white]{baseline_path}[/]",
            title="[bold green]BASELINE CREATED[/]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    if unavailable:
        console.print()

        table = Table(
            title="[italic cyan]Unavailable Files[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
        )
        table.add_column("Path / Error", style="white")

        for item in unavailable:
            table.add_row(str(item))

        console.print(table)

    pause_return()


def _collect_targets(profile: str) -> Tuple[list[str], list[str]]:
    targets = []
    errors = []

    def _walk_error(exc: OSError) -> None:
        errors.append(str(exc))

    for item in SCAN_PROFILES.get(profile, MONITORED_FILES):
        if os.path.isdir(item):
            for root, _, files in os.walk(
                item,
                onerror=_walk_error,
            ):
                for filename in files:
                    targets.append(os.path.join(root, filename))

        elif item.endswith(os.sep):
            errors.append(f"Expected directory unavailable: {item}")

        else:
            targets.append(item)

    return targets, errors


def summarize_integrity_rows(rows: list) -> dict:
    """Summarize observed integrity states from the current scan."""
    statuses = [status for _, status in rows]

    return {
        "targets": len(rows),
        "verified": sum(status in {"UNCHANGED", "MODIFIED"} for status in statuses),
        "unavailable": statuses.count("UNAVAILABLE"),
        "changes": sum(
            status in {"MODIFIED", "MISSING", "CREATED", "BROKEN LINK"} for status in statuses
        ),
    }


MAX_DISPLAY_ROWS = 60


def select_integrity_display_rows(rows: list) -> tuple:
    """Bound TUI output and identify hidden important results."""
    priority_statuses = {
        "MODIFIED",
        "MISSING",
        "CREATED",
        "BROKEN LINK",
        "UNAVAILABLE",
    }

    important = [row for row in rows if row[1] in priority_statuses]
    routine = [row for row in rows if row[1] not in priority_statuses]

    selected = (important + routine)[:MAX_DISPLAY_ROWS]

    hidden_important = max(0, len(important) - MAX_DISPLAY_ROWS)
    hidden_routine = len(rows) - len(selected) - hidden_important

    return selected, hidden_important, hidden_routine


def scan_integrity(
    profile: str = "critical",
    silent: bool = False,
):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                "Validate files against a known baseline",
            )

            console.print(
                Panel.fit(
                    "[yellow]File Integrity is only supported on Linux.[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return make_result("unsupported")

    baseline_path = get_baseline_path(profile)

    if not os.path.exists(baseline_path):
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                f"Validate files against the baseline • Profile: {profile.capitalize()}",
            )

            console.print(
                Panel.fit(
                    f"[yellow]No {profile.capitalize()} "
                    f"integrity baseline exists.[/]\n"
                    f"[dim]Create a {profile.capitalize()} "
                    f"baseline before running this scan.[/]",
                    title="[bold yellow]BASELINE REQUIRED[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return make_result(
            "error",
            details=[f"{profile.capitalize()} baseline file missing"],
            tags=["baseline_missing"],
        )

    baseline_check = check_baseline_integrity(profile)

    if baseline_check["status"] != "ok":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                f"Validate files against the baseline • Profile: {profile.capitalize()}",
            )

            console.print(
                Panel.fit(
                    "\n".join(f"[yellow]{detail}[/]" for detail in baseline_check["details"]),
                    title="[bold yellow]BASELINE WARNING[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return baseline_check

    try:
        with open(
            baseline_path,
            "r",
            encoding="utf-8",
        ) as file:
            baseline_data = json.load(file)

        baseline = baseline_data.get("hashes", {})
        metadata = baseline_data.get("_metadata", {})
        expected_absent = set(metadata.get("expected_absent", []))
        baseline_unavailable = _baseline_unavailable_paths(metadata)
        baseline_monitored = set(metadata.get("monitored", []))

    except Exception as e:
        return make_result(
            "error",
            details=[f"Unable to load baseline: {e}"],
            tags=["file_integrity_issue"],
        )

    targets, target_errors = _collect_targets(profile)

    current_targets = set(targets)
    previously_hashed = set(baseline)

    rows = []
    issues = []
    scan_errors = [f"Integrity target collection incomplete: {error}" for error in target_errors]

    missing_candidates = previously_hashed - current_targets

    for path in sorted(missing_candidates):
        if target_errors:
            rows.append((path, "UNAVAILABLE"))
            scan_errors.append(f"{path} was not rediscovered, but target collection was incomplete")
            continue

        if not os.path.lexists(path):
            rows.append((path, "MISSING"))
            issues.append(f"{path} is missing")
        else:
            rows.append((path, "UNAVAILABLE"))
            scan_errors.append(f"{path} was not rediscovered during collection")

    # Separate loop — not nested in missing_candidates
    for path in targets:
        if path in expected_absent:
            if not os.path.lexists(path):
                rows.append((path, "ABSENT"))
                continue

            if os.path.islink(path) and not os.path.exists(path):
                rows.append((path, "BROKEN LINK"))
                issues.append(f"{path} appeared after baseline creation as a broken symbolic link")
                continue

            new_hash, hash_error = get_sha256(path)

            if hash_error:
                rows.append((path, "UNAVAILABLE"))
                scan_errors.append(
                    f"{path} appeared after baseline creation "
                    f"but could not be inspected: {hash_error}"
                )
            else:
                rows.append((path, "CREATED"))
                issues.append(f"{path} appeared but was absent when the baseline was created")

            continue

        # Existing baseline comparison begins here
        old_hash = baseline.get(path)

        if old_hash is None:
            if path in baseline_unavailable:
                current_hash, hash_error = get_sha256(path)

                rows.append((path, "UNAVAILABLE"))

                if current_hash is not None:
                    scan_errors.append(
                        f"{path} was unavailable during baseline creation "
                        "but is now readable; recreate the baseline "
                        "to establish a trusted comparison"
                    )
                else:
                    scan_errors.append(
                        f"{path} was unavailable during baseline creation "
                        f"and remains unverified: {hash_error or 'unknown error'}"
                    )

            elif path not in baseline_monitored:
                new_hash, hash_error = get_sha256(path)

                if hash_error:
                    rows.append((path, "UNAVAILABLE"))
                    scan_errors.append(
                        f"{path} was newly discovered but could not be inspected: {hash_error}"
                    )
                else:
                    rows.append((path, "CREATED"))
                    issues.append(f"{path} was discovered after baseline creation")

            else:
                rows.append((path, "UNAVAILABLE"))
                scan_errors.append(
                    f"{path} was monitored at baseline creation "
                    "but has no recorded hash or availability state"
                )

            continue

        new_hash, hash_error = get_sha256(path)

        if hash_error == "missing":
            rows.append((path, "MISSING"))
            issues.append(f"{path} is missing")

        elif hash_error:
            rows.append((path, "UNAVAILABLE"))
            scan_errors.append(f"{path} could not be inspected: {hash_error}")

        elif new_hash != old_hash:
            rows.append((path, "MODIFIED"))
            issues.append(f"{path} was modified")

        else:
            rows.append((path, "UNCHANGED"))

    # Run copy detection before constructing the structured result.
    # Silent mode suppresses presentation, not detection.
    copy_results = scan_for_copies(baseline)

    copies = []
    for path, reason in copy_results:
        if reason.startswith("Copy scan stopped after "):
            scan_errors.append(f"{path}: {reason}")
        else:
            copies.append((path, reason))

    tags = []

    if issues:
        tags.append("file_integrity_issue")

    if copies:
        tags.append("suspicious_file_copy")

    if scan_errors:
        tags.append("integrity_scan_incomplete")

    if issues or copies:
        status = "warning"
    elif scan_errors:
        status = "error"
    else:
        status = "ok"

    copy_details = [f"Suspicious copy detected: {path} ({reason})" for path, reason in copies]

    result = make_result(
        status,
        details=issues
        + copy_details
        + [f"Integrity inspection incomplete: {error}" for error in scan_errors],
        tags=tags,
    )

    if silent:
        return result

    copies = scan_for_copies(baseline)

    clear_screen()
    _header(
        "FILE INTEGRITY SCAN",
        f"Validate files against the baseline • Profile: {profile.capitalize()}",
    )

    coverage = summarize_integrity_rows(rows)

    console.print(
        Panel.fit(
            f"[dim]Profile:[/] [white]{profile.capitalize()}[/]\n"
            f"[dim]Targets:[/] [white]{coverage['targets']}[/]   "
            f"[dim]Verified:[/] [green]{coverage['verified']}[/]   "
            f"[dim]Unavailable:[/] [yellow]{coverage['unavailable']}[/]   "
            f"[dim]Changes:[/] "
            f"[{'yellow' if coverage['changes'] else 'green'}]"
            f"{coverage['changes']}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Integrity Results[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("File", style="white")
    table.add_column("Status", no_wrap=True)

    display_rows, hidden_important, hidden_routine = select_integrity_display_rows(rows)

    for path, row_status in display_rows:
        if row_status == "UNCHANGED":
            rendered = "[green]UNCHANGED[/]"

        elif row_status == "ABSENT":
            rendered = "[green]ABSENT[/]"

        elif row_status == "MODIFIED":
            rendered = "[yellow]MODIFIED[/]"

        elif row_status == "CREATED":
            rendered = "[yellow]CREATED[/]"

        elif row_status == "MISSING":
            rendered = "[red]MISSING[/]"

        elif row_status == "BROKEN LINK":
            rendered = "[yellow]BROKEN LINK[/]"

        else:
            rendered = "[yellow]UNAVAILABLE[/]"

        table.add_row(path, rendered)

    console.print(table)

    omitted = hidden_important + hidden_routine

    if omitted:
        console.print(
            f"[dim]Showing {len(display_rows)} of {len(rows)} "
            f"file results. Hidden: {hidden_important} requiring review, "
            f"{hidden_routine} routine. "
            "Summary counts include all inspected targets.[/]"
        )

    if hidden_important:
        console.print(
            Panel.fit(
                f"[yellow]{hidden_important} important file result(s) "
                "were omitted from the terminal display.[/]\n"
                "[dim]The scan evaluated these files, but their "
                "individual results are not shown. Additional "
                "review is required.[/]",
                title="[bold yellow]HIDDEN FINDINGS[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    console.print()

    copies = scan_for_copies(baseline)

    if copies:
        copy_table = Table(
            title="[italic cyan]Suspicious Copies[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        copy_table.add_column("Path", style="white")
        copy_table.add_column("Reason", style="yellow")

        for path, reason in copies:
            copy_table.add_row(path, reason)

        console.print(copy_table)
        console.print()

    if scan_errors and (issues or copies):
        details = "\n".join(f"[yellow]• {error}[/]" for error in scan_errors[:10])

        if len(scan_errors) > 10:
            details += f"\n[dim]...and {len(scan_errors) - 10} additional inspection error(s).[/]"

        console.print(
            Panel.fit(
                details,
                title="[bold yellow]COLLECTION WARNING[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        console.print()

    if issues or copies:
        console.print(
            Panel.fit(
                f"[yellow]{len(issues)} integrity issue(s), "
                f"{len(copies)} suspicious copy finding(s).[/]\n"
                "[dim]Validate unexpected changes before restoring "
                "or replacing files.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif scan_errors:
        details = "\n".join(f"[yellow]• {error}[/]" for error in scan_errors[:10])

        if len(scan_errors) > 10:
            details += f"\n[dim]...and {len(scan_errors) - 10} additional inspection error(s).[/]"

        console.print(
            Panel.fit(
                "[yellow]No integrity changes were detected, "
                "but the scan was incomplete.[/]\n\n" + details,
                title="[bold yellow]STATUS: INCOMPLETE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No file integrity issues detected.[/]\n"
                "[dim]Monitored files match the stored SHA-256 baseline.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result


def integrity_menu() -> None:
    while True:
        clear_screen()
        _header(
            "FILE INTEGRITY",
            "Create and validate SHA-256 baselines",
        )

        menu = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
            collapse_padding=True,
        )
        menu.add_column(no_wrap=True)
        menu.add_column()
        menu.add_column()

        menu.add_row("[bold cyan]ACTIONS[/]", "", "")
        menu.add_row(
            "[cyan][1][/]",
            "Create Integrity Baseline",
            "[dim]Create a profile-specific baseline[/]",
        )
        menu.add_row(
            "[cyan][2][/]",
            "Run Integrity Scan",
            "[dim]Compare files against the matching baseline[/]",
        )
        menu.add_row("", "", "")
        menu.add_row("[cyan][0][/]", "Back", "")

        console.print(menu)

        choice = prompt_option()

        if choice == "1":
            clear_screen()
            _header(
                "SELECT BASELINE PROFILE",
                "Choose the scope for the integrity baseline",
            )

            profiles = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
            )

            profiles.add_row(
                "[cyan][1][/]",
                "Critical",
                "[dim]passwd, shadow, sudoers, SSH configuration[/]",
            )
            profiles.add_row(
                "[cyan][2][/]",
                "System",
                "[dim]Security configs, persistence paths, and system binaries[/]",
            )
            profiles.add_row(
                "[cyan][3][/]",
                "User",
                "[dim]Shell profile and authorized keys[/]",
            )
            profiles.add_row(
                "[cyan][0][/]",
                "Back",
                "",
            )

            console.print(profiles)

            selected = Prompt.ask(
                "\n[cyan]Select a profile[/]",
                choices=["0", "1", "2", "3"],
                default="1",
            )

            profile_map = {
                "1": "critical",
                "2": "system",
                "3": "user",
            }

            if selected in profile_map:
                create_baseline(profile_map[selected])

        elif choice == "2":
            clear_screen()
            _header(
                "SELECT SCAN PROFILE",
                "Choose the scope for the integrity scan",
            )

            profiles = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
            )

            profiles.add_row(
                "[cyan][1][/]",
                "Critical",
                "[dim]passwd, shadow, sudoers, SSH configuration[/]",
            )
            profiles.add_row(
                "[cyan][2][/]",
                "System",
                "[dim]Security configs, persistence paths, and system binaries[/]",
            )
            profiles.add_row(
                "[cyan][3][/]",
                "User",
                "[dim]Shell profile and authorized keys[/]",
            )
            profiles.add_row(
                "[cyan][0][/]",
                "Back",
                "",
            )

            console.print(profiles)

            selected = Prompt.ask(
                "\n[cyan]Select a profile[/]",
                choices=["0", "1", "2", "3"],
                default="1",
            )

            profile_map = {
                "1": "critical",
                "2": "system",
                "3": "user",
            }

            if selected in profile_map:
                scan_integrity(profile_map[selected])

        elif choice == "0":
            break
