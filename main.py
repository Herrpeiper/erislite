# main.py

import json, os, sys, socket\

from pathlib import Path

from rich.console import Console

from ui.splash import show_splash
from ui.cli import launch_cli

CONFIG_PATH = Path("config/user_profile.json")
console = Console()

def load_or_create_profile():
    CONFIG_PATH.parent.mkdir(exist_ok=True)

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'r') as file:
            return json.load(file)
    else:
        profile = {
            "hostname": socket.gethostname(),
            "segment": "default",
            "role": "workstation"
        }
        with open(CONFIG_PATH, 'w') as file:
            json.dump(profile, file, indent=4)
        os.chmod(CONFIG_PATH, 0o444)
        console.print("[yellow]Auto-generated user profile and locked file.[/]")
        return profile


def main():
    profile = load_or_create_profile()
    show_splash(profile)
    launch_cli(profile)

DEV_MODE = True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if DEV_MODE:
            raise  # shows traceback
        else:
            console.print("\n[bold red]Interrupted by user. Exiting...[/]")