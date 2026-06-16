#!/usr/bin/env python3
"""
main.py — Vortex v2 direct entry point.

Usage (without pip install):
    python main.py <command> [options]

Usage (after pip install -e .):
    vortex <command> [options]
"""

import sys
from pathlib import Path

if getattr(sys, 'frozen', False):
    current_dir = Path(sys.executable).parent
else:
    current_dir = Path(__file__).resolve().parent

if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

if sys.version_info < (3, 8):
    sys.exit(
        f"Vortex requires Python 3.8 or later. "
        f"You are running Python {sys.version}."
    )

from vortex.cli import cli

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        from rich.console import Console
        Console().print("\n  [yellow]⚠[/yellow]  Interrupted.")
        sys.exit(0)
