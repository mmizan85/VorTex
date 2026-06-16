"""
vortex/ui.py
────────────
All terminal output for Vortex v2.

Every public function is a pure I/O side-effect — no business logic.
Nothing in this module imports from cli.py (no circular deps).

Design principles
─────────────────
  • All output goes through Rich Console — no plain print().
  • Color scheme:
      Cyan / Blue  — info, headers, vault identity
      Green        — success, unlocked (accessible) state
      Red          — errors, locked state, security alerts
      Yellow       — warnings, auto-lock alerts
      Magenta      — command names, tips, highlights
      Dim/Grey     — secondary info, timestamps, IDs
  • PIN prompts use getpass (no Rich markup in prompt string — avoids
    ANSI escape codes appearing as literal text on some terminals).
"""

from __future__ import annotations

import getpass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .security import format_recovery_key, normalize_recovery_key, validate_pin

if TYPE_CHECKING:
    from .vault_manager import VaultManager

# ─────────────────────────────────────────────────────────────────────────────
# Console instances
# ─────────────────────────────────────────────────────────────────────────────

console = Console()
err_console = Console(stderr=True)


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

_ART = r"""
  __     __ ___  ____  ____   ___  _  _
  \ \   / // _ \|  _ \|_  _| / _ \| \/ |
   \ \ / /| | | | |_) | || || | | |    |
    \ V / | |_| |  _ <  || || |_| | || |
     \_/   \___/|_| \_\ |_|  \___/|_||_|
     v2.0 | Dec 2024 | D:Mohammod Mizan
"""


def print_banner(subtitle: str = "") -> None:
    """Print the full Vortex v2 banner panel."""
    body = f"[bold cyan]{_ART.strip()}[/bold cyan]"
    if subtitle:
        body += f"\n\n[dim]{subtitle}[/dim]"
    else:
        body += (
            "\n\n[dim]Zero-Knowledge File Vault  "
            "·  AES-256-GCM  "
            "·  Git-like Workflow  "
            "·  v2.0[/dim]"
        )
    console.print(
        Panel(body, border_style="cyan", padding=(0, 4)),
        justify="center",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Single-line status printers
# ─────────────────────────────────────────────────────────────────────────────

def success(msg: str) -> None:
    console.print(f"  [bold green]✔[/bold green]  {msg}")


def error(msg: str) -> None:
    console.print(f"  [bold red]✘[/bold red]  {msg}")


def warning(msg: str) -> None:
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def info(msg: str) -> None:
    console.print(f"  [bold blue]ℹ[/bold blue]  {msg}")


def tip(msg: str) -> None:
    console.print(f"  [bold magenta]💡[/bold magenta]  [italic]{msg}[/italic]")


def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold dim]{title}[/bold dim]", style="dim"))


# ─────────────────────────────────────────────────────────────────────────────
# PIN prompts  (BUG FIX: plain strings only — no Rich markup in getpass prompts)
# ─────────────────────────────────────────────────────────────────────────────

def prompt_pin(label: str = "PIN") -> str:
    """
    Prompt for a PIN without terminal echo.

    BUG FIX: v1 used f-strings with Rich markup tokens ([?]) inside
    getpass.getpass().  On some terminals this printed literal escape codes.
    Now uses a plain ASCII prompt string.
    """
    try:
        return getpass.getpass(f"  Enter {label}: ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        raise KeyboardInterrupt


def prompt_new_pin(label: str = "Set PIN (4-8 digits)") -> str:
    """Prompt for a new PIN with confirmation loop."""
    while True:
        pin = prompt_pin(label)
        err_msg = validate_pin(pin)
        if err_msg:
            error(err_msg)
            continue
        confirm_pin = prompt_pin("Confirm PIN")
        if pin != confirm_pin:
            error("PINs do not match. Please try again.")
            continue
        return pin


# ─────────────────────────────────────────────────────────────────────────────
# Recovery key
# ─────────────────────────────────────────────────────────────────────────────

def show_recovery_key(raw_key: str) -> None:
    """Display the one-time recovery key in a high-visibility panel."""
    formatted = format_recovery_key(raw_key)
    console.print(
        Panel(
            "[bold yellow blink]⚠   RECOVERY KEY — DISPLAY ONLY ONCE   ⚠[/bold yellow blink]\n\n"
            f"[bold white on dark_orange3]        {formatted}        [/bold white on dark_orange3]\n\n"
            "[dim]Write this down and store it somewhere safe.\n"
            "It is the [bold]ONLY[/bold] way to reset your PIN without losing data.\n"
            "Vortex will [bold]NEVER[/bold] show it again.[/dim]",
            title="[bold red]! Save This Now[/bold red]",
            border_style="bright_red",
            padding=(1, 8),
        )
    )


def prompt_recovery_key() -> str:
    """Prompt for recovery key (accepts dashes, spaces, or plain)."""
    try:
        raw = Prompt.ask(
            "  [cyan]Recovery Key[/cyan] [dim](XXXX-XXXX-XXXX-XXXX)[/dim]"
        )
        return normalize_recovery_key(raw)
    except (EOFError, KeyboardInterrupt):
        console.print()
        raise KeyboardInterrupt


# ─────────────────────────────────────────────────────────────────────────────
# Confirmation
# ─────────────────────────────────────────────────────────────────────────────

def confirm(message: str, default: bool = False) -> bool:
    """Ask yes/no. Returns False on Ctrl-C without raising."""
    try:
        return Confirm.ask(f"  [yellow]{message}[/yellow]", default=default)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Audit alert  (NEW)
# ─────────────────────────────────────────────────────────────────────────────

def show_audit_alert(failure_count: int, last_ts: Optional[str]) -> None:
    """
    Display a security alert panel when unseen failed attempts are detected.
    Called after every successful login where failures exist.
    """
    last_str = ""
    if last_ts:
        try:
            dt = datetime.fromisoformat(last_ts)
            last_str = f"\n  [dim]Last attempt: {dt.strftime('%Y-%m-%d %H:%M UTC')}[/dim]"
        except ValueError:
            pass

    plural = "s" if failure_count != 1 else ""
    console.print(
        Panel(
            f"[bold red]⚠  SECURITY ALERT[/bold red]\n\n"
            f"  [yellow]{failure_count}[/yellow] failed login attempt{plural} "
            f"detected since your last session.{last_str}\n\n"
            "  If you did not make these attempts, someone may be\n"
            "  trying to access your vault.  Consider changing your PIN:\n"
            "  [bold cyan]vortex reset[/bold cyan]",
            border_style="red",
            padding=(0, 2),
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Auto-lock status  (NEW)
# ─────────────────────────────────────────────────────────────────────────────

def show_auto_lock_warning(elapsed_seconds: int, timeout_minutes: int) -> None:
    """Show a prominent auto-lock timeout warning banner."""
    elapsed_min = elapsed_seconds // 60
    elapsed_sec = elapsed_seconds % 60
    console.print(
        Panel(
            f"[bold yellow]⏰  AUTO-LOCK TIMEOUT EXCEEDED[/bold yellow]\n\n"
            f"  Your files have been unlocked for "
            f"[yellow]{elapsed_min}m {elapsed_sec}s[/yellow] "
            f"(limit: {timeout_minutes}m).\n\n"
            "  Run  [bold cyan]vortex lock[/bold cyan]  to immediately re-secure your files.",
            border_style="yellow",
            padding=(0, 2),
        )
    )


def show_auto_lock_reminder(remaining_seconds: int) -> None:
    """Show a subtle reminder that auto-lock is approaching."""
    mins = remaining_seconds // 60
    secs = remaining_seconds % 60
    time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    warning(
        f"Vault is unlocked. Auto-lock reminder in [yellow]{time_str}[/yellow]. "
        "Run [cyan]vortex lock[/cyan] to secure files."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Post-command tips  (NEW)
# ─────────────────────────────────────────────────────────────────────────────

_TIPS: Dict[str, str] = {
    "init": (
        "Run [cyan]vortex lock[/cyan] to encrypt your tracked files, or "
        "[cyan]vortex add -s[/cyan] to select more files first."
    ),
    "lock": (
        "Run [cyan]vortex unlock[/cyan] to decrypt files when needed. "
        "Use [cyan]vortex status[/cyan] to view the vault state."
    ),
    "unlock": (
        "Your files are now accessible. Run [cyan]vortex lock[/cyan] "
        "when finished to re-secure them."
    ),
    "add": (
        "Paths staged for locking. Run [cyan]vortex lock[/cyan] to encrypt them now."
    ),
    "untrack": (
        "The file is now a normal file and will not be locked again. "
        "Use [cyan]vortex add[/cyan] to re-track it if needed."
    ),
    "reset": (
        "Your PIN has been updated. Your locked files are unaffected."
    ),
    "purge": (
        "Vault deleted. Run [cyan]vortex init[/cyan] in any directory to start fresh."
    ),
}


def show_post_tip(command: str) -> None:
    """Print a helpful tip after a command completes."""
    msg = _TIPS.get(command)
    if msg:
        console.print()
        tip(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Status view  (UPGRADED)
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _fmt_ts(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso[:16].replace("T", " ")


def _auto_lock_badge(info: Dict[str, Any]) -> str:
    """Return a Rich-formatted auto-lock status string for the summary panel."""
    if not info.get("is_unlocked"):
        return "[green]🔒 Locked[/green]"
    elapsed = info.get("elapsed_seconds", 0)
    elapsed_str = f"{elapsed // 60}m {elapsed % 60}s"
    timeout = info.get("timeout_minutes", 15)
    if info.get("is_overdue"):
        return (
            f"[bold red]⚠ OVERDUE — unlocked for {elapsed_str} "
            f"(limit: {timeout}m)[/bold red]"
        )
    remaining = info.get("remaining_seconds", 0)
    rem_str = f"{remaining // 60}m {remaining % 60}s"
    return (
        f"[yellow]🔓 Unlocked {elapsed_str} ago[/yellow]  "
        f"· Auto-lock in [cyan]{rem_str}[/cyan]"
    )


def print_status(vault: "VaultManager") -> None:
    """
    Render a full vault status report.

    Shows:
      1. Summary panel (version, paths, auto-lock state, security alert count)
      2. Full tracked-file table with obfuscated vault IDs and color-coded state
         (NEW in v2 — v1 only showed basic tracking info)
    """
    if not vault.is_initialized:
        console.print(
            Panel(
                "[yellow]No vault found in this directory.[/yellow]\n\n"
                "Run [bold cyan]vortex init[/bold cyan] to create one.",
                title="[bold]⬡ Vortex[/bold]",
                border_style="yellow",
            )
        )
        return

    config = vault.get_config()
    tracked: List[str] = config.get("tracked_paths", [])
    locked_files: Dict = config.get("files", {})
    auto_lock_info = vault.get_auto_lock_info()

    # Unseen failure count (show without clearing — no PIN required for status)
    audit = vault.get_audit_log()
    failure_count, _ = audit.get_unseen_failures()

    # ── 1. Summary panel ──────────────────────────────────────────────────
    summary = Table(
        box=None,
        show_header=False,
        padding=(0, 1),
        show_edge=False,
    )
    summary.add_column(style="dim cyan", no_wrap=True, min_width=22)
    summary.add_column(style="white", min_width=40)

    summary.add_row("Vault Version", config.get("version", "—"))
    summary.add_row("Created", _fmt_ts(config.get("created_at", "")))
    summary.add_row("Base Directory", str(vault.base_path))
    summary.add_row(
        "Tracked Paths",
        str(len(tracked)) if tracked else "[dim]none[/dim]",
    )

    lock_count = len(locked_files)
    locked_str = (
        f"[bold red]{lock_count}[/bold red]"
        if lock_count > 0
        else "[bold green]0[/bold green]"
    )
    summary.add_row("Locked Files", locked_str)
    summary.add_row(
        "Auto-Lock",
        _auto_lock_badge(auto_lock_info),
    )

    if failure_count > 0:
        summary.add_row(
            "[bold red]Security[/bold red]",
            f"[bold red]⚠ {failure_count} failed login attempt(s) detected[/bold red] "
            "[dim](log in to view details)[/dim]",
        )

    console.print()
    console.print(
        Panel(
            summary,
            title="[bold cyan]⬡ Vortex  ·  Zero-Knowledge File Vault[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    # ── 2. Tracked file table (UPGRADED — now shows obfuscated names) ─────
    if not tracked and not locked_files:
        console.print()
        info(
            "No tracked paths. Use [cyan]vortex add[/cyan] or "
            "[cyan]vortex init --selective[/cyan] to get started."
        )
        return

    # Build a map: original_path → (vault_filename, file_info)
    path_to_vault: Dict[str, Tuple[str, Dict]] = {}
    for vf, fi in locked_files.items():
        path_to_vault[fi["original_path"]] = (vf, fi)

    # Collect all paths for the table (tracked + any locked-only paths)
    all_paths: List[str] = list(tracked)
    for fi in locked_files.values():
        if fi["original_path"] not in all_paths:
            all_paths.append(fi["original_path"])

    t = Table(
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="dim",
        show_lines=True,
        padding=(0, 1),
        title="[bold]Tracked File Status[/bold]",
        title_style="bold cyan",
    )
    t.add_column("#", style="dim", width=4, justify="right")
    t.add_column("Original Path", style="cyan", min_width=25, no_wrap=False)
    t.add_column("Vault Filename (Obfuscated)", style="dim", min_width=28, no_wrap=True)
    t.add_column("Size", style="yellow", width=9, justify="right")
    t.add_column("Locked At", style="dim", width=17, justify="center")
    t.add_column("State", width=14, justify="center")

    for i, path in enumerate(all_paths, 1):
        if path in path_to_vault:
            vf, fi = path_to_vault[path]
            # Truncate long vault IDs for display
            vault_display = vf[:22] + "…" if len(vf) > 22 else vf
            size_str = _fmt_size(fi.get("size", 0))
            locked_at = _fmt_ts(fi.get("locked_at", ""))
            state = Text("● LOCKED", style="bold red")
        else:
            vault_display = "[dim]—[/dim]"
            size_str = "[dim]—[/dim]"
            locked_at = "[dim]—[/dim]"
            state = Text("● UNLOCKED", style="bold green")

        t.add_row(
            str(i),
            path,
            vault_display,
            size_str,
            locked_at,
            state,
        )

    console.print()
    console.print(t)

    # ── 3. Quick-action footer ────────────────────────────────────────────
    console.print()
    unlocked_count = sum(1 for p in all_paths if p not in path_to_vault)
    if lock_count > 0 and unlocked_count > 0:
        tip(
            f"{lock_count} locked · {unlocked_count} unlocked  "
            "·  [cyan]vortex lock[/cyan] to encrypt all  "
            "·  [cyan]vortex unlock[/cyan] to decrypt all"
        )
    elif lock_count > 0:
        tip(
            "All tracked files are locked.  "
            "Run [cyan]vortex unlock[/cyan] to access them."
        )
    elif unlocked_count > 0:
        tip(
            "Files are accessible.  "
            "Run [cyan]vortex lock[/cyan] to re-secure them."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Progress bar factory
# ─────────────────────────────────────────────────────────────────────────────

def make_progress(description: str = "Processing…") -> Progress:
    """Create a Rich Progress pre-configured for Vortex file operations."""
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn(
            "[progress.description]{task.description}",
        ),
        BarColumn(bar_width=24, complete_style="bold green", pulse_style="yellow"),
        MofNCompleteColumn(),
        TextColumn("·"),
        TaskProgressColumn(),
        TextColumn("·"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def make_spinner(description: str) -> Progress:
    """Lightweight spinner for single-step operations."""
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
