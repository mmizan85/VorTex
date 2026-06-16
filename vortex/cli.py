"""
vortex/cli.py
─────────────
Click command group and all sub-commands for Vortex v2.

Commands
────────
  vortex init   [--selective/-s]          Initialise vault
  vortex add    [PATHS...] [--selective]  Add paths to tracking (NEW)
  vortex lock   [TARGET]                  Encrypt tracked/specified files
  vortex unlock                           Decrypt all locked files
  vortex untrack <TARGET>                 Decrypt + permanently untrack (NEW)
  vortex status                           Show full vault status
  vortex reset                            Change PIN via recovery key
  vortex purge                            Decrypt all + delete vault

Bug fixes vs v1
───────────────
  1. ``vortex lock <target>`` — tracked path now added ONLY after at least
     one file is successfully encrypted (was added before in v1, causing
     phantom tracking entries on total failure).
  2. ``_rel`` is no longer imported as a private function from file_ops;
     ``rel_path()`` is the public API now.
  3. Auto-lock state is tracked and displayed on every command.
  4. Audit alerts shown after successful authentication.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Tuple

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


from .exceptions import (
    AccountLockedError,
    CorruptedVaultError,
    InvalidRecoveryKeyError,
    PathNotTrackedError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WrongPINError,
)
from .file_ops import (
    count_lockable_files,
    find_locked_by_path,
    lock_paths,
    rel_path,          # BUG FIX: was private _rel imported across boundaries
    unlock_all_files,
    unlock_specific_paths,
)
from .security import clear_bytes
from .vault_manager import VaultManager
from . import ui

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _vault() -> VaultManager:
    """VaultManager bound to the current working directory."""
    return VaultManager(Path.cwd())


def _authenticate(vault: VaultManager, pin: str) -> Optional[bytes]:
    """
    Verify PIN. Returns DEK on success, None on failure (error already printed).
    """
    try:
        with ui.make_spinner("Verifying PIN…") as prog:
            prog.add_task("Verifying PIN…")
            dek = vault.verify_pin_and_get_dek(pin)
        return dek
    except AccountLockedError as exc:
        ui.error(
            f"Account locked after too many failures. "
            f"Try again in [yellow]{exc.remaining_seconds}[/yellow] second(s)."
        )
    except WrongPINError as exc:
        ui.error(str(exc))
    except CorruptedVaultError as exc:
        ui.error(f"Vault configuration is corrupted: {exc}")
    except Exception as exc:
        ui.error(f"Authentication error: {exc}")
    return None


def _show_audit_alert_if_needed(vault: VaultManager) -> None:
    """Show security alert if there are unseen failed login attempts."""
    try:
        audit = vault.get_audit_log()
        count, last_ts = audit.get_unseen_failures()
        if count > 0:
            console.print()
            ui.show_audit_alert(count, last_ts)
            audit.mark_failures_seen()
    except Exception:
        pass  # audit alert failure must never crash the tool


def _check_auto_lock(vault: VaultManager) -> None:
    """Display auto-lock status warnings relevant to the current run."""
    try:
        info = vault.get_auto_lock_info()
        if info["is_unlocked"]:
            if info["is_overdue"]:
                console.print()
                ui.show_auto_lock_warning(
                    info["elapsed_seconds"], info["timeout_minutes"]
                )
            elif info["remaining_seconds"] is not None and info["remaining_seconds"] < 120:
                # Warn only when less than 2 minutes remain
                console.print()
                ui.show_auto_lock_reminder(info["remaining_seconds"])
    except Exception:
        pass


def _normalize_target(target: str, vault: VaultManager) -> Optional[str]:
    """
    Resolve *target* (possibly absolute) to a POSIX relative path string.
    Prints an error and returns None if target is outside the vault base.
    """
    try:
        tp = (vault.base_path / target).resolve()
        return rel_path(tp, vault.base_path)
    except Exception as exc:
        ui.error(f"Cannot resolve path '{target}': {exc}")
        return None



# ─────────────────────────────────────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────────────────────────────────────

console = Console()


def show_custom_help():
    """Displays a stunning, highly distinct, and ultra-readable help handbook for Vortex Vault."""
    
    # 1.  (Fixed Text Color and Contrast)
    title_text = Text()
    title_text.append("VORTEX VAULT (v1.26.06)", style="bold bright_cyan")
    title_text.append("\n• Zero-Knowledge File Cryptography System •", style="bold yellow")
    title_text.append("\nSecure your private assets seamlessly with an encrypted Git-like workflow.", style="dim white")
    
    console.print(Panel(
        title_text,
        border_style="bright_blue",
        padding=(1, 2),
        title="[bold magenta] System Handbook [/bold magenta]",
        title_align="center"
    ))
    
    # 2. Critical Warning Box (Highly Eye-Catching)
    warning_text = Text()
    warning_text.append("🕭 CRITICAL SECURITY WARNING:\n", style="bold red blink")
    warning_text.append("NEVER DELETE OR ALTER THE '.vortex' FOLDER!\n\n", style="bold yellow")
    warning_text.append("This hidden directory acts as your local key storage, housing database configurations, salt, and metadata.\n", style="white")
    warning_text.append("If this folder is deleted, your locked and encrypted files will become ", style="white")
    warning_text.append("PERMANENTLY UNRECOVERABLE!", style="bold red underline")
    
    console.print(Panel(
        warning_text,
        border_style="red",
        padding=(1, 2)
    ))

    # 3. Usage & Developer Info
    console.print("\n[bold magenta]🧱 Core System Architecture:[/bold magenta] [underline cyan]https://github.com/mmizan85/VorTex[/underline cyan]")
    console.print("[bold magenta]🔧 Global Execution Command:[/bold magenta] [bold white]vortex [COMMAND] [OPTIONS][/bold white]\n")

    # 4. Commands Table with Advanced Descriptions & Parameters
    table = Table(
        show_header=True, 
        header_style="bold bright_cyan", 
        box=box.HEAVY_EDGE,           
        show_lines=True,              
        border_style="bright_blue"
    )
    table.add_column("Target Command", style="bold bright_green", width=18, justify="center")
    table.add_column("Sub-Parameters / Options", style="bold gold1", width=22)
    table.add_column("Operational System Protocol & Actions", style="white")
    table.add_column("Execution Example", style="bright_yellow")

    # --- ROW 1: init base ---
    table.add_row(
        "init",
        "[dim]None (Base)[/dim]",
        "Initializes a fresh zero-knowledge cryptographic vault in your active directory.",
        "vortex init"
    )
    # --- ROW 2: init options ---
    table.add_row(
        "",
        "-s, --selective\n-t, --timeout <min>",
        "• [dim]-s[/dim]: Interactive menu to select initial file list.\n• [dim]-t[/dim]: Configures background auto-lock countdown timer.",
        "vortex init -s\nvortex init -t 15"
    )

    # --- ROW 3: add base ---
    table.add_row(
        "add",
        "<paths...>",
        "Appends new local file paths or full directories directly into the tracker metadata.",
        "vortex add secret.txt"
    )
    # --- ROW 4: add selective ---
    table.add_row(
        "",
        "-s, --selective",
        "Launches an interactive Terminal UI checkbox menu to seamlessly pick untracked files.",
        "vortex add -s"
    )

    # --- ROW 5: lock ---
    table.add_row(
        "lock",
        "[dim][target_path][/dim]",
        "Runs AES-256-GCM chunked encryption over manifests. Zeroes out source files and blinds them.",
        "vortex lock\nvortex lock media/"
    )

    # --- ROW 6: unlock ---
    table.add_row(
        "unlock",
        "[dim]None[/dim]",
        "Decrypts and fully restores target plaintexts after verifying master PIN authorization hashes.",
        "vortex unlock"
    )

    # --- ROW 7: status ---
    table.add_row(
        "status",
        "[dim]None[/dim]",
        "Generates a cross-platform matrix showing tracked items, locked vs open state, and UUID maps.",
        "vortex status"
    )

    # --- ROW 8: untrack ---
    table.add_row(
        "untrack",
        "<target_path>",
        "Decrypts the target item, decouples it from tracking database, and pushes it to normal storage.",
        "vortex untrack notes.db"
    )

    # --- ROW 9: reset ---
    table.add_row(
        "reset",
        "[dim]None[/dim]",
        "Bypasses an active lockout using a 16-character Recovery Key to securely override the PIN.",
        "vortex reset"
    )

    # --- ROW 10: purge ---
    table.add_row(
        "purge",
        "[dim]None[/dim]",
        "Emergency mass decryption. Wipes internal keys, balances storage, and deletes the vault context.",
        "vortex purge"
    )

    console.print(table)
    
    # 5. Developer Credits & Footer
    credits_text = Text()
    credits_text.append("Lead Engineer & System Architect: ", style="dim white")
    credits_text.append("Mohammad Mizan ", style="bold gold1")
    credits_text.append("(@mmizan)\n", style="dim cyan")
    credits_text.append("💡 Need atomic breakdown? Append '--help' to individual actions. Example: 'vortex lock --help'", style="italic dim white")
    
    credits_panel = Panel(
        credits_text,
        border_style="dim cyan",
        # box=box.SMOOTH
    )

    console.print(credits_panel)

# Click group overrides to attach our custom UI
@click.group(invoke_without_command=True, add_help_option=False)
@click.option("-h", "--help", is_flag=True, help="Display the advanced interactive system handbook.")
@click.option("-v", "--version", is_flag=True, help="Display software engine version build metadata.")
@click.pass_context
def cli(ctx: click.Context, help: bool, version: bool):
    """Vortex — Zero-Knowledge File Vault with Git-like workflow."""
    if version:
        console.print(f"[bold cyan]Vortex Vault Engine[/bold cyan] Build v2.0.0")
        sys.exit(0)
        
    # Trigger full interface guide if '--help', '-h', or blank group execution occurs
    if help or ctx.invoked_subcommand is None:
        show_custom_help()
        sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# init
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("init")
@click.option(
    "--selective", "-s",
    is_flag=True,
    default=False,
    help="Interactively choose which files/folders to track.",
)
@click.option(
    "--timeout", "-t",
    type=click.IntRange(1, 1440),
    default=15,
    show_default=True,
    metavar="MINUTES",
    help="Auto-lock reminder timeout in minutes.",
)
def cmd_init(selective: bool, timeout: int) -> None:
    """
    Initialise a new vault in the current directory.

    \b
    Creates a hidden .vortex/ directory containing:
      • AES-256 Data Encryption Key (wrapped under PIN-derived KEK)
      • PBKDF2-HMAC-SHA256 PIN hash  (PIN never stored in plain text)
      • One-time Recovery Key        (displayed once; store it safely)
      • Audit log                    (records auth events for alerting)

    \b
    Examples:
      vortex init
      vortex init --selective
      vortex init --timeout 30
    """
    vault = _vault()

    if vault.is_initialized:
        ui.error(
            "A vault already exists here. "
            "Use [bold cyan]vortex status[/bold cyan] to inspect it."
        )
        sys.exit(1)

    ui.print_banner()
    console.print()

    # ── Optional interactive file selection ───────────────────────────────
    tracked: List[str] = []
    if selective:
        from .selector import interactive_select
        ui.info("Select the files/folders this vault should track:")
        console.print()
        tracked = interactive_select(vault.base_path)
        console.print()
        if tracked:
            ui.success(f"{len(tracked)} path(s) selected.")
        else:
            ui.info("No paths selected — you can add them later with [cyan]vortex add[/cyan].")
        console.print()

    # ── PIN setup ─────────────────────────────────────────────────────────
    ui.info("Choose a PIN to protect your vault (4–8 digits, never stored in plain text).")
    console.print()
    try:
        pin = ui.prompt_new_pin()
    except KeyboardInterrupt:
        console.print()
        ui.warning("Initialisation cancelled.")
        sys.exit(0)

    # ── Create vault ──────────────────────────────────────────────────────
    console.print()
    try:
        with ui.make_spinner("Generating cryptographic key material…") as prog:
            prog.add_task("Generating cryptographic key material…")
            recovery_key = vault.initialize(pin, tracked, auto_lock_timeout_minutes=timeout)
        del pin
    except VaultAlreadyInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)
    except PermissionError as exc:
        ui.error(f"Permission denied — cannot create .vortex directory: {exc}")
        sys.exit(1)
    except Exception as exc:
        ui.error(f"Initialisation failed: {exc}")
        sys.exit(1)

    ui.success("Vault initialised successfully!")
    console.print()
    ui.show_recovery_key(recovery_key)
    del recovery_key

    if tracked:
        console.print()
        ui.info(
            f"{len(tracked)} path(s) staged for locking. "
            "Run [bold cyan]vortex lock[/bold cyan] to encrypt them."
        )

    ui.show_post_tip("init")


# ─────────────────────────────────────────────────────────────────────────────
# add  (NEW COMMAND)
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("add")
@click.argument("paths", nargs=-1, metavar="[PATH...]")
@click.option(
    "--selective", "-s",
    is_flag=True,
    default=False,
    help="Interactively pick additional files/folders to track.",
)
def cmd_add(paths: Tuple[str, ...], selective: bool) -> None:
    """
    Add files or folders to the vault's tracking list.

    \b
    Added paths are staged for locking but NOT immediately encrypted.
    Run 'vortex lock' after adding to encrypt them.

    \b
    Examples:
      vortex add secrets.txt
      vortex add docs/ images/ notes.txt
      vortex add --selective
      vortex add docs/ --selective
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    _check_auto_lock(vault)

    already_tracked = set(vault.get_tracked_paths())
    to_add: List[str] = []

    # ── Positional path arguments ─────────────────────────────────────────
    for raw in paths:
        rp = _normalize_target(raw, vault)
        if rp is None:
            continue
        target_path = vault.base_path / rp
        if not target_path.exists():
            ui.error(f"Path not found: '{raw}'")
            continue
        if rp in already_tracked:
            ui.warning(f"Already tracked: [cyan]{rp}[/cyan]")
            continue
        to_add.append(rp)

    # ── Interactive selection ─────────────────────────────────────────────
    if selective:
        from .selector import interactive_select
        console.print()
        ui.info("Select additional files/folders to track:")
        console.print()
        selected = interactive_select(
            vault.base_path,
            exclude_paths=already_tracked | set(to_add),
        )
        console.print()
        for rp in selected:
            if rp not in to_add:
                to_add.append(rp)

    if not to_add:
        ui.info(
            "No new paths to add. "
            "Use [cyan]vortex status[/cyan] to see what is tracked."
        )
        sys.exit(0)

    # ── Add paths to tracking ─────────────────────────────────────────────
    added_count = 0
    for rp in to_add:
        if vault.add_tracked_path(rp):
            ui.success(f"Tracking: [cyan]{rp}[/cyan]")
            added_count += 1
        else:
            ui.warning(f"Already tracked (skipped): [cyan]{rp}[/cyan]")

    console.print()
    ui.success(
        f"[bold]{added_count}[/bold] path(s) added to tracking list."
    )
    ui.show_post_tip("add")


# ─────────────────────────────────────────────────────────────────────────────
# lock
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("lock")
@click.argument("target", required=False, default=None, metavar="[TARGET]")
def cmd_lock(target: Optional[str]) -> None:
    """
    Encrypt and hide tracked files.

    \b
    Without TARGET  — encrypts all tracked paths that exist on disk.
    With TARGET     — encrypts only that specific file or folder, and
                      adds it to the tracking list IF encryption succeeds.

    \b
    What happens to each file:
      1. Encrypted in 64 KiB AES-256-GCM chunks (constant RAM usage)
      2. Renamed to a random UUID with .vtx extension (type hidden)
      3. Moved to .vortex/locked/
      4. Original overwritten with zeros then deleted

    \b
    Bug fix (v2): the tracked path is now only added AFTER at least one
    file is successfully locked. In v1 it was always added immediately.

    \b
    Examples:
      vortex lock
      vortex lock secrets.txt
      vortex lock confidential/
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    _check_auto_lock(vault)

    # ── Authenticate ──────────────────────────────────────────────────────
    try:
        pin = ui.prompt_pin("PIN")
    except KeyboardInterrupt:
        console.print()
        ui.warning("Cancelled.")
        sys.exit(0)

    dek = _authenticate(vault, pin)
    del pin

    if dek is None:
        sys.exit(1)

    _show_audit_alert_if_needed(vault)

    # ── Resolve target paths ──────────────────────────────────────────────
    target_rel: Optional[str] = None   # relative path string for tracking

    if target:
        tp = (vault.base_path / target).resolve()
        if not tp.exists():
            ui.error(f"Target not found: '{target}'")
            clear_bytes(dek)
            sys.exit(1)
        target_rel = rel_path(tp, vault.base_path)
        targets: List[Path] = [tp]

    else:
        tracked = vault.get_tracked_paths()
        if not tracked:
            ui.warning(
                "No tracked paths. Use [cyan]vortex add[/cyan] to add files first."
            )
            clear_bytes(dek)
            sys.exit(0)

        targets = [
            vault.base_path / p
            for p in tracked
            if (vault.base_path / p).exists()
        ]

        if not targets:
            ui.info("All tracked paths are already locked or no longer exist on disk.")
            clear_bytes(dek)
            sys.exit(0)

    # ── Pre-count for progress bar ────────────────────────────────────────
    lockable = count_lockable_files(targets, vault)

    if lockable == 0:
        ui.info("Everything is already locked — nothing to do.")
        clear_bytes(dek)
        sys.exit(0)

    # ── Lock with progress bar ────────────────────────────────────────────
    console.print()
    errors: List[str] = []
    files_locked = 0

    with ui.make_progress() as prog:
        task = prog.add_task(
            "[cyan]Encrypting files…[/cyan]",
            total=lockable,
        )

        def on_success(rp: str) -> None:
            nonlocal files_locked
            files_locked += 1
            prog.advance(task)
            prog.update(
                task,
                description=(
                    f"[cyan]Locked:[/cyan] [dim]{Path(rp).name[:40]}[/dim]"
                ),
            )

        def on_failure(filename: str, msg: str) -> None:
            errors.append(f"  [red]✘[/red]  {filename}: {msg}")
            prog.advance(task)

        total_locked, total_failed = lock_paths(
            targets, vault, dek, on_success, on_failure
        )

    # BUG FIX (v1→v2): add to tracking ONLY after at least one success
    if target_rel and total_locked > 0:
        vault.add_tracked_path(target_rel)

    vault.get_audit_log().record_lock(total_locked)
    vault.clear_unlocked_state()

    clear_bytes(dek)
    del dek

    # ── Summary ───────────────────────────────────────────────────────────
    console.print()
    if total_locked:
        ui.success(
            f"[bold]{total_locked}[/bold] file(s) encrypted and obfuscated as random UUIDs."
        )
    if total_failed:
        ui.warning(f"{total_failed} file(s) could not be locked:")
        for err in errors:
            console.print(err)
    if not total_locked and not total_failed:
        ui.info("Nothing to lock.")

    ui.show_post_tip("lock")


# ─────────────────────────────────────────────────────────────────────────────
# unlock
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("unlock")
def cmd_unlock() -> None:
    """
    Decrypt and restore all locked files to their original locations.

    \b
    What happens:
      1. PIN verified against stored PBKDF2 hash
      2. Each .vtx file in .vortex/locked/ is AES-GCM decrypted
      3. Files restored to their exact original paths and names
      4. Encrypted .vtx copies removed from .vortex/locked/
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    if not vault.has_locked_files():
        ui.info("No locked files found — nothing to unlock.")
        sys.exit(0)

    # ── Authenticate ──────────────────────────────────────────────────────
    try:
        pin = ui.prompt_pin("PIN")
    except KeyboardInterrupt:
        console.print()
        ui.warning("Cancelled.")
        sys.exit(0)

    dek = _authenticate(vault, pin)
    del pin

    if dek is None:
        sys.exit(1)

    _show_audit_alert_if_needed(vault)

    locked_count = len(vault.get_locked_files())
    console.print()
    errors: List[str] = []
    files_unlocked = 0

    with ui.make_progress() as prog:
        task = prog.add_task(
            "[green]Decrypting files…[/green]",
            total=locked_count,
        )

        def on_success(rp: str) -> None:
            nonlocal files_unlocked
            files_unlocked += 1
            prog.advance(task)
            prog.update(
                task,
                description=(
                    f"[green]Restored:[/green] [dim]{Path(rp).name[:40]}[/dim]"
                ),
            )

        def on_failure(vf: str, msg: str) -> None:
            errors.append(f"  [red]✘[/red]  {vf[:20]}…: {msg}")
            prog.advance(task)

        total_unlocked, total_failed = unlock_all_files(
            vault, dek, on_success, on_failure
        )

    vault.get_audit_log().record_unlock(total_unlocked)
    vault.set_unlocked_state()     # start auto-lock timer

    clear_bytes(dek)
    del dek

    console.print()
    if total_unlocked:
        ui.success(
            f"[bold]{total_unlocked}[/bold] file(s) decrypted and restored."
        )
    if total_failed:
        ui.warning(f"{total_failed} file(s) could not be unlocked:")
        for err in errors:
            console.print(err)

    ui.show_post_tip("unlock")


# ─────────────────────────────────────────────────────────────────────────────
# untrack  (NEW COMMAND)
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("untrack")
@click.argument("target", metavar="TARGET")
def cmd_untrack(target: str) -> None:
    """
    Permanently decrypt a file/folder and remove it from tracking.

    \b
    After this command the file is a normal file and will NOT be
    encrypted again by future 'vortex lock' runs.

    \b
    If the target is currently locked, your PIN is required to decrypt
    it first.  If it is already on disk (unlocked), no PIN is needed.

    \b
    Tracking removal rules:
      • The exact path and any sub-paths are removed from tracked_paths.
      • If a parent directory is tracked (e.g. docs/ is tracked and you
        untrack docs/report.txt), a warning is shown because 'vortex lock'
        would re-encrypt the file as part of the parent directory.

    \b
    Examples:
      vortex untrack secrets.txt
      vortex untrack confidential/
      vortex untrack docs/report.txt
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    _check_auto_lock(vault)

    # ── Resolve target ────────────────────────────────────────────────────
    target_rel = _normalize_target(target, vault)
    if target_rel is None:
        sys.exit(1)

    # ── Find locked files matching this target ────────────────────────────
    locked_matches = find_locked_by_path(target_rel, vault)
    is_in_tracking = vault.path_is_tracked(target_rel)

    if not locked_matches and not is_in_tracking:
        # Check whether the file exists on disk but under a tracked parent
        tracked = vault.get_tracked_paths()
        target_prefix = target_rel + "/"
        parent_tracked = [
            p for p in tracked
            if target_rel.startswith(p.rstrip("/") + "/")
        ]
        if not parent_tracked:
            ui.error(
                f"'{target_rel}' is not being tracked by this vault. "
                "Use [cyan]vortex status[/cyan] to see tracked paths."
            )
            sys.exit(1)
        # File is under a tracked parent dir but not individually tracked
        ui.warning(
            f"'{target_rel}' is not directly tracked, but its parent "
            f"[cyan]{parent_tracked[0]}[/cyan] is.\n"
            "  Untracking the parent directory instead is recommended:\n"
            f"  [cyan]vortex untrack {parent_tracked[0]}[/cyan]"
        )
        if not ui.confirm(f"Decrypt and permanently exclude '{target_rel}' anyway?"):
            ui.info("Cancelled.")
            sys.exit(0)

    dek: Optional[bytes] = None

    # ── Decrypt locked files (PIN required) ───────────────────────────────
    if locked_matches:
        lock_word = "file" if len(locked_matches) == 1 else "files"
        console.print()
        ui.info(
            f"Found [bold]{len(locked_matches)}[/bold] locked {lock_word} "
            f"matching [cyan]{target_rel}[/cyan]. PIN required to decrypt."
        )
        console.print()

        try:
            pin = ui.prompt_pin("PIN")
        except KeyboardInterrupt:
            console.print()
            ui.warning("Cancelled.")
            sys.exit(0)

        dek = _authenticate(vault, pin)
        del pin

        if dek is None:
            sys.exit(1)

        _show_audit_alert_if_needed(vault)

        errors: List[str] = []
        files_unlocked = 0

        with ui.make_progress() as prog:
            task = prog.add_task(
                f"[green]Decrypting {target_rel}…[/green]",
                total=len(locked_matches),
            )

            def on_success(rp: str) -> None:
                nonlocal files_unlocked
                files_unlocked += 1
                prog.advance(task)
                prog.update(
                    task,
                    description=(
                        f"[green]Restored:[/green] [dim]{Path(rp).name[:40]}[/dim]"
                    ),
                )

            def on_failure(vf: str, msg: str) -> None:
                errors.append(f"  [red]✘[/red]  {vf[:20]}…: {msg}")
                prog.advance(task)

            total_unlocked, total_failed = unlock_specific_paths(
                target_rel, vault, dek, on_success, on_failure
            )

        vault.get_audit_log().record_unlock(total_unlocked)
        clear_bytes(dek)
        del dek

        console.print()
        if total_unlocked:
            ui.success(
                f"[bold]{total_unlocked}[/bold] file(s) decrypted and restored."
            )
        if total_failed:
            ui.warning(f"{total_failed} file(s) could not be decrypted:")
            for err in errors:
                console.print(err)

    # ── Remove from tracking ──────────────────────────────────────────────
    removed = vault.remove_tracked_path(target_rel)

    if removed:
        ui.success(
            f"[cyan]{target_rel}[/cyan] removed from tracking list."
        )
    else:
        # May not have been directly tracked (covered by parent dir)
        ui.info(
            f"'{target_rel}' was not directly in the tracking list "
            "(may have been covered by a parent directory entry)."
        )

    # ── Warn if a parent directory is still tracked ───────────────────────
    tracked = vault.get_tracked_paths()
    still_covered = [
        p for p in tracked
        if target_rel.startswith(p.rstrip("/") + "/")
    ]
    if still_covered:
        console.print()
        ui.warning(
            f"Parent directory [cyan]{still_covered[0]}[/cyan] is still tracked.\n"
            f"  Running [cyan]vortex lock[/cyan] will re-encrypt files inside it, "
            f"including [cyan]{target_rel}[/cyan] if it exists on disk.\n"
            f"  To prevent this, also untrack the parent: "
            f"[cyan]vortex untrack {still_covered[0]}[/cyan]"
        )

    ui.show_post_tip("untrack")


# ─────────────────────────────────────────────────────────────────────────────
# status
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("status")
def cmd_status() -> None:
    """
    Display vault health, tracked files, and their lock state.

    \b
    Shows a color-coded table with:
      • Original file names
      • Obfuscated vault filenames (UUID.vtx)
      • File sizes and lock timestamps
      • Current state (LOCKED / UNLOCKED)
      • Auto-lock timer status
      • Security alert count (if any failed logins occurred)

    No PIN required — metadata only, no secrets exposed.
    """
    vault = _vault()
    try:
        ui.print_status(vault)
    except CorruptedVaultError as exc:
        ui.error(f"Vault configuration is corrupted: {exc}")
        sys.exit(1)
    except Exception as exc:
        ui.error(f"Could not read vault status: {exc}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# reset
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("reset")
def cmd_reset() -> None:
    """
    Reset your PIN using the Recovery Key.

    \b
    Key properties:
      • Requires the Recovery Key shown during 'vortex init'
      • The Data Encryption Key is NOT changed
      • All locked files remain intact and accessible after reset
      • Only the PIN-derived Key Encryption Key is rotated

    \b
    If you have lost BOTH your PIN and Recovery Key, your data
    cannot be recovered — there is no back door by design.
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    console.print()
    ui.warning("PIN reset requires your Recovery Key.")
    console.print()

    try:
        recovery_key = ui.prompt_recovery_key()
    except KeyboardInterrupt:
        console.print()
        ui.warning("Cancelled.")
        sys.exit(0)

    try:
        with ui.make_spinner("Verifying recovery key…") as prog:
            prog.add_task("Verifying recovery key…")
            dek = vault.verify_recovery_key_and_get_dek(recovery_key)
        del recovery_key
    except InvalidRecoveryKeyError as exc:
        ui.error(str(exc))
        sys.exit(1)
    except CorruptedVaultError as exc:
        ui.error(f"Vault is corrupted: {exc}")
        sys.exit(1)
    except Exception as exc:
        ui.error(f"Verification failed: {exc}")
        sys.exit(1)

    ui.success("Recovery key verified.")
    console.print()

    try:
        new_pin = ui.prompt_new_pin("Set new PIN (4–8 digits)")
    except KeyboardInterrupt:
        clear_bytes(dek)
        console.print()
        ui.warning("Cancelled.")
        sys.exit(0)

    try:
        with ui.make_spinner("Updating vault credentials…") as prog:
            prog.add_task("Updating vault credentials…")
            vault.reset_pin(new_pin, dek)
        del new_pin
    except Exception as exc:
        ui.error(f"Failed to reset PIN: {exc}")
        sys.exit(1)
    finally:
        clear_bytes(dek)
        del dek

    console.print()
    ui.success(
        "PIN reset successfully. "
        "All locked files are unaffected."
    )
    ui.show_post_tip("reset")


# ─────────────────────────────────────────────────────────────────────────────
# purge
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("purge")
def cmd_purge() -> None:
    """
    Decrypt all files and permanently delete the vault.

    \b
    Steps performed:
      1. PIN verified
      2. Every locked file decrypted back to its original location
      3. .vortex/ directory and all metadata permanently deleted

    \b
    WARNING: This is IRREVERSIBLE. The vault cannot be recovered
    after this command completes.
    """
    vault = _vault()

    try:
        vault.require_initialized()
    except VaultNotInitializedError as exc:
        ui.error(str(exc))
        sys.exit(1)

    console.print()
    console.print(
        "[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]"
    )
    console.print(
        "[bold red]  PURGE — IRREVERSIBLE — ALL VAULT METADATA WILL BE DELETED[/bold red]"
    )
    console.print(
        "[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]"
    )
    console.print()

    if not ui.confirm("Are you absolutely sure you want to purge this vault?"):
        ui.info("Purge cancelled.")
        sys.exit(0)

    try:
        pin = ui.prompt_pin("PIN to authorise purge")
    except KeyboardInterrupt:
        console.print()
        ui.warning("Cancelled.")
        sys.exit(0)

    dek = _authenticate(vault, pin)
    del pin

    if dek is None:
        sys.exit(1)

    _show_audit_alert_if_needed(vault)

    # ── Decrypt all locked files ──────────────────────────────────────────
    if vault.has_locked_files():
        locked_count = len(vault.get_locked_files())
        console.print()
        ui.info(f"Decrypting [bold]{locked_count}[/bold] file(s) before purge…")
        errors: List[str] = []

        with ui.make_progress() as prog:
            task = prog.add_task("[cyan]Restoring…[/cyan]", total=locked_count)

            def on_success(rp: str) -> None:
                prog.advance(task)
                prog.update(
                    task,
                    description=(
                        f"[cyan]Restored:[/cyan] [dim]{Path(rp).name[:40]}[/dim]"
                    ),
                )

            def on_failure(vf: str, msg: str) -> None:
                errors.append(f"  [red]✘[/red]  {vf[:20]}…: {msg}")
                prog.advance(task)

            total_unlocked, total_failed = unlock_all_files(
                vault, dek, on_success, on_failure
            )

        if total_failed:
            console.print()
            ui.warning(f"{total_failed} file(s) were not restored:")
            for err in errors:
                console.print(err)
            console.print()
            if not ui.confirm(
                f"{total_failed} file(s) could not be restored. "
                "Purge anyway and permanently lose them?"
            ):
                clear_bytes(dek)
                ui.info("Purge aborted. Vault is intact.")
                sys.exit(0)

    vault.get_audit_log().record_purge()
    clear_bytes(dek)
    del dek

    try:
        vault.destroy()
    except Exception as exc:
        ui.error(f"Failed to delete .vortex directory: {exc}")
        sys.exit(1)

    console.print()
    ui.success(
        "Vault purged. The [dim].vortex[/dim] directory has been permanently deleted."
    )
    ui.show_post_tip("purge")
