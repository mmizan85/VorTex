"""
vortex/selector.py
──────────────────
Interactive file/folder selection for ``vortex init --selective`` and
``vortex add --selective``.

Bug fixes vs v1
───────────────
  - InquirerPy ``Choice`` import path normalised across package versions:
    tries both ``InquirerPy.base.control.Choice`` and the top-level import,
    falling back gracefully to ``pick`` then manual text entry.
  - ``interactive_select`` now accepts ``exclude_paths`` so already-tracked
    paths are filtered from the picker in ``vortex add`` mode.

Backend fallback chain
──────────────────────
  1. InquirerPy  — rich checkbox UI with arrow-key navigation.
  2. pick        — simpler curses-based checkbox.
  3. Manual      — plain text input for non-interactive/headless terminals.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

from .file_ops import list_visible_items
from . import ui


def interactive_select(
    base_path: Path,
    exclude_paths: Optional[Set[str]] = None,
    title: str = "Select files/folders to track:",
) -> List[str]:
    """
    Open an interactive multi-select menu listing *base_path* contents.

    Parameters
    ----------
    base_path:
        Directory to list.
    exclude_paths:
        Relative path strings to hide from the picker (already-tracked items).
    title:
        Prompt title shown above the selection list.

    Returns
    -------
    List of POSIX relative-path strings selected by the user.
    Never raises — all errors are handled internally.
    """
    exclude = exclude_paths or set()

    try:
        return _inquirerpy_select(base_path, exclude, title)
    except ImportError:
        pass

    try:
        return _pick_select(base_path, exclude, title)
    except ImportError:
        pass

    return _manual_select(base_path, exclude)


# ─────────────────────────────────────────────────────────────────────────────
# Backend: InquirerPy
# ─────────────────────────────────────────────────────────────────────────────

def _make_choice(value: str, name: str) -> object:
    """
    BUG FIX: InquirerPy changed the import path of ``Choice`` between
    versions.  This helper tries both known paths.
    """
    try:
        from InquirerPy.base.control import Choice          # type: ignore[import]
        return Choice(value=value, name=name)
    except ImportError:
        pass
    try:
        from InquirerPy import Choice as C2                 # type: ignore[import]
        return C2(value=value, name=name)
    except ImportError:
        pass
    # Fallback: return raw value (InquirerPy will display it as-is)
    return value


def _inquirerpy_select(
    base_path: Path,
    exclude: Set[str],
    title: str,
) -> List[str]:
    """Multi-select via InquirerPy. Raises ImportError if unavailable."""
    from InquirerPy import inquirer          # type: ignore[import]

    items = [
        item for item in list_visible_items(base_path)
        if item.relative_to(base_path).as_posix() not in exclude
    ]

    if not items:
        ui.warning("No new files or folders available to add.")
        return []

    choices = [
        _make_choice(
            value=item.relative_to(base_path).as_posix(),
            name=("📁  " if item.is_dir() else "📄  ") + item.name,
        )
        for item in items
    ]

    try:
        selected: List[str] = inquirer.checkbox(
            message=title,
            choices=choices,
            instruction=(
                "  ↑↓ navigate  ·  Space select  ·  Enter confirm  ·  Ctrl-C cancel"
            ),
        ).execute()
        return selected or []
    except KeyboardInterrupt:
        return []
    except Exception as exc:
        ui.warning(f"InquirerPy error: {exc}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Backend: pick
# ─────────────────────────────────────────────────────────────────────────────

def _pick_select(
    base_path: Path,
    exclude: Set[str],
    title: str,
) -> List[str]:
    """Multi-select via the ``pick`` library. Raises ImportError if unavailable."""
    import pick  # type: ignore[import]

    items = [
        item for item in list_visible_items(base_path)
        if item.relative_to(base_path).as_posix() not in exclude
    ]

    if not items:
        return []

    labels = [
        f"{'[DIR]  ' if item.is_dir() else '[FILE] '}{item.name}"
        for item in items
    ]

    try:
        result = pick.pick(
            labels,
            f"{title}  (Space=toggle, Enter=confirm):",
            multiselect=True,
            min_selection_count=0,
        )
        if not result:
            return []
        # pick returns [(label, index), ...] in multiselect mode
        return [
            items[idx].relative_to(base_path).as_posix()
            for _, idx in result
        ]
    except KeyboardInterrupt:
        return []
    except Exception as exc:
        ui.warning(f"pick error: {exc}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Backend: manual text input
# ─────────────────────────────────────────────────────────────────────────────

def _manual_select(base_path: Path, exclude: Set[str]) -> List[str]:
    """Plain text fallback when neither InquirerPy nor pick is installed."""
    from rich.console import Console
    con = Console()

    ui.warning("Interactive mode requires InquirerPy or pick.")
    ui.info("  Install with:  [bold]pip install InquirerPy[/bold]")
    con.print()
    ui.info("Falling back to manual entry — type one path per line, blank line to finish.")
    con.print()

    items = [
        item for item in list_visible_items(base_path)
        if item.relative_to(base_path).as_posix() not in exclude
    ]

    if items:
        con.print("[dim]Available items:[/dim]")
        for item in items:
            already = "(tracked)" if item.relative_to(base_path).as_posix() in exclude else ""
            icon = "📁" if item.is_dir() else "📄"
            con.print(f"  {icon}  {item.name}  [dim]{already}[/dim]")
        con.print()

    selected: List[str] = []
    while True:
        try:
            entry = input("  Path (blank to finish): ").strip()
        except (EOFError, KeyboardInterrupt):
            con.print()
            break
        if not entry:
            break
        candidate = base_path / entry
        if not candidate.exists():
            ui.error(f"Not found: {entry}")
            continue
        try:
            rp = candidate.relative_to(base_path).as_posix()
        except ValueError:
            ui.error(f"Path must be inside the current directory: {entry}")
            continue
        if rp in exclude:
            ui.warning(f"Already tracked: {rp}")
            continue
        if rp not in selected:
            selected.append(rp)
            ui.success(f"Added: {rp}")
        else:
            ui.warning(f"Already in selection: {rp}")

    return selected
