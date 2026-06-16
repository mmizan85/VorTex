"""
vortex/file_ops.py
──────────────────
High-level file locking and unlocking operations.

Bug fixes vs v1
───────────────
  1. Empty directories now cleaned up after locking (bottom-up rmdir).
  2. ``.vtx`` files inside the base directory (but outside .vortex) are
     skipped during collection — double-encryption is now impossible.
  3. ``rel_path()`` is a public function so cli.py no longer imports
     the private ``_rel`` across module boundaries (API hygiene fix).
  4. ``unlock_specific_paths()`` added for the ``vortex untrack`` command.
  5. Orphan ``.tmp`` cleanup runs before every lock batch.

Atomicity guarantee
───────────────────
  Encryption: writes to ``.venc_<uuid>.tmp`` then renames to ``.vtx``.
  Decryption: writes to ``.vdec_<uuid>.tmp`` then renames to original name.
  Only on 100% success does the rename occur; partial files never persist.

Secure deletion
───────────────
  Plaintext originals are overwritten with zeros then unlinked.
  Note: hardware-level retention (SSD wear-levelling, copy-on-write FSes)
  can bypass software overwrite — this is a best-effort measure.
"""

from __future__ import annotations

import os
import uuid as _uuid_mod
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple

from .crypto_engine import decrypt_file, encrypt_file
from .exceptions import FileDecryptionError, FileEncryptionError
from .vault_manager import VaultManager

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_OVERWRITE_CHUNK: bytes = b"\x00" * 65_536   # 64 KiB zero buffer


def rel_path(path: Path, base: Path) -> str:
    """
    Public helper: POSIX-style relative path string.
    Falls back to the absolute path string if *path* is outside *base*.

    BUG FIX: was a private ``_rel`` function imported across module boundaries
    in v1.  Now public and declared here once.
    """
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _is_under(child: Path, parent: Path) -> bool:
    """True when *child* is inside *parent* (Python 3.8-compatible)."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def generate_vault_filename() -> str:
    """Random UUID hex string with ``.vtx`` extension."""
    return _uuid_mod.uuid4().hex + ".vtx"


# ─────────────────────────────────────────────────────────────────────────────
# File collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_files(root: Path, skip_dir: Path) -> List[Path]:
    """
    Recursively collect every regular file under *root*, excluding:
      • Anything inside *skip_dir* (the ``.vortex`` directory).
      • BUG FIX: ``.vtx`` files in the base directory to prevent
        double-encryption of already-encrypted files.

    Parameters
    ----------
    root:
        File or directory to collect from.
    skip_dir:
        Directory to skip entirely (``vault.vortex_path``).
    """
    if root.is_file():
        if _is_under(root, skip_dir):
            return []
        # Skip loose .vtx files that are not inside the vault store
        if root.suffix == ".vtx" and not _is_under(root, skip_dir):
            return []
        return [root]

    result: List[Path] = []
    if root.is_dir():
        for item in root.rglob("*"):
            if not item.is_file():
                continue
            if _is_under(item, skip_dir):
                continue
            # Skip stray .vtx files outside the vault store
            if item.suffix == ".vtx":
                continue
            result.append(item)
    return result


def list_visible_items(base_path: Path) -> List[Path]:
    """
    Return sorted non-hidden, non-cache items one level deep in *base_path*.
    Used by the interactive file selector.
    """
    try:
        return sorted(
            item
            for item in base_path.iterdir()
            if not item.name.startswith(".")
            and item.name not in {"__pycache__", "node_modules"}
        )
    except OSError:
        return []


def count_lockable_files(targets: List[Path], vault: VaultManager) -> int:
    """Count files across *targets* that are not yet locked."""
    locked_originals: Set[str] = {
        info["original_path"]
        for info in vault.get_locked_files().values()
    }
    total = 0
    for target in targets:
        for file_path in collect_files(target, vault.vortex_path):
            rp = rel_path(file_path, vault.base_path)
            if rp not in locked_originals:
                total += 1
    return total


# ─────────────────────────────────────────────────────────────────────────────
# Secure deletion & directory cleanup
# ─────────────────────────────────────────────────────────────────────────────

def _secure_delete(path: Path) -> None:
    """Overwrite *path* with zeros then unlink it (best-effort)."""
    try:
        size = path.stat().st_size
        if size > 0:
            with open(path, "r+b") as fh:
                remaining = size
                while remaining > 0:
                    chunk_len = min(len(_OVERWRITE_CHUNK), remaining)
                    fh.write(_OVERWRITE_CHUNK[:chunk_len])
                    remaining -= chunk_len
                try:
                    fh.flush()
                    os.fsync(fh.fileno())
                except OSError:
                    pass
    except (OSError, PermissionError):
        pass
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_orphan_tmps(locked_dir: Path) -> None:
    """Remove stale ``.tmp`` files from a previous interrupted operation."""
    if not locked_dir.exists():
        return
    for tmp in locked_dir.glob("*.tmp"):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_empty_dirs(root: Path, skip_dir: Path) -> None:
    """
    BUG FIX (v1): empty directory skeletons persisted after locking.

    Walk *root* bottom-up and rmdir any empty directories (excluding
    *root* itself and anything inside *skip_dir*).

    ``Path.rmdir()`` only succeeds on truly empty directories, so this
    is safe to call unconditionally — non-empty directories are silently
    skipped.
    """
    if not root.is_dir():
        return

    # Sort by depth descending (deepest first) so we work bottom-up
    all_dirs = sorted(
        [
            p for p in root.rglob("*")
            if p.is_dir()
            and not _is_under(p, skip_dir)
            and p != root
        ],
        key=lambda p: len(p.parts),
        reverse=True,
    )

    for d in all_dirs:
        try:
            d.rmdir()   # silently fails if not empty
        except OSError:
            pass

    # Also try the root target itself
    try:
        root.rmdir()
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Lock
# ─────────────────────────────────────────────────────────────────────────────

def lock_paths(
    targets: List[Path],
    vault: VaultManager,
    dek: bytes,
    on_success: Optional[Callable[[str], None]] = None,
    on_failure: Optional[Callable[[str, str], None]] = None,
) -> Tuple[int, int]:
    """
    Encrypt every regular file found under each path in *targets*.

    BUG FIX (v1): tracked path is now added by the *caller* only after at
    least one file is successfully locked — not before.

    Skips already-locked files silently.

    Returns
    -------
    (files_locked, files_failed)
    """
    vault.locked_dir.mkdir(parents=True, exist_ok=True)
    _cleanup_orphan_tmps(vault.locked_dir)

    locked_originals: Set[str] = {
        info["original_path"]
        for info in vault.get_locked_files().values()
    }

    files_locked = 0
    files_failed = 0

    for target in targets:
        for file_path in collect_files(target, vault.vortex_path):
            rp = rel_path(file_path, vault.base_path)
            if rp in locked_originals:
                continue

            vault_filename = generate_vault_filename()
            dest = vault.locked_dir / vault_filename

            try:
                original_size = file_path.stat().st_size
                encrypt_file(file_path, dest, dek, vault_filename)
                vault.add_file_record(vault_filename, rp, original_size)
                _secure_delete(file_path)
                locked_originals.add(rp)
                files_locked += 1
                if on_success:
                    on_success(rp)

            except PermissionError as exc:
                files_failed += 1
                if dest.exists():
                    try:
                        dest.unlink()
                    except OSError:
                        pass
                if on_failure:
                    on_failure(file_path.name, f"Permission denied: {exc}")
            except FileEncryptionError as exc:
                files_failed += 1
                if dest.exists():
                    try:
                        dest.unlink()
                    except OSError:
                        pass
                if on_failure:
                    on_failure(file_path.name, str(exc))
            except Exception as exc:
                files_failed += 1
                if on_failure:
                    on_failure(file_path.name, f"Unexpected error: {exc}")

    # BUG FIX: clean up empty directory skeletons left behind by locking
    for target in targets:
        if target.is_dir():
            _cleanup_empty_dirs(target, vault.vortex_path)

    return files_locked, files_failed


# ─────────────────────────────────────────────────────────────────────────────
# Unlock all
# ─────────────────────────────────────────────────────────────────────────────

def unlock_all_files(
    vault: VaultManager,
    dek: bytes,
    on_success: Optional[Callable[[str], None]] = None,
    on_failure: Optional[Callable[[str, str], None]] = None,
) -> Tuple[int, int]:
    """
    Decrypt every locked file and restore it to its original path.

    Returns
    -------
    (files_unlocked, files_failed)
    """
    records = dict(vault.get_locked_files())   # snapshot
    files_unlocked = 0
    files_failed = 0

    for vault_filename, info in records.items():
        src = vault.locked_dir / vault_filename
        original_rel: str = info["original_path"]
        dest = vault.base_path / original_rel

        if not src.exists():
            files_failed += 1
            if on_failure:
                on_failure(
                    vault_filename,
                    f"Encrypted file missing from vault store: {src.name}",
                )
            continue

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            decrypt_file(src, dest, dek, vault_filename)
            src.unlink(missing_ok=True)
            vault.remove_file_record(vault_filename)
            files_unlocked += 1
            if on_success:
                on_success(original_rel)

        except PermissionError as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, f"Permission denied: {exc}")
        except FileDecryptionError as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, str(exc))
        except Exception as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, f"Unexpected error: {exc}")

    return files_unlocked, files_failed


# ─────────────────────────────────────────────────────────────────────────────
# Unlock specific paths  (NEW — used by vortex untrack)
# ─────────────────────────────────────────────────────────────────────────────

def unlock_specific_paths(
    target_rel: str,
    vault: VaultManager,
    dek: bytes,
    on_success: Optional[Callable[[str], None]] = None,
    on_failure: Optional[Callable[[str, str], None]] = None,
) -> Tuple[int, int]:
    """
    Decrypt only the locked files whose ``original_path`` matches *target_rel*
    exactly OR starts with ``target_rel + "/"`` (directory prefix).

    Used by ``vortex untrack`` to selectively decrypt without touching other
    locked files.

    Returns
    -------
    (files_unlocked, files_failed)
    """
    records = dict(vault.get_locked_files())
    target_prefix = target_rel.rstrip("/") + "/"

    matching = {
        vault_filename: info
        for vault_filename, info in records.items()
        if (
            info["original_path"] == target_rel
            or info["original_path"].startswith(target_prefix)
        )
    }

    if not matching:
        return 0, 0

    files_unlocked = 0
    files_failed = 0

    for vault_filename, info in matching.items():
        src = vault.locked_dir / vault_filename
        original_rel: str = info["original_path"]
        dest = vault.base_path / original_rel

        if not src.exists():
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, f"Encrypted file missing: {src.name}")
            continue

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            decrypt_file(src, dest, dek, vault_filename)
            src.unlink(missing_ok=True)
            vault.remove_file_record(vault_filename)
            files_unlocked += 1
            if on_success:
                on_success(original_rel)

        except PermissionError as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, f"Permission denied: {exc}")
        except FileDecryptionError as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, str(exc))
        except Exception as exc:
            files_failed += 1
            if on_failure:
                on_failure(vault_filename, f"Unexpected error: {exc}")

    return files_unlocked, files_failed


def find_locked_by_path(target_rel: str, vault: VaultManager) -> List[str]:
    """
    Return a list of vault filenames whose original_path matches *target_rel*
    or is under it.  Used to decide whether PIN is needed for untrack.
    """
    target_prefix = target_rel.rstrip("/") + "/"
    return [
        vf
        for vf, info in vault.get_locked_files().items()
        if (
            info["original_path"] == target_rel
            or info["original_path"].startswith(target_prefix)
        )
    ]
