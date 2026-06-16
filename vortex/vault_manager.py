"""
vortex/vault_manager.py
───────────────────────
High-level management of the ``.vortex`` vault directory.

v2 Config schema additions
──────────────────────────
  auto_lock_timeout_minutes  int   — minutes until auto-lock reminder (default 15)
  unlocked_at                str?  — ISO-8601 UTC timestamp set on unlock, cleared on lock

BUG FIX (v1 → v2)
──────────────────
  - ``get_config()`` returned a stale dict in multi-step operations.
    All internal methods now call ``_load_config()`` directly (fresh disk
    read), while ``get_config()`` is kept for read-only external callers and
    always loads fresh data by setting ``_cache = None`` at the start.
  - ``verify_pin_and_get_dek`` now integrates with AuditLog.
  - Backward-compatible with v1.0.0 config files.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .audit import AuditLog
from .crypto_engine import (
    decrypt_dek,
    derive_kek_from_pin,
    derive_kek_from_recovery,
    derive_pin_hash,
    derive_recovery_verify_hash,
    encrypt_dek,
    generate_dek,
    generate_recovery_key,
    verify_pin,
    verify_recovery_key,
)
from .exceptions import (
    AccountLockedError,
    CorruptedVaultError,
    InvalidRecoveryKeyError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WrongPINError,
)
from .security import (
    LOCKOUT_SECONDS,
    MAX_FAILED_ATTEMPTS,
    clear_bytes,
)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VORTEX_DIR: str = ".vortex"
CONFIG_FILE: str = "config.json"
LOCKED_SUBDIR: str = "locked"
VAULT_VERSION: str = "2.0.0"
DEFAULT_AUTO_LOCK_MINUTES: int = 15


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


# ─────────────────────────────────────────────────────────────────────────────
# VaultManager
# ─────────────────────────────────────────────────────────────────────────────

class VaultManager:
    """
    Single source of truth for all vault state.

    Instantiate with the directory that should contain ``.vortex/``.
    """

    def __init__(self, base_path: Optional[Path] = None) -> None:
        self.base_path: Path = (base_path or Path.cwd()).resolve()
        self.vortex_path: Path = self.base_path / VORTEX_DIR
        self.config_path: Path = self.vortex_path / CONFIG_FILE
        self.locked_dir: Path = self.vortex_path / LOCKED_SUBDIR

    # ──────────────────────────────────────────────────────────────────────
    # Initialization state
    # ──────────────────────────────────────────────────────────────────────

    @property
    def is_initialized(self) -> bool:
        return self.config_path.is_file()

    def require_initialized(self) -> None:
        if not self.is_initialized:
            raise VaultNotInitializedError(
                "No vault found in the current directory. "
                "Run [bold cyan]vortex init[/bold cyan] to create one."
            )

    # ──────────────────────────────────────────────────────────────────────
    # Config I/O  (BUG FIX: always fresh-reads from disk)
    # ──────────────────────────────────────────────────────────────────────

    def _load_config(self) -> Dict:
        """Read config from disk; always fresh (no cache)."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            raise CorruptedVaultError(
                f"Vault config is not valid JSON: {exc}"
            ) from exc
        except OSError as exc:
            raise CorruptedVaultError(
                f"Cannot read vault config: {exc}"
            ) from exc

    def _save_config(self, config: Dict) -> None:
        """Atomically write *config* to disk via tmp → rename."""
        tmp = self.config_path.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(config, fh, indent=2, default=str)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            tmp.replace(self.config_path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise CorruptedVaultError(f"Cannot save vault config: {exc}") from exc

    def get_config(self) -> Dict:
        """
        Public read-only accessor.
        BUG FIX: always reads from disk (no stale cache).
        """
        return self._load_config()

    # ──────────────────────────────────────────────────────────────────────
    # Initialisation
    # ──────────────────────────────────────────────────────────────────────

    def initialize(
        self,
        pin: str,
        tracked_paths: Optional[List[str]] = None,
        auto_lock_timeout_minutes: int = DEFAULT_AUTO_LOCK_MINUTES,
    ) -> str:
        """
        Create ``.vortex/`` and write all cryptographic material.

        Returns the one-time recovery key — show it once and discard.
        """
        if self.is_initialized:
            raise VaultAlreadyInitializedError(
                "A vault already exists here."
            )

        self.vortex_path.mkdir(parents=True, exist_ok=True)
        self.locked_dir.mkdir(parents=True, exist_ok=True)
        self._hide_directory(self.vortex_path)

        # ── Generate all cryptographic material ──────────────────────────
        dek = generate_dek()

        pin_salt = os.urandom(32)
        kek_salt = os.urandom(32)
        r_kek_salt = os.urandom(32)
        r_verify_salt = os.urandom(32)

        pin_hash = derive_pin_hash(pin, pin_salt)
        kek = derive_kek_from_pin(pin, kek_salt)
        enc_dek = encrypt_dek(dek, kek)

        recovery_key = generate_recovery_key()
        r_kek = derive_kek_from_recovery(recovery_key, r_kek_salt)
        r_enc_dek = encrypt_dek(dek, r_kek)
        r_verify_hash = derive_recovery_verify_hash(recovery_key, r_verify_salt)

        config: Dict[str, Any] = {
            "version": VAULT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            # PIN verification
            "pin_salt": _b64e(pin_salt),
            "pin_hash": _b64e(pin_hash),
            # PIN-based DEK wrapping
            "kek_salt": _b64e(kek_salt),
            "encrypted_dek": _b64e(enc_dek),
            # Recovery key
            "recovery_kek_salt": _b64e(r_kek_salt),
            "recovery_verify_salt": _b64e(r_verify_salt),
            "recovery_key_hash": _b64e(r_verify_hash),
            "recovery_encrypted_dek": _b64e(r_enc_dek),
            # Brute-force protection
            "failed_attempts": 0,
            "lockout_until": None,
            # Auto-lock
            "auto_lock_timeout_minutes": auto_lock_timeout_minutes,
            "unlocked_at": None,
            # Tracking
            "tracked_paths": list(tracked_paths or []),
            "files": {},
        }
        self._save_config(config)

        # Initialise empty audit log
        self.get_audit_log().record_init()

        clear_bytes(dek)
        clear_bytes(kek)
        clear_bytes(r_kek)
        del dek, kek, r_kek

        return recovery_key

    @staticmethod
    def _hide_directory(path: Path) -> None:
        """Apply FILE_ATTRIBUTE_HIDDEN on Windows; no-op on Unix."""
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02)
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────────────────
    # Audit log
    # ──────────────────────────────────────────────────────────────────────

    def get_audit_log(self) -> AuditLog:
        """Return an AuditLog bound to this vault's .vortex directory."""
        return AuditLog(self.vortex_path)

    # ──────────────────────────────────────────────────────────────────────
    # Auto-lock
    # ──────────────────────────────────────────────────────────────────────

    def set_unlocked_state(self) -> None:
        """Record the time files were unlocked (for auto-lock reminders)."""
        config = self._load_config()
        config["unlocked_at"] = datetime.now(timezone.utc).isoformat()
        self._save_config(config)

    def clear_unlocked_state(self) -> None:
        """Clear the unlocked timestamp (call after locking files)."""
        config = self._load_config()
        config["unlocked_at"] = None
        self._save_config(config)

    def get_auto_lock_info(self) -> Dict[str, Any]:
        """
        Return auto-lock status information.

        Returns
        -------
        dict with keys:
          is_unlocked        bool  — vault is currently in unlocked state
          timeout_minutes    int   — configured timeout
          elapsed_seconds    int?  — seconds since unlock (None if locked)
          remaining_seconds  int?  — seconds until reminder (None if locked/overdue)
          is_overdue         bool  — timeout has already passed
        """
        config = self._load_config()
        unlocked_at_str: Optional[str] = config.get("unlocked_at")
        timeout_minutes: int = config.get("auto_lock_timeout_minutes", DEFAULT_AUTO_LOCK_MINUTES)

        if not unlocked_at_str:
            return {
                "is_unlocked": False,
                "timeout_minutes": timeout_minutes,
                "elapsed_seconds": None,
                "remaining_seconds": None,
                "is_overdue": False,
            }

        try:
            unlocked_at = datetime.fromisoformat(unlocked_at_str)
        except ValueError:
            return {
                "is_unlocked": False,
                "timeout_minutes": timeout_minutes,
                "elapsed_seconds": None,
                "remaining_seconds": None,
                "is_overdue": False,
            }

        now = datetime.now(timezone.utc)
        elapsed = int((now - unlocked_at).total_seconds())
        threshold = timeout_minutes * 60
        remaining = threshold - elapsed
        is_overdue = elapsed > threshold

        return {
            "is_unlocked": True,
            "timeout_minutes": timeout_minutes,
            "elapsed_seconds": elapsed,
            "remaining_seconds": max(0, remaining) if not is_overdue else None,
            "is_overdue": is_overdue,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Brute-force lockout
    # ──────────────────────────────────────────────────────────────────────

    def _check_lockout(self) -> None:
        config = self._load_config()
        lockout_str: Optional[str] = config.get("lockout_until")
        if not lockout_str:
            return
        lockout_dt = datetime.fromisoformat(lockout_str)
        now = datetime.now(timezone.utc)
        if now < lockout_dt:
            remaining = int((lockout_dt - now).total_seconds()) + 1
            raise AccountLockedError(remaining)
        # Lockout expired — clear it silently
        config["lockout_until"] = None
        config["failed_attempts"] = 0
        self._save_config(config)

    def _record_failure(self) -> Tuple[bool, int]:
        """Increment failed-attempt counter. Returns (is_locked_out, attempts_remaining)."""
        config = self._load_config()
        config["failed_attempts"] = config.get("failed_attempts", 0) + 1
        if config["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            until = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_SECONDS)
            config["lockout_until"] = until.isoformat()
            config["failed_attempts"] = 0
            self._save_config(config)
            return True, 0
        remaining = MAX_FAILED_ATTEMPTS - config["failed_attempts"]
        self._save_config(config)
        return False, remaining

    def _clear_failures(self) -> None:
        config = self._load_config()
        config["failed_attempts"] = 0
        config["lockout_until"] = None
        self._save_config(config)

    # ──────────────────────────────────────────────────────────────────────
    # Authentication & key retrieval
    # ──────────────────────────────────────────────────────────────────────

    def verify_pin_and_get_dek(self, pin: str) -> bytes:
        """
        Verify *pin* and return the DEK on success.

        Now integrated with AuditLog — records every attempt outcome.
        """
        self._check_lockout()
        config = self._load_config()
        audit = self.get_audit_log()

        pin_salt = _b64d(config["pin_salt"])
        stored_hash = _b64d(config["pin_hash"])

        if not verify_pin(pin, pin_salt, stored_hash):
            locked_out, remaining = self._record_failure()
            attempts_so_far = MAX_FAILED_ATTEMPTS - remaining
            audit.record_failed_auth(attempt_number=attempts_so_far)
            if locked_out:
                audit.record_lockout(LOCKOUT_SECONDS)
                raise AccountLockedError(LOCKOUT_SECONDS)
            plural = "s" if remaining != 1 else ""
            raise WrongPINError(
                f"Incorrect PIN. "
                f"{remaining} attempt{plural} remaining before temporary lockout."
            )

        self._clear_failures()
        audit.record_auth_success()

        kek_salt = _b64d(config["kek_salt"])
        enc_dek = _b64d(config["encrypted_dek"])
        kek = derive_kek_from_pin(pin, kek_salt)
        try:
            dek = decrypt_dek(enc_dek, kek)
        except Exception as exc:
            raise WrongPINError(
                "PIN accepted but DEK decryption failed — vault may be corrupted."
            ) from exc
        finally:
            clear_bytes(kek)
            del kek

        return dek

    def verify_recovery_key_and_get_dek(self, recovery_key: str) -> bytes:
        """Verify the recovery key and return the DEK."""
        config = self._load_config()

        rv_salt = _b64d(config["recovery_verify_salt"])
        stored_rv_hash = _b64d(config["recovery_key_hash"])

        if not verify_recovery_key(recovery_key, rv_salt, stored_rv_hash):
            raise InvalidRecoveryKeyError(
                "The recovery key you entered is incorrect."
            )

        r_kek_salt = _b64d(config["recovery_kek_salt"])
        r_enc_dek = _b64d(config["recovery_encrypted_dek"])
        r_kek = derive_kek_from_recovery(recovery_key, r_kek_salt)
        try:
            dek = decrypt_dek(r_enc_dek, r_kek)
        except Exception as exc:
            raise InvalidRecoveryKeyError(
                "Recovery key accepted but DEK decryption failed."
            ) from exc
        finally:
            clear_bytes(r_kek)
            del r_kek

        return dek

    def reset_pin(self, new_pin: str, dek: bytes) -> None:
        """
        Replace PIN and re-wrap DEK under new KEK.
        DEK itself (and all encrypted files) is unchanged.
        """
        config = self._load_config()

        new_pin_salt = os.urandom(32)
        new_kek_salt = os.urandom(32)

        new_kek = derive_kek_from_pin(new_pin, new_kek_salt)
        new_enc_dek = encrypt_dek(dek, new_kek)

        config["pin_salt"] = _b64e(new_pin_salt)
        config["pin_hash"] = _b64e(derive_pin_hash(new_pin, new_pin_salt))
        config["kek_salt"] = _b64e(new_kek_salt)
        config["encrypted_dek"] = _b64e(new_enc_dek)
        config["failed_attempts"] = 0
        config["lockout_until"] = None

        self._save_config(config)
        self.get_audit_log().record_reset_pin()

        clear_bytes(new_kek)
        del new_kek

    # ──────────────────────────────────────────────────────────────────────
    # Tracked paths
    # ──────────────────────────────────────────────────────────────────────

    def get_tracked_paths(self) -> List[str]:
        return list(self._load_config().get("tracked_paths", []))

    def add_tracked_path(self, rel_path: str) -> bool:
        """
        Add *rel_path* to the tracking list.
        Returns ``True`` if added, ``False`` if already present.
        """
        config = self._load_config()
        tracked: List[str] = config.get("tracked_paths", [])
        if rel_path in tracked:
            return False
        tracked.append(rel_path)
        config["tracked_paths"] = tracked
        self._save_config(config)
        self.get_audit_log().record_add_path(rel_path)
        return True

    def remove_tracked_path(self, rel_path: str) -> bool:
        """
        Remove *rel_path* and any sub-paths from the tracking list.
        Returns ``True`` if anything was removed, ``False`` if not found.
        """
        config = self._load_config()
        tracked: List[str] = config.get("tracked_paths", [])
        prefix = rel_path.rstrip("/") + "/"
        new_tracked = [
            p for p in tracked
            if p != rel_path and not p.startswith(prefix)
        ]
        if len(new_tracked) == len(tracked):
            return False  # nothing removed
        config["tracked_paths"] = new_tracked
        self._save_config(config)
        self.get_audit_log().record_untrack(rel_path)
        return True

    def path_is_tracked(self, rel_path: str) -> bool:
        """True when *rel_path* exactly matches a tracked entry."""
        return rel_path in self._load_config().get("tracked_paths", [])

    # ──────────────────────────────────────────────────────────────────────
    # Locked file records
    # ──────────────────────────────────────────────────────────────────────

    def get_locked_files(self) -> Dict:
        """Return a copy of the ``files`` dict (fresh from disk)."""
        return dict(self._load_config().get("files", {}))

    def has_locked_files(self) -> bool:
        return bool(self._load_config().get("files"))

    def add_file_record(
        self,
        vault_filename: str,
        original_path: str,
        original_size: int,
    ) -> None:
        config = self._load_config()
        files: Dict = config.get("files", {})
        files[vault_filename] = {
            "original_path": original_path,
            "original_name": Path(original_path).name,
            "size": original_size,
            "locked_at": datetime.now(timezone.utc).isoformat(),
        }
        config["files"] = files
        self._save_config(config)

    def remove_file_record(self, vault_filename: str) -> None:
        config = self._load_config()
        files: Dict = config.get("files", {})
        files.pop(vault_filename, None)
        config["files"] = files
        self._save_config(config)

    # ──────────────────────────────────────────────────────────────────────
    # Vault destruction
    # ──────────────────────────────────────────────────────────────────────

    def destroy(self) -> None:
        """Delete the entire ``.vortex`` directory tree."""
        if not self.vortex_path.exists():
            return
        if sys.platform == "win32":
            self._unhide_tree(self.vortex_path)
        shutil.rmtree(self.vortex_path)

    @staticmethod
    def _unhide_tree(root: Path) -> None:
        try:
            import ctypes
            NORMAL = 0x80
            ctypes.windll.kernel32.SetFileAttributesW(str(root), NORMAL)
            for item in root.rglob("*"):
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(item), NORMAL)
                except Exception:
                    pass
        except Exception:
            pass
