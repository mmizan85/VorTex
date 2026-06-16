"""
vortex/audit.py
───────────────
Persistent audit log for Vortex.

The log lives at ``.vortex/audit.json`` and records:
  • Failed authentication attempts (with timestamps)
  • Account lockout events
  • Successful logins
  • Lock / unlock operations
  • Path additions and removals

On every successful login the caller should:
    1. Call ``get_unseen_failures()`` to obtain the count + last timestamp.
    2. Display an alert to the user if count > 0.
    3. Call ``mark_failures_seen()`` to reset the unseen counter.

Audit data is NOT encrypted — it contains only metadata (event types,
timestamps) with no secret key material.  An attacker with filesystem access
can read it, but it reveals nothing about file contents.

Event types (string constants)
───────────────────────────────
  FAILED_AUTH   — wrong PIN attempt
  LOCKOUT       — account locked due to too many failures
  AUTH_SUCCESS  — correct PIN entered
  LOCK          — files locked (encrypted)
  UNLOCK        — files unlocked (decrypted)
  INIT          — vault initialised
  ADD_PATH      — tracked path added
  UNTRACK       — path removed from tracking
  RESET_PIN     — PIN successfully reset via recovery key
  PURGE         — vault purged
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .exceptions import AuditLogError

# ─────────────────────────────────────────────────────────────────────────────
# Event type constants
# ─────────────────────────────────────────────────────────────────────────────

FAILED_AUTH: str = "failed_auth"
LOCKOUT: str = "lockout"
AUTH_SUCCESS: str = "auth_success"
LOCK: str = "lock"
UNLOCK: str = "unlock"
INIT: str = "init"
ADD_PATH: str = "add_path"
UNTRACK: str = "untrack"
RESET_PIN: str = "reset_pin"
PURGE: str = "purge"

AUDIT_FILE: str = "audit.json"
MAX_EVENTS: int = 500          # rolling window; oldest events are pruned


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# AuditLog class
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog:
    """
    Read/write the audit log for a single vault.

    Parameters
    ----------
    vortex_path:
        Absolute path to the ``.vortex`` directory.
    """

    def __init__(self, vortex_path: Path) -> None:
        self.path: Path = vortex_path / AUDIT_FILE

    # ──────────────────────────────────────────────────────────────────────
    # Public recording API
    # ──────────────────────────────────────────────────────────────────────

    def record(
        self,
        event_type: str,
        message: str = "",
        details: Optional[Dict] = None,
    ) -> None:
        """
        Append one event to the audit log.

        Parameters
        ----------
        event_type:
            One of the module-level constants (e.g. ``FAILED_AUTH``).
        message:
            Short human-readable description.
        details:
            Optional dict of extra metadata (serialised as JSON).
        """
        try:
            data = self._load()
            event: Dict = {
                "type": event_type,
                "timestamp": _now_iso(),
                "message": message,
            }
            if details:
                event["details"] = details
            data["events"].append(event)

            # Track unseen failures for the login-alert feature
            if event_type == FAILED_AUTH:
                data["unseen_failures"] = data.get("unseen_failures", 0) + 1
                data["last_failure_ts"] = event["timestamp"]
            elif event_type == AUTH_SUCCESS:
                # Failures are marked seen AFTER the caller has read them
                pass

            # Prune oldest events to keep the file bounded
            if len(data["events"]) > MAX_EVENTS:
                data["events"] = data["events"][-MAX_EVENTS:]

            self._save(data)
        except AuditLogError:
            raise
        except Exception:
            pass  # audit log failures must never crash the tool

    def record_failed_auth(self, attempt_number: int = 0) -> None:
        """Shortcut: record a failed PIN attempt."""
        self.record(
            FAILED_AUTH,
            f"Wrong PIN entered (attempt {attempt_number})",
        )

    def record_lockout(self, duration_seconds: int) -> None:
        """Shortcut: record an account lockout."""
        self.record(
            LOCKOUT,
            f"Account locked for {duration_seconds}s after repeated failures.",
            {"duration_seconds": duration_seconds},
        )

    def record_auth_success(self) -> None:
        """Shortcut: record a successful authentication."""
        self.record(AUTH_SUCCESS, "Successful login.")

    def record_lock(self, file_count: int) -> None:
        """Shortcut: record a lock operation."""
        self.record(LOCK, f"{file_count} file(s) encrypted.", {"files": file_count})

    def record_unlock(self, file_count: int) -> None:
        """Shortcut: record an unlock operation."""
        self.record(UNLOCK, f"{file_count} file(s) decrypted.", {"files": file_count})

    def record_init(self) -> None:
        """Shortcut: record vault initialisation."""
        self.record(INIT, "Vault initialised.")

    def record_add_path(self, path: str) -> None:
        """Shortcut: record a tracked-path addition."""
        self.record(ADD_PATH, f"Path added to tracking: {path}", {"path": path})

    def record_untrack(self, path: str) -> None:
        """Shortcut: record an untrack operation."""
        self.record(UNTRACK, f"Path removed from tracking: {path}", {"path": path})

    def record_reset_pin(self) -> None:
        """Shortcut: record a PIN reset."""
        self.record(RESET_PIN, "PIN reset via recovery key.")

    def record_purge(self) -> None:
        """Shortcut: record a vault purge."""
        self.record(PURGE, "Vault purged and deleted.")

    # ──────────────────────────────────────────────────────────────────────
    # Query API
    # ──────────────────────────────────────────────────────────────────────

    def get_unseen_failures(self) -> Tuple[int, Optional[str]]:
        """
        Return ``(count, last_failure_timestamp_or_None)`` for failures that
        occurred since the last time they were displayed to the user.
        """
        try:
            data = self._load()
            count = data.get("unseen_failures", 0)
            last_ts = data.get("last_failure_ts")
            return count, last_ts
        except Exception:
            return 0, None

    def mark_failures_seen(self) -> None:
        """Reset the unseen-failure counter (call after showing the alert)."""
        try:
            data = self._load()
            data["unseen_failures"] = 0
            data.pop("last_failure_ts", None)
            self._save(data)
        except Exception:
            pass

    def get_recent_events(self, limit: int = 20) -> List[Dict]:
        """
        Return the *limit* most recent audit events, newest first.
        Returns an empty list on any error.
        """
        try:
            data = self._load()
            return list(reversed(data.get("events", [])[-limit:]))
        except Exception:
            return []

    def total_failed_auth_count(self) -> int:
        """Total failed authentication attempts ever recorded."""
        try:
            events = self._load().get("events", [])
            return sum(1 for e in events if e.get("type") == FAILED_AUTH)
        except Exception:
            return 0

    # ──────────────────────────────────────────────────────────────────────
    # Internal I/O
    # ──────────────────────────────────────────────────────────────────────

    def _load(self) -> Dict:
        """Load (or initialise) the audit log from disk."""
        if not self.path.exists():
            return {"version": "1.0", "events": [], "unseen_failures": 0}
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            # Return blank log rather than crashing; log corruption is non-fatal
            return {"version": "1.0", "events": [], "unseen_failures": 0}

    def _save(self, data: Dict) -> None:
        """Atomically write the audit log."""
        tmp = self.path.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            tmp.replace(self.path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise AuditLogError(f"Cannot save audit log: {exc}") from exc
