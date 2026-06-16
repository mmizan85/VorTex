"""
vortex/security.py
──────────────────
PIN validation, recovery-key formatting, and best-effort memory clearing.

Memory safety note
──────────────────
Python's immutable ``bytes`` objects cannot be reliably zeroed because the
interpreter manages their memory internally.  ``clear_bytes`` makes a
best-effort attempt on CPython via ctypes and is always paired with an
immediate ``del`` of the reference.  For genuinely high-assurance use,
consider a language with explicit ownership semantics.
"""

from __future__ import annotations

import ctypes
import re
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

PIN_MIN_LENGTH: int = 4
PIN_MAX_LENGTH: int = 8
MAX_FAILED_ATTEMPTS: int = 3
LOCKOUT_SECONDS: int = 30


# ─────────────────────────────────────────────────────────────────────────────
# PIN validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_pin(pin: str) -> Optional[str]:
    """
    Validate the PIN format.

    Returns ``None`` when valid; a human-readable error string otherwise.
    """
    if not pin:
        return "PIN cannot be empty."
    if not pin.isdigit():
        return "PIN must contain digits only (0–9)."
    if len(pin) < PIN_MIN_LENGTH:
        return (
            f"PIN is too short — got {len(pin)} digit(s), "
            f"minimum is {PIN_MIN_LENGTH}."
        )
    if len(pin) > PIN_MAX_LENGTH:
        return (
            f"PIN is too long — got {len(pin)} digit(s), "
            f"maximum is {PIN_MAX_LENGTH}."
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Recovery key helpers
# ─────────────────────────────────────────────────────────────────────────────

def format_recovery_key(raw: str) -> str:
    """Format a 16-char raw key as ``XXXX-XXXX-XXXX-XXXX``."""
    clean = re.sub(r"[-\s]", "", raw).upper()
    if len(clean) == 16:
        return "-".join(clean[i: i + 4] for i in range(0, 16, 4))
    return clean


def normalize_recovery_key(raw: str) -> str:
    """Strip dashes/spaces and upper-case the recovery key."""
    return re.sub(r"[-\s]", "", raw).upper()


# ─────────────────────────────────────────────────────────────────────────────
# Memory safety
# ─────────────────────────────────────────────────────────────────────────────

def clear_bytes(data: bytes) -> None:
    """
    Best-effort overwrite of a ``bytes`` object's internal buffer on CPython.
    Always follow with ``del var``.
    """
    try:
        length = len(data)
        if length == 0:
            return
        buf = (ctypes.c_char * length).from_address(id(data) + 33)
        ctypes.memset(buf, 0, length)
    except Exception:
        pass


def clear_bytearray(data: bytearray) -> None:
    """Zero a mutable bytearray in-place (reliable on all implementations)."""
    for i in range(len(data)):
        data[i] = 0
