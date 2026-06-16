"""
vortex/exceptions.py
────────────────────
Typed exception hierarchy for Vortex v2.
Every exception carries a clear, user-facing message and inherits
from VortexError so callers can catch the entire family with one clause.
"""


class VortexError(Exception):
    """Base class for every Vortex exception."""


class VaultNotInitializedError(VortexError):
    """Operation requires an initialised vault; none was found."""


class VaultAlreadyInitializedError(VortexError):
    """A vault already exists in the target directory."""


class WrongPINError(VortexError):
    """The supplied PIN did not match the stored hash."""


class AccountLockedError(VortexError):
    """Too many failed attempts; the account is temporarily locked."""

    def __init__(self, remaining_seconds: int) -> None:
        self.remaining_seconds = remaining_seconds
        super().__init__(
            f"Account locked. Try again in {remaining_seconds} second(s)."
        )


class InvalidRecoveryKeyError(VortexError):
    """The supplied recovery key is incorrect or does not match."""


class CorruptedVaultError(VortexError):
    """Vault configuration is missing, unreadable, or structurally invalid."""


class InvalidPINFormatError(VortexError):
    """PIN does not meet the 4-8 digit requirement."""


class FileEncryptionError(VortexError):
    """A file could not be encrypted."""


class FileDecryptionError(VortexError):
    """A file could not be decrypted (wrong key, truncation, or tampering)."""


class AuditLogError(VortexError):
    """The audit log could not be read or written."""


class PathNotTrackedError(VortexError):
    """The requested path is not in the vault's tracking list."""


class AutoLockError(VortexError):
    """Auto-lock operation failed."""
