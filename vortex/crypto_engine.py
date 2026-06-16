"""
vortex/crypto_engine.py
───────────────────────
All cryptographic primitives used by Vortex.

Encryption scheme
─────────────────
  Cipher         : AES-256-GCM  (authenticated, nonce-based)
  Key derivation : PBKDF2-HMAC-SHA-256, 480 000 iterations (OWASP 2023)
  Key hierarchy  :
      PIN  ──PBKDF2──▶  KEK  ──AES-GCM──▶  DEK  (stored encrypted in config)
      DEK  ──AES-GCM──▶  file ciphertext

Binary file format (.vtx)
────────────────────────────────────────────────────────────────────────
 Offset  Size   Field
 ──────  ─────  ──────────────────────────────────────────────────────
 0       4      Magic bytes  b"VRTX"
 4       1      Version      0x02
 5       8      Original file size (uint64, big-endian)
 13      …      Repeated chunks:
                  12  Random nonce (AES-GCM 96-bit)
                   4  Ciphertext length + 16-byte tag (uint32 BE)
                   N  Ciphertext + authentication tag

AAD per chunk: ``b"<file_uuid>:<chunk_index>"`` — binds every chunk to its
file and position, preventing chunk-swap / cross-file attacks.
"""

from __future__ import annotations

import os
import secrets
import struct
import uuid as _uuid_mod
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import FileDecryptionError, FileEncryptionError

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_SIZE: int = 65_536           # 64 KiB per encryption chunk
MAGIC: bytes = b"VRTX"
FILE_VERSION: bytes = b"\x02"     # v2 format
PBKDF2_ITERATIONS: int = 480_000  # OWASP 2023
KEY_LENGTH: int = 32              # AES-256 → 32-byte key
NONCE_LENGTH: int = 12            # AES-GCM recommended nonce size
TAG_LENGTH: int = 16              # AES-GCM authentication tag
HEADER_SIZE: int = len(MAGIC) + len(FILE_VERSION) + 8  # 13 bytes total

# Alphabet excludes visually ambiguous characters (0/O, 1/I/l)
_RECOVERY_ALPHABET: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


# ─────────────────────────────────────────────────────────────────────────────
# Key derivation
# ─────────────────────────────────────────────────────────────────────────────

def _pbkdf2(material: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 32-byte key from *material* and *salt* via PBKDF2-HMAC-SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(material.encode("utf-8"))


def derive_pin_hash(pin: str, salt: bytes) -> bytes:
    """Derive a verification hash for *pin* (domain-separated)."""
    return _pbkdf2(f"vortex:pin_verify:v1:{pin}", salt)


def verify_pin(pin: str, salt: bytes, stored_hash: bytes) -> bool:
    """Constant-time comparison of derived hash against *stored_hash*."""
    return secrets.compare_digest(derive_pin_hash(pin, salt), stored_hash)


def derive_kek_from_pin(pin: str, kek_salt: bytes) -> bytes:
    """Derive a Key Encryption Key from *pin*."""
    return _pbkdf2(f"vortex:kek:v1:{pin}", kek_salt)


def derive_kek_from_recovery(recovery_key: str, recovery_salt: bytes) -> bytes:
    """Derive a Key Encryption Key from the recovery key."""
    return _pbkdf2(f"vortex:recovery_kek:v1:{recovery_key}", recovery_salt)


def derive_recovery_verify_hash(recovery_key: str, salt: bytes) -> bytes:
    """Derive a verification hash for the recovery key."""
    return _pbkdf2(f"vortex:recovery_verify:v1:{recovery_key}", salt)


def verify_recovery_key(recovery_key: str, salt: bytes, stored_hash: bytes) -> bool:
    """Constant-time comparison for the recovery key."""
    return secrets.compare_digest(
        derive_recovery_verify_hash(recovery_key, salt), stored_hash
    )


# ─────────────────────────────────────────────────────────────────────────────
# DEK management
# ─────────────────────────────────────────────────────────────────────────────

def generate_dek() -> bytes:
    """Generate a cryptographically random 32-byte Data Encryption Key."""
    return os.urandom(KEY_LENGTH)


def generate_recovery_key() -> str:
    """Return a cryptographically random 16-character recovery key."""
    return "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(16))


def encrypt_dek(dek: bytes, kek: bytes) -> bytes:
    """
    Encrypt *dek* with *kek* using AES-256-GCM.
    Returns ``nonce (12 B) || ciphertext+tag (48 B)`` = 60 bytes.
    """
    nonce = os.urandom(NONCE_LENGTH)
    ct = AESGCM(kek).encrypt(nonce, dek, b"vortex:dek_wrap:v1")
    return nonce + ct


def decrypt_dek(blob: bytes, kek: bytes) -> bytes:
    """
    Decrypt a DEK blob from :func:`encrypt_dek`.
    Raises ``ValueError`` on authentication failure.
    """
    if len(blob) < NONCE_LENGTH + TAG_LENGTH + KEY_LENGTH:
        raise ValueError("DEK blob is too short.")
    return AESGCM(kek).decrypt(blob[:NONCE_LENGTH], blob[NONCE_LENGTH:], b"vortex:dek_wrap:v1")


# ─────────────────────────────────────────────────────────────────────────────
# File encryption
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file(source: Path, dest: Path, dek: bytes, file_uuid: str) -> int:
    """
    Encrypt *source* to *dest* in 64 KiB AES-256-GCM chunks.

    Atomic guarantee: writes to a unique ``.tmp`` file first, then renames to
    *dest* only on 100% success.  The ``.tmp`` is deleted on any error.

    Returns the number of chunks written.
    """
    aesgcm = AESGCM(dek)
    tmp = dest.parent / f".venc_{_uuid_mod.uuid4().hex}.tmp"

    try:
        original_size = source.stat().st_size

        with open(source, "rb") as src_fh, open(tmp, "wb") as dst_fh:
            # Write 13-byte header
            dst_fh.write(MAGIC)
            dst_fh.write(FILE_VERSION)
            dst_fh.write(struct.pack(">Q", original_size))

            chunk_index = 0
            while True:
                chunk = src_fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = os.urandom(NONCE_LENGTH)
                aad = f"{file_uuid}:{chunk_index}".encode("ascii")
                ciphertext = aesgcm.encrypt(nonce, chunk, aad)
                dst_fh.write(nonce)
                dst_fh.write(struct.pack(">I", len(ciphertext)))
                dst_fh.write(ciphertext)
                chunk_index += 1

            dst_fh.flush()
            try:
                os.fsync(dst_fh.fileno())
            except OSError:
                pass

        tmp.replace(dest)          # atomic rename — only runs on full success
        return chunk_index

    except FileEncryptionError:
        raise
    except Exception as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise FileEncryptionError(
            f"Encryption failed for '{source.name}': {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────────────────────
# File decryption
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_file(source: Path, dest: Path, dek: bytes, file_uuid: str) -> int:
    """
    Decrypt a Vortex-encrypted *source* back to *dest*.

    Atomic guarantee: decrypts to a ``.tmp`` file, verifies reconstructed
    size, then renames to *dest*.  The ``.tmp`` is deleted on any error.
    *dest* is never created if decryption is not fully successful.

    Returns the number of chunks decrypted.
    """
    aesgcm = AESGCM(dek)
    tmp = dest.parent / f".vdec_{_uuid_mod.uuid4().hex}.tmp"

    try:
        with open(source, "rb") as src_fh, open(tmp, "wb") as dst_fh:

            # ── Validate header ─────────────────────────────────────────
            magic = src_fh.read(4)
            if magic != MAGIC:
                raise ValueError(f"Bad magic bytes {magic!r} — not a Vortex file.")

            version = src_fh.read(1)
            if version not in (FILE_VERSION, b"\x01"):   # accept v1 and v2 files
                raise ValueError(
                    f"Unsupported file version 0x{version.hex()} "
                    f"(expected 0x{FILE_VERSION.hex()})."
                )

            raw_size = src_fh.read(8)
            if len(raw_size) != 8:
                raise ValueError("Header truncated: missing original-size field.")
            (original_size,) = struct.unpack(">Q", raw_size)

            # ── Decrypt chunks ──────────────────────────────────────────
            chunk_index = 0
            bytes_written = 0

            while True:
                nonce_data = src_fh.read(NONCE_LENGTH)
                if not nonce_data:
                    break                                  # clean EOF
                if len(nonce_data) < NONCE_LENGTH:
                    raise ValueError(
                        f"Chunk {chunk_index}: nonce truncated "
                        f"(got {len(nonce_data)} B)."
                    )

                len_buf = src_fh.read(4)
                if len(len_buf) < 4:
                    raise ValueError(
                        f"Chunk {chunk_index}: length field truncated."
                    )
                (ct_len,) = struct.unpack(">I", len_buf)

                ciphertext = src_fh.read(ct_len)
                if len(ciphertext) < ct_len:
                    raise ValueError(
                        f"Chunk {chunk_index}: ciphertext truncated "
                        f"(got {len(ciphertext)} B, expected {ct_len})."
                    )

                aad = f"{file_uuid}:{chunk_index}".encode("ascii")
                try:
                    plaintext = aesgcm.decrypt(nonce_data, ciphertext, aad)
                except InvalidTag:
                    raise ValueError(
                        f"Chunk {chunk_index}: GCM authentication failed — "
                        "wrong key, wrong UUID, or tampered data."
                    )

                dst_fh.write(plaintext)
                bytes_written += len(plaintext)
                chunk_index += 1

            dst_fh.flush()
            try:
                os.fsync(dst_fh.fileno())
            except OSError:
                pass

        # ── Size integrity check BEFORE atomic rename ────────────────────
        # BUG FIX: dest is never created if sizes don't match — the old code
        # could leave a zero-byte dest if tmp.replace() ran before the check.
        if bytes_written != original_size:
            tmp.unlink(missing_ok=True)
            raise ValueError(
                f"Size mismatch after decryption: "
                f"expected {original_size} B, got {bytes_written} B."
            )

        tmp.replace(dest)          # atomic rename — only on verified success
        return chunk_index

    except FileDecryptionError:
        raise
    except Exception as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise FileDecryptionError(
            f"Decryption failed for '{source.name}': {exc}"
        ) from exc
