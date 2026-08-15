"""
crypto_backend.py

Secure File Encryption, Integrity Verification, and Cryptographic Performance
Analysis System using ASCON Lightweight Symmetric Cryptography.

NIST Lightweight Cryptography Standard (ASCON-128).
Compatible with IoT, embedded systems, and edge devices.

IMPORTANT:
This module contains ONLY the cryptographic / data-handling backend.
It is UNCHANGED from the original console implementation, aside from
removing the interactive input()/print() menu controller class, which
has been replaced by the Tkinter GUI in gui.py. Every class, method,
algorithm, file format, and metrics structure below is identical to
the original implementation.

Requirements:
    pip install ascon cryptography
"""

import os
import sys
import json
import time
import hashlib
import struct
import secrets
from datetime import datetime
from pathlib import Path

import ascon


# ─────────────────────────────────────────────
# DIRECTORY SETUP
# ─────────────────────────────────────────────

DIRS = {
    "keys":      Path("keys"),
    "encrypted": Path("encrypted"),
    "decrypted": Path("decrypted"),
    "hashes":    Path("hashes"),
    "metrics":   Path("metrics"),
}

for _dir in DIRS.values():
    _dir.mkdir(parents=True, exist_ok=True)

KEY_FILE     = DIRS["keys"] / "ascon.key"
METRICS_FILE = DIRS["metrics"] / "metrics_report.json"

# ASCON-128 constants
KEY_SIZE   = 16   # 128-bit
NONCE_SIZE = 16   # 128-bit
VARIANT    = "Ascon-128"

# Associated data used during AEAD (can be any context string)
ASSOCIATED_DATA = b"ASCON-SECURE-FILE-ENCRYPTION-SYSTEM-v1.0"


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def _separator(char="=", width=52):
    print(char * width)

def _banner(title):
    _separator()
    print(f"  {title}")
    _separator()

def _success(msg): print(f"  [OK]  {msg}")
def _info(msg):    print(f"  [..] {msg}")
def _warn(msg):    print(f"  [!!] {msg}")
def _error(msg):   print(f"  [XX] {msg}")

def _file_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


# ─────────────────────────────────────────────
# KEY MANAGER
# ─────────────────────────────────────────────

class KeyManager:
    """
    Manages the 128-bit ASCON secret key.
    Stores key as raw binary at keys/ascon.key.
    """

    def generate_secret_key(self) -> bytes:
        """Generate a new 128-bit ASCON secret key and save it."""
        key = secrets.token_bytes(KEY_SIZE)
        self.save_secret_key(key)
        return key

    def save_secret_key(self, key: bytes) -> None:
        """Persist key to disk as raw binary."""
        KEY_FILE.write_bytes(key)

    def load_secret_key(self) -> bytes:
        """Load key from disk; raise FileNotFoundError if missing."""
        if not KEY_FILE.exists():
            raise FileNotFoundError(
                "ASCON key not found. Please generate a key first (Option 1)."
            )
        key = KEY_FILE.read_bytes()
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key file is corrupted (expected {KEY_SIZE} bytes, "
                f"got {len(key)} bytes)."
            )
        return key


# ─────────────────────────────────────────────
# ENCRYPTION MODULE
# ─────────────────────────────────────────────

class AsconEncryptor:
    """
    Encrypts files using ASCON-128 Authenticated Encryption.

    Encrypted package layout (binary):
        [4 bytes: nonce_len][nonce][ciphertext+tag]

    Output: encrypted/<filename>.ascon
    """

    def __init__(self):
        self._km = KeyManager()

    def encrypt_file(self, filepath: str) -> dict:
        """
        Encrypt a file with ASCON-128.

        Returns a metrics dict.
        """
        src = Path(filepath)

        # ── Validation ──────────────────────────────
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src}")
        if not src.is_file():
            raise ValueError(f"Path is not a regular file: {src}")

        file_size = _file_size(src)
        _info(f"Encrypting: {src.name}  ({file_size:,} bytes)")

        t_start = time.perf_counter()

        # ── Load key & generate nonce ────────────────
        key   = self._km.load_secret_key()
        nonce = secrets.token_bytes(NONCE_SIZE)

        # ── Read plaintext ───────────────────────────
        plaintext = src.read_bytes()

        # ── ASCON-128 AEAD Encryption ────────────────
        ciphertext_with_tag = ascon.encrypt(
            key,
            nonce,
            ASSOCIATED_DATA,
            plaintext,
            variant=VARIANT,
        )

        # ── Package: [nonce_len(4B)] + [nonce] + [ciphertext+tag] ──
        package  = struct.pack(">I", NONCE_SIZE)
        package += nonce
        package += ciphertext_with_tag

        # ── Save ─────────────────────────────────────
        out_path = DIRS["encrypted"] / (src.name + ".ascon")
        out_path.write_bytes(package)

        elapsed = time.perf_counter() - t_start

        metrics = {
            "operation":   "ASCON Encryption",
            "algorithm":   VARIANT,
            "file":        src.name,
            "file_size":   file_size,
            "key_size":    KEY_SIZE * 8,   # bits
            "nonce_size":  NONCE_SIZE * 8, # bits
            "output_size": _file_size(out_path),
            "time_ms":     round(elapsed * 1000, 4),
            "timestamp":   datetime.now().isoformat(),
            "status":      "SUCCESS",
            "output_path": str(out_path),
        }
        _success(f"Encrypted → {out_path}")
        _info(f"Time: {metrics['time_ms']} ms  |  Key: {metrics['key_size']}-bit  |  Nonce: {metrics['nonce_size']}-bit")
        return metrics


# ─────────────────────────────────────────────
# DECRYPTION MODULE
# ─────────────────────────────────────────────

class AsconDecryptor:
    """
    Decrypts .ascon files and verifies the authentication tag.

    Output: decrypted/<original_filename>
    """

    def __init__(self):
        self._km = KeyManager()

    def decrypt_file(self, filepath: str) -> dict:
        """
        Decrypt an ASCON-128 encrypted file.

        Returns a metrics dict.
        """
        src = Path(filepath)

        if not src.exists():
            raise FileNotFoundError(f"Encrypted file not found: {src}")

        _info(f"Decrypting: {src.name}")
        t_start = time.perf_counter()

        # ── Load key ─────────────────────────────────
        key = self._km.load_secret_key()

        # ── Parse package ────────────────────────────
        package = src.read_bytes()
        if len(package) < 4 + NONCE_SIZE:
            raise ValueError("Encrypted package is too short / corrupted.")

        nonce_len = struct.unpack(">I", package[:4])[0]
        if nonce_len != NONCE_SIZE:
            raise ValueError(
                f"Invalid nonce length in package: {nonce_len} (expected {NONCE_SIZE})."
            )

        nonce              = package[4 : 4 + nonce_len]
        ciphertext_with_tag = package[4 + nonce_len :]

        # ── ASCON-128 Authenticated Decryption ───────
        plaintext = ascon.decrypt(
            key,
            nonce,
            ASSOCIATED_DATA,
            ciphertext_with_tag,
            variant=VARIANT,
        )

        if plaintext is None:
            raise ValueError(
                "Authentication tag verification FAILED.\n"
                "  The file may be corrupted, tampered, or the wrong key was used."
            )

        # ── Recover original filename ─────────────────
        original_name = src.stem  # removes .ascon
        out_path = DIRS["decrypted"] / original_name
        out_path.write_bytes(plaintext)

        elapsed = time.perf_counter() - t_start

        metrics = {
            "operation": "ASCON Decryption",
            "algorithm": VARIANT,
            "file":      src.name,
            "file_size": _file_size(src),
            "time_ms":   round(elapsed * 1000, 4),
            "timestamp": datetime.now().isoformat(),
            "status":    "SUCCESS",
            "output_path": str(out_path),
        }
        _success(f"Decrypted  → {out_path}  ({len(plaintext):,} bytes recovered)")
        _info(f"Auth tag:  VERIFIED ✓  |  Time: {metrics['time_ms']} ms")
        return metrics


# ─────────────────────────────────────────────
# HASHING MODULE
# ─────────────────────────────────────────────

class Hasher:
    """
    SHA-256 hash generation and verification.
    Reads files in chunks to support large files.

    Hash files stored at: hashes/<filename>.hash
    """

    CHUNK_SIZE = 65536  # 64 KB

    def _compute_sha256(self, path: Path) -> str:
        """Compute SHA-256 digest of a file via chunked reading."""
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(self.CHUNK_SIZE):
                digest.update(chunk)
        return digest.hexdigest()

    def generate_hash(self, filepath: str) -> dict:
        """Generate and save SHA-256 hash of a file."""
        src = Path(filepath)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {src}")

        _info(f"Hashing: {src.name}")
        t_start = time.perf_counter()

        hex_digest = self._compute_sha256(src)

        hash_path = DIRS["hashes"] / (src.name + ".hash")
        hash_path.write_text(hex_digest)

        elapsed = time.perf_counter() - t_start

        metrics = {
            "operation": "Hash Generation",
            "algorithm": "SHA-256",
            "file":      src.name,
            "file_size": _file_size(src),
            "hash":      hex_digest,
            "time_ms":   round(elapsed * 1000, 4),
            "timestamp": datetime.now().isoformat(),
            "status":    "SUCCESS",
            "output_path": str(hash_path),
        }
        _success(f"SHA-256: {hex_digest}")
        _success(f"Saved   → {hash_path}")
        return metrics

    def verify_hash(self, filepath: str) -> dict:
        """Verify a file against its stored .hash file."""
        src = Path(filepath)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {src}")

        hash_path = DIRS["hashes"] / (src.name + ".hash")
        if not hash_path.exists():
            raise FileNotFoundError(
                f"Hash file not found: {hash_path}\n"
                "  Generate a hash first (Option 4)."
            )

        _info(f"Verifying hash for: {src.name}")
        t_start = time.perf_counter()

        stored_hash  = hash_path.read_text().strip()
        current_hash = self._compute_sha256(src)

        elapsed  = time.perf_counter() - t_start
        is_valid = secrets.compare_digest(stored_hash, current_hash)
        status   = "VALID" if is_valid else "TAMPERED"

        metrics = {
            "operation":    "Hash Verification",
            "algorithm":    "SHA-256",
            "file":         src.name,
            "file_size":    _file_size(src),
            "stored_hash":  stored_hash,
            "current_hash": current_hash,
            "time_ms":      round(elapsed * 1000, 4),
            "timestamp":    datetime.now().isoformat(),
            "status":       status,
        }

        if is_valid:
            _success(f"Hash VALID — file integrity confirmed ✓")
        else:
            _warn(f"Hash MISMATCH — file may be TAMPERED!")
            _warn(f"  Stored : {stored_hash}")
            _warn(f"  Current: {current_hash}")
        return metrics


# ─────────────────────────────────────────────
# INTEGRITY VERIFIER
# ─────────────────────────────────────────────

class IntegrityVerifier:
    """
    SHA-256-based file integrity verification.

    Compares the stored hash against the current file digest.
    Reports: VALID | INVALID | TAMPERED
    """

    def __init__(self):
        self._hasher = Hasher()

    def compare_hashes(self, stored: str, current: str) -> str:
        """Return VALID or TAMPERED based on constant-time comparison."""
        return "VALID" if secrets.compare_digest(stored.lower(), current.lower()) else "TAMPERED"

    def verify_file_integrity(self, filepath: str) -> dict:
        """
        Full integrity check pipeline:
        1. Compute current SHA-256 of file.
        2. Load stored .hash file.
        3. Compare digests.
        4. Report result.
        """
        src = Path(filepath)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {src}")

        hash_path = DIRS["hashes"] / (src.name + ".hash")
        if not hash_path.exists():
            raise FileNotFoundError(
                f"No stored hash found for '{src.name}'.\n"
                "  Generate a hash first (Option 4)."
            )

        _info(f"Integrity check: {src.name}")
        t_start = time.perf_counter()

        stored_hash  = hash_path.read_text().strip()
        current_hash = self._hasher._compute_sha256(src)
        result       = self.compare_hashes(stored_hash, current_hash)

        elapsed = time.perf_counter() - t_start

        metrics = {
            "operation":    "Integrity Verification",
            "algorithm":    "SHA-256",
            "file":         src.name,
            "file_size":    _file_size(src),
            "stored_hash":  stored_hash,
            "current_hash": current_hash,
            "result":       result,
            "time_ms":      round(elapsed * 1000, 4),
            "timestamp":    datetime.now().isoformat(),
            "status":       result,
        }

        _separator("-", 52)
        print(f"  File       : {src.name}")
        print(f"  Stored Hash: {stored_hash[:32]}...")
        print(f"  Current    : {current_hash[:32]}...")
        print(f"  Result     : {result}")
        _separator("-", 52)

        if result == "VALID":
            _success("File integrity VERIFIED — no tampering detected ✓")
        else:
            _warn("INTEGRITY FAILURE — file appears to be TAMPERED!")

        return metrics


# ─────────────────────────────────────────────
# PERFORMANCE METRICS ANALYZER
# ─────────────────────────────────────────────

class CryptographicMetricsAnalyzer:
    """
    Records and reports performance metrics for all cryptographic operations.

    Persists to: metrics/metrics_report.json
    """

    def __init__(self):
        self._records: list[dict] = []
        self._load()

    def _load(self):
        if METRICS_FILE.exists():
            try:
                self._records = json.loads(METRICS_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                self._records = []

    def record(self, metrics: dict):
        """Append a metrics entry and persist."""
        self._records.append(metrics)
        self._save()

    def _save(self):
        METRICS_FILE.write_text(
            json.dumps(self._records, indent=2, ensure_ascii=False)
        )

    def view_report(self):
        """Print a formatted summary of all recorded operations."""
        _banner("CRYPTOGRAPHIC PERFORMANCE REPORT")
        if not self._records:
            _info("No metrics recorded yet.")
            return

        print(f"  Total Operations: {len(self._records)}\n")
        for i, rec in enumerate(self._records, 1):
            print(f"  [{i:03d}] {rec.get('operation', 'N/A')}")
            print(f"         Algorithm : {rec.get('algorithm', 'N/A')}")
            if "file" in rec:
                print(f"         File      : {rec['file']}")
            if "file_size" in rec:
                print(f"         File Size : {rec['file_size']:,} bytes")
            if "key_size" in rec:
                print(f"         Key Size  : {rec['key_size']} bits")
            print(f"         Time      : {rec.get('time_ms', 'N/A')} ms")
            print(f"         Status    : {rec.get('status', 'N/A')}")
            print(f"         Timestamp : {rec.get('timestamp', 'N/A')}")
            if "result" in rec:
                print(f"         Result    : {rec.get('result', 'N/A')}")
            if "hash" in rec:
                print(f"         SHA-256   : {rec['hash'][:32]}...")
            print()

    def export_report(self, export_path: str | None = None) -> Path:
        """Export full JSON report to a user-specified or default path."""
        dest = Path(export_path) if export_path else METRICS_FILE
        dest.write_text(
            json.dumps(self._records, indent=2, ensure_ascii=False)
        )
        _success(f"Metrics report exported → {dest}")
        return dest

    def clear(self):
        self._records = []
        self._save()
