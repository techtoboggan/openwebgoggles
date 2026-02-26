"""
Ephemeral cryptographic utilities for OpenWebGoggles session security.

Provides Ed25519 signing for server→browser messages and HMAC-SHA256
verification for browser→server messages. All key material is held
in process memory only and never written to disk.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
import time


def _lazy_nacl():
    """Import nacl on demand so the module can be imported even without PyNaCl."""
    try:
        import nacl.encoding
        import nacl.signing

        return nacl
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_session_keys() -> tuple[bytes, str, str]:
    """Generate an ephemeral Ed25519 keypair.

    Returns:
        (private_key_seed, public_key_hex, verify_key_hex)
        - private_key_seed: 32 bytes (the Ed25519 seed, kept in memory only)
        - public_key_hex: hex-encoded public key for injection into browser bootstrap
        - verify_key_hex: same as public_key_hex (Ed25519 verify key)
    """
    nacl = _lazy_nacl()
    if nacl is None:
        # Fallback: HMAC-only mode (no asymmetric signing)
        seed = os.urandom(32)
        hmac_key = hashlib.sha256(b"hmac-signing-key:" + seed).digest()
        verify_hex = hashlib.sha256(b"browser-verify-key:" + seed).hexdigest()
        return hmac_key, verify_hex, verify_hex

    signing_key = nacl.signing.SigningKey.generate()
    seed = bytes(signing_key)  # 32-byte seed
    verify_hex = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode("ascii")
    return seed, verify_hex, verify_hex


# ---------------------------------------------------------------------------
# Nonce generation
# ---------------------------------------------------------------------------

_NONCE_LOCK = threading.Lock()
_NONCE_COUNTER = 0


def generate_nonce() -> str:
    """Generate a unique nonce combining timestamp + random + counter.

    Format: hex(timestamp_ms || random_8_bytes || counter_8_bytes)
    This ensures uniqueness even under high-frequency calls.
    """
    global _NONCE_COUNTER
    with _NONCE_LOCK:
        _NONCE_COUNTER += 1
        ctr_val = _NONCE_COUNTER
    ts = struct.pack(">Q", int(time.time() * 1000))
    rand = os.urandom(8)
    ctr = struct.pack(">Q", ctr_val & 0xFFFFFFFFFFFFFFFF)
    return (ts + rand + ctr).hex()


# ---------------------------------------------------------------------------
# Message signing (server → browser)
# ---------------------------------------------------------------------------


def sign_message(private_key_seed: bytes, payload: str, nonce: str) -> str:
    """Sign a message using Ed25519.

    Args:
        private_key_seed: 32-byte Ed25519 seed
        payload: JSON string to sign
        nonce: unique nonce string

    Returns:
        Hex-encoded Ed25519 signature over (nonce + payload)
    """
    nacl = _lazy_nacl()
    message = (nonce + payload).encode("utf-8")

    if nacl is None:
        # Fallback: HMAC-SHA256
        sig = hmac.new(private_key_seed, message, hashlib.sha256).digest()
        return sig.hex()

    signing_key = nacl.signing.SigningKey(private_key_seed)
    signed = signing_key.sign(message)
    return signed.signature.hex()


# ---------------------------------------------------------------------------
# Message verification (browser → server, using HMAC with session token)
# ---------------------------------------------------------------------------


def verify_hmac(token: str, payload: str, nonce: str, signature_hex: str) -> bool:
    """Verify an HMAC-SHA256 signature from the browser.

    The browser signs messages with the session token as the HMAC key.

    Args:
        token: session token (shared secret)
        payload: JSON string
        nonce: nonce string
        signature_hex: hex-encoded HMAC-SHA256

    Returns:
        True if signature is valid
    """
    message = (nonce + payload).encode("utf-8")
    expected = hmac.new(token.encode("utf-8"), message, hashlib.sha256).digest()
    try:
        received = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    return hmac.compare_digest(expected, received)


# ---------------------------------------------------------------------------
# Nonce replay protection
# ---------------------------------------------------------------------------


class NonceTracker:
    """Tracks seen nonces to prevent replay attacks.

    Nonces older than `window_seconds` are automatically pruned.
    """

    MAX_NONCE_COUNT = 100_000

    def __init__(self, window_seconds: int = 300):
        self._seen: dict[str, float] = {}
        self._window = window_seconds

    def check_and_record(self, nonce: str) -> bool:
        """Returns True if the nonce is fresh (not seen before).
        Returns False if it's a replay."""
        now = time.time()
        self._prune(now)

        if nonce in self._seen:
            return False

        if len(self._seen) >= self.MAX_NONCE_COUNT:
            return False

        self._seen[nonce] = now
        return True

    def _prune(self, now: float) -> None:
        """Remove expired nonces."""
        cutoff = now - self._window
        expired = [n for n, t in self._seen.items() if t < cutoff]
        for n in expired:
            del self._seen[n]

    def clear(self) -> None:
        self._seen.clear()


# ---------------------------------------------------------------------------
# Key cleanup
# ---------------------------------------------------------------------------


def zero_key(key_bytes: bytes | bytearray) -> None:
    """Best-effort zeroing of key material in memory."""
    if isinstance(key_bytes, bytearray):
        for i in range(len(key_bytes)):
            key_bytes[i] = 0
        return
    try:
        import ctypes
        import sys

        if sys.implementation.name != "cpython":
            return
        ctypes.pythonapi.PyBytes_AsString.restype = ctypes.c_char_p
        ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
        ptr = ctypes.pythonapi.PyBytes_AsString(key_bytes)
        ctypes.memset(ptr, 0, len(key_bytes))
    except Exception:
        pass
