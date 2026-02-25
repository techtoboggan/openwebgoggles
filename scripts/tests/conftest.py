"""
Shared fixtures for the openwebgoggles security test suite.
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure the scripts directory and tests directory are on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    NonceTracker,
    generate_session_keys,
)
from security_gate import SecurityGate


@pytest.fixture
def gate():
    """Fresh SecurityGate instance."""
    return SecurityGate()


@pytest.fixture
def session_keys():
    """Ephemeral Ed25519 session keypair."""
    private_key, public_hex, verify_hex = generate_session_keys()
    return private_key, public_hex, verify_hex


@pytest.fixture
def nonce_tracker():
    """Fresh NonceTracker with default 300s window."""
    return NonceTracker(window_seconds=300)


@pytest.fixture
def session_token():
    """Random 32-byte hex session token."""
    return os.urandom(32).hex()
