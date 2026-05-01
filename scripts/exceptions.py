"""Custom exception hierarchy for OpenWebGoggles.

Provides typed exceptions that tests can assert on precisely,
replacing bare RuntimeError / ValueError raises in the codebase.

Hierarchy:
    OWGError
    ├── SessionError        — webview server subprocess lifecycle failures
    │   └── LockError       — failed to acquire the session lock
    ├── StateValidationError — state/action payload validation failures
    │   └── MergeError      — _deep_merge rejected the payload
    ├── AssetError          — SDK / app asset not found
    └── AuthError           — authentication / token validation failures
"""

from __future__ import annotations


class OWGError(Exception):
    """Base exception for all OpenWebGoggles errors."""


class SessionError(OWGError):
    """Raised when a webview server subprocess fails to start, stop, or respond."""


class LockError(SessionError):
    """Raised when the session lock cannot be acquired (another instance running)."""


class StateValidationError(OWGError):
    """Raised when a state or action payload fails validation."""


class MergeError(StateValidationError):
    """Raised when _deep_merge rejects a payload (dangerous keys, depth exceeded)."""


class AssetError(OWGError):
    """Raised when a required asset file (SDK, app directory) cannot be found."""


class AuthError(OWGError):
    """Raised when authentication or token validation fails."""


class BinaryResolveError(OWGError):
    """Raised when the openwebgoggles binary cannot be located on disk.

    Used by init/repair flows: writing an unresolvable command into an MCP
    config produces silent ENOENT spam every time the host launches, so we
    refuse to write a config we know is broken and surface the problem
    instead.
    """
