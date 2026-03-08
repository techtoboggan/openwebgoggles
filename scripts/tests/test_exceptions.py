"""Tests for custom exception hierarchy (exceptions.py) and their usage in session.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

# Ensure scripts/ on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exceptions import (
    AssetError,
    AuthError,
    LockError,
    MergeError,
    OWGError,
    SessionError,
    StateValidationError,
)
from session import MAX_MERGE_DEPTH, _deep_merge


# ---------------------------------------------------------------------------
# Hierarchy assertions
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_owg_error_is_exception(self):
        assert issubclass(OWGError, Exception)

    def test_session_error_is_owg_error(self):
        assert issubclass(SessionError, OWGError)

    def test_lock_error_is_session_error(self):
        assert issubclass(LockError, SessionError)

    def test_state_validation_error_is_owg_error(self):
        assert issubclass(StateValidationError, OWGError)

    def test_merge_error_is_state_validation_error(self):
        assert issubclass(MergeError, StateValidationError)

    def test_asset_error_is_owg_error(self):
        assert issubclass(AssetError, OWGError)

    def test_auth_error_is_owg_error(self):
        assert issubclass(AuthError, OWGError)

    def test_lock_error_is_also_owg_error(self):
        """LockError must satisfy isinstance(e, OWGError) via chain."""
        assert issubclass(LockError, OWGError)

    def test_merge_error_is_also_owg_error(self):
        assert issubclass(MergeError, OWGError)

    def test_exceptions_are_instantiable(self):
        for cls in (OWGError, SessionError, LockError, StateValidationError, MergeError, AssetError, AuthError):
            exc = cls("test message")
            assert str(exc) == "test message"


# ---------------------------------------------------------------------------
# _deep_merge raises MergeError (not bare ValueError)
# ---------------------------------------------------------------------------


class TestDeepMergeRaisesMergeError:
    def test_depth_exceeded_raises_merge_error(self):
        """Exceeding MAX_MERGE_DEPTH must raise MergeError, not ValueError."""
        base: dict = {}
        override: dict = {}
        with pytest.raises(MergeError, match="Merge depth exceeds maximum"):
            _deep_merge(base, override, _depth=MAX_MERGE_DEPTH + 1)

    def test_depth_exceeded_is_state_validation_error(self):
        """MergeError should satisfy isinstance checks on StateValidationError."""
        with pytest.raises(StateValidationError):
            _deep_merge({}, {}, _depth=MAX_MERGE_DEPTH + 1)

    def test_dangerous_key_proto_raises_merge_error(self):
        with pytest.raises(MergeError, match="dangerous key '__proto__'"):
            _deep_merge({}, {"__proto__": {"evil": True}})

    def test_dangerous_key_constructor_raises_merge_error(self):
        with pytest.raises(MergeError, match="dangerous key 'constructor'"):
            _deep_merge({}, {"constructor": "x"})

    def test_dangerous_key_prototype_raises_merge_error(self):
        with pytest.raises(MergeError, match="dangerous key 'prototype'"):
            _deep_merge({}, {"prototype": {}})

    def test_safe_merge_succeeds(self):
        base = {"a": 1, "b": {"c": 2}}
        _deep_merge(base, {"b": {"d": 3}})
        assert base == {"a": 1, "b": {"c": 2, "d": 3}}


# ---------------------------------------------------------------------------
# WebviewSession raises typed exceptions
# ---------------------------------------------------------------------------


class TestWebviewSessionExceptions:
    """Assert that WebviewSession raises the typed exception subclasses."""

    def _make_session(self, tmp_path: Path):
        from session import WebviewSession

        return WebviewSession(work_dir=tmp_path, open_browser=False)

    def test_find_free_ports_raises_session_error(self, tmp_path):
        """When all ports are busy, _find_free_ports must raise SessionError."""
        session = self._make_session(tmp_path)
        with mock.patch.object(session, "_port_available", return_value=False):
            with pytest.raises(SessionError, match="Could not find free ports"):
                session._find_free_ports()

    def test_find_free_ports_is_owg_error(self, tmp_path):
        session = self._make_session(tmp_path)
        with mock.patch.object(session, "_port_available", return_value=False):
            with pytest.raises(OWGError):
                session._find_free_ports()

    def test_find_assets_dir_raises_asset_error(self, tmp_path):
        """When assets/ cannot be found, _find_assets_dir must raise AssetError."""
        session = self._make_session(tmp_path)
        # _find_assets_dir prefers mcp_server.__file__; patch both so neither
        # resolves to a real assets/ directory
        fake_file = str(tmp_path / "fake" / "session.py")
        modules_patch = dict(sys.modules)
        modules_patch.pop("mcp_server", None)
        with mock.patch("session.__file__", fake_file):
            with mock.patch.dict("sys.modules", {"mcp_server": None}):  # type: ignore[dict-item]
                with pytest.raises(AssetError, match="Cannot find assets directory"):
                    session._find_assets_dir()

    def test_copy_app_absolute_path_raises_asset_error(self, tmp_path):
        session = self._make_session(tmp_path)
        with pytest.raises(AssetError, match="not found"):
            session._copy_app("/absolute/path")

    def test_copy_app_dotdot_raises_asset_error(self, tmp_path):
        session = self._make_session(tmp_path)
        with pytest.raises(AssetError, match="not found"):
            session._copy_app("../escape")

    def test_copy_app_leading_dot_raises_asset_error(self, tmp_path):
        session = self._make_session(tmp_path)
        with pytest.raises(AssetError, match="not found"):
            session._copy_app(".hidden")

    def test_copy_app_unknown_app_raises_asset_error(self, tmp_path):
        session = self._make_session(tmp_path)
        assets_mock = tmp_path / "assets"
        (assets_mock / "apps").mkdir(parents=True)
        with mock.patch.object(session, "_find_assets_dir", return_value=assets_mock):
            with pytest.raises(AssetError, match="not found"):
                session._copy_app("nonexistent_app")

    def test_acquire_lock_raises_lock_error(self, tmp_path):
        """When lock cannot be acquired after retries, must raise LockError."""

        session = self._make_session(tmp_path)
        session.data_dir = tmp_path
        # Simulate persistent lock contention: flock always raises
        with mock.patch("fcntl.flock", side_effect=OSError("locked")):
            with mock.patch.object(session, "_kill_stale_server"):
                with pytest.raises(LockError, match="Cannot acquire webview lock"):
                    session._acquire_lock()

    def test_lock_error_is_session_error(self, tmp_path):
        """LockError must satisfy isinstance checks for SessionError."""

        session = self._make_session(tmp_path)
        session.data_dir = tmp_path
        with mock.patch("fcntl.flock", side_effect=OSError("locked")):
            with mock.patch.object(session, "_kill_stale_server"):
                with pytest.raises(SessionError):
                    session._acquire_lock()
