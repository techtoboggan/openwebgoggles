"""
Tests for SessionArchive (data_contract.py) — session persistence.

Covers: save, list, get, delete, retention enforcement, path traversal prevention.
"""

from __future__ import annotations

import os
import sys
import time
import uuid

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_contract import MAX_PERSISTED_SESSIONS, SessionArchive, _validate_session_id


def _uuid() -> str:
    """Generate a fresh UUID string for test session IDs."""
    return str(uuid.uuid4())


# ═══════════════════════════════════════════════════════════════════════════════
# 1. BASIC SAVE / GET
# ═══════════════════════════════════════════════════════════════════════════════


class TestSaveAndGet:
    def test_save_creates_file(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        path = archive.save(sid, state={"title": "Test"})
        assert path.is_file()
        assert path.name == f"{sid}.json"

    def test_get_returns_saved_data(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={"title": "Hello"}, actions=[{"id": "ok"}])
        result = archive.get(sid)
        assert result is not None
        assert result["session_id"] == sid
        assert result["state"]["title"] == "Hello"
        assert len(result["actions"]) == 1

    def test_get_missing_returns_none(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert archive.get(_uuid()) is None

    def test_save_with_title(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={}, title="My Session")
        result = archive.get(sid)
        assert result["title"] == "My Session"

    def test_save_infers_title_from_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={"title": "From State"})
        result = archive.get(sid)
        assert result["title"] == "From State"

    def test_save_default_title(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={})
        result = archive.get(sid)
        assert result["title"] == "Untitled"

    def test_save_with_mode(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={}, mode="app")
        result = archive.get(sid)
        assert result["mode"] == "app"

    def test_save_timestamps(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={})
        result = archive.get(sid)
        assert "saved_at" in result
        assert "created_at" in result
        # Timestamps should be ISO format
        assert "T" in result["saved_at"]

    def test_save_file_permissions(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        path = archive.save(sid, state={})
        # Should be 0o600 (owner read/write only)
        perms = oct(path.stat().st_mode & 0o777)
        assert perms == "0o600"

    def test_save_overwrites_existing(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={"v": 1})
        archive.save(sid, state={"v": 2})
        result = archive.get(sid)
        assert result["state"]["v"] == 2


# ═══════════════════════════════════════════════════════════════════════════════
# 2. LIST SESSIONS
# ═══════════════════════════════════════════════════════════════════════════════


class TestListSessions:
    def test_list_empty(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert archive.list_sessions() == []

    def test_list_returns_metadata(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={"title": "Alpha"}, mode="browser")
        sessions = archive.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == sid
        assert sessions[0]["title"] == "Alpha"
        assert sessions[0]["mode"] == "browser"

    def test_list_sorted_newest_first(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid_old = _uuid()
        sid_new = _uuid()

        # Use time.sleep(1) to guarantee distinct second-level timestamps
        # (saved_at uses strftime with second precision)
        archive.save(sid_old, state={}, created_at="2026-01-01T00:00:00Z")
        time.sleep(1.1)
        archive.save(sid_new, state={}, created_at="2026-03-01T00:00:00Z")
        sessions = archive.list_sessions()
        assert len(sessions) == 2
        assert sessions[0]["session_id"] == sid_new

    def test_list_max_results(self, tmp_path):
        archive = SessionArchive(tmp_path)
        for _ in range(5):
            archive.save(_uuid(), state={})
        sessions = archive.list_sessions(max_results=3)
        assert len(sessions) == 3

    def test_list_excludes_non_json(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save(_uuid(), state={})
        # Create a non-json file
        (tmp_path / "sessions" / "notes.txt").write_text("hello")
        sessions = archive.list_sessions()
        assert len(sessions) == 1

    def test_list_skips_corrupt_files(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save(_uuid(), state={})
        (tmp_path / "sessions").mkdir(exist_ok=True)
        (tmp_path / "sessions" / "corrupt.json").write_text("not json{{{")
        sessions = archive.list_sessions()
        assert len(sessions) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DELETE
# ═══════════════════════════════════════════════════════════════════════════════


class TestDelete:
    def test_delete_existing(self, tmp_path):
        archive = SessionArchive(tmp_path)
        sid = _uuid()
        archive.save(sid, state={})
        assert archive.delete(sid) is True
        assert archive.get(sid) is None

    def test_delete_nonexistent(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert archive.delete(_uuid()) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 4. RETENTION ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════════


class TestRetention:
    def test_enforces_max_sessions(self, tmp_path, monkeypatch):
        import data_contract

        monkeypatch.setattr(data_contract, "MAX_PERSISTED_SESSIONS", 3)
        archive = SessionArchive(tmp_path)

        for _ in range(5):
            archive.save(_uuid(), state={})
            time.sleep(0.01)  # Ensure distinct mtimes

        # Should only keep the 3 newest
        sessions = archive.list_sessions()
        assert len(sessions) == 3

    def test_retention_removes_oldest(self, tmp_path, monkeypatch):
        import data_contract

        monkeypatch.setattr(data_contract, "MAX_PERSISTED_SESSIONS", 2)
        archive = SessionArchive(tmp_path)

        sid_old = _uuid()
        sid_mid = _uuid()
        sid_new = _uuid()

        archive.save(sid_old, state={"n": 0})
        time.sleep(0.01)
        archive.save(sid_mid, state={"n": 1})
        time.sleep(0.01)
        archive.save(sid_new, state={"n": 2})

        # "old" should be gone
        assert archive.get(sid_old) is None
        assert archive.get(sid_mid) is not None
        assert archive.get(sid_new) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_archive_dir_created_on_first_save(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert not archive.archive_dir.exists()
        archive.save(_uuid(), state={})
        assert archive.archive_dir.is_dir()

    def test_large_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        big_state = {"rows": [{"id": i, "data": "x" * 100} for i in range(500)]}
        sid = _uuid()
        archive.save(sid, state=big_state)
        result = archive.get(sid)
        assert len(result["state"]["rows"]) == 500

    def test_special_characters_in_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        state = {"title": "Test <script>alert('xss')</script>", "emoji": "\U0001f680"}
        sid = _uuid()
        archive.save(sid, state=state)
        result = archive.get(sid)
        assert result["state"]["emoji"] == "\U0001f680"

    def test_max_persisted_sessions_constant(self):
        assert MAX_PERSISTED_SESSIONS == 100


# ═══════════════════════════════════════════════════════════════════════════════
# 6. PATH TRAVERSAL PREVENTION (Security Hardening)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathTraversalPrevention:
    """Verify session_id format validation prevents path traversal attacks."""

    def test_valid_uuid_accepted(self, tmp_path):
        """Standard UUID format should work."""
        archive = SessionArchive(tmp_path)
        sid = "550e8400-e29b-41d4-a716-446655440000"
        path = archive.save(sid, state={"ok": True})
        assert path.is_file()
        result = archive.get(sid)
        assert result["state"]["ok"] is True

    def test_path_traversal_rejected_save(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.save("../../etc/passwd", state={})

    def test_path_traversal_rejected_get(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.get("../../../.env")

    def test_path_traversal_rejected_delete(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.delete("../../sensitive")

    def test_non_uuid_string_rejected(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.save("my-session-name", state={})

    def test_empty_string_rejected(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.save("", state={})

    def test_null_bytes_rejected(self, tmp_path):
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.save("550e8400-e29b-41d4\x00-a716-446655440000", state={})

    def test_uppercase_uuid_rejected(self, tmp_path):
        """UUID validation enforces lowercase hex only."""
        archive = SessionArchive(tmp_path)
        with pytest.raises(ValueError, match="Invalid session_id"):
            archive.save("550E8400-E29B-41D4-A716-446655440000", state={})


class TestValidateSessionId:
    """Unit tests for the _validate_session_id function."""

    def test_valid_uuid(self):
        _validate_session_id("550e8400-e29b-41d4-a716-446655440000")

    def test_valid_uuid_v4(self):
        _validate_session_id(str(uuid.uuid4()))

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            _validate_session_id(12345)  # type: ignore[arg-type]

    def test_rejects_slash(self):
        with pytest.raises(ValueError):
            _validate_session_id("550e8400/e29b-41d4-a716-446655440000")

    def test_rejects_dotdot(self):
        with pytest.raises(ValueError):
            _validate_session_id("..%2f..%2fetc%2fpasswd")

    def test_rejects_short(self):
        with pytest.raises(ValueError):
            _validate_session_id("550e8400")
