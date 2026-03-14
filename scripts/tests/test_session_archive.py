"""
Tests for SessionArchive (data_contract.py) — session persistence.

Covers: save, list, get, delete, retention enforcement.
"""

from __future__ import annotations

import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_contract import MAX_PERSISTED_SESSIONS, SessionArchive


# ═══════════════════════════════════════════════════════════════════════════════
# 1. BASIC SAVE / GET
# ═══════════════════════════════════════════════════════════════════════════════


class TestSaveAndGet:
    def test_save_creates_file(self, tmp_path):
        archive = SessionArchive(tmp_path)
        path = archive.save("sess-001", state={"title": "Test"})
        assert path.is_file()
        assert path.name == "sess-001.json"

    def test_get_returns_saved_data(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-002", state={"title": "Hello"}, actions=[{"id": "ok"}])
        result = archive.get("sess-002")
        assert result is not None
        assert result["session_id"] == "sess-002"
        assert result["state"]["title"] == "Hello"
        assert len(result["actions"]) == 1

    def test_get_missing_returns_none(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert archive.get("nonexistent") is None

    def test_save_with_title(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-003", state={}, title="My Session")
        result = archive.get("sess-003")
        assert result["title"] == "My Session"

    def test_save_infers_title_from_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-004", state={"title": "From State"})
        result = archive.get("sess-004")
        assert result["title"] == "From State"

    def test_save_default_title(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-005", state={})
        result = archive.get("sess-005")
        assert result["title"] == "Untitled"

    def test_save_with_mode(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-006", state={}, mode="app")
        result = archive.get("sess-006")
        assert result["mode"] == "app"

    def test_save_timestamps(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-007", state={})
        result = archive.get("sess-007")
        assert "saved_at" in result
        assert "created_at" in result
        # Timestamps should be ISO format
        assert "T" in result["saved_at"]

    def test_save_file_permissions(self, tmp_path):
        archive = SessionArchive(tmp_path)
        path = archive.save("sess-008", state={})
        # Should be 0o600 (owner read/write only)
        perms = oct(path.stat().st_mode & 0o777)
        assert perms == "0o600"

    def test_save_overwrites_existing(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-009", state={"v": 1})
        archive.save("sess-009", state={"v": 2})
        result = archive.get("sess-009")
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
        archive.save("sess-a", state={"title": "Alpha"}, mode="browser")
        sessions = archive.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "sess-a"
        assert sessions[0]["title"] == "Alpha"
        assert sessions[0]["mode"] == "browser"

    def test_list_sorted_newest_first(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-old", state={}, created_at="2026-01-01T00:00:00Z")
        # Ensure different saved_at timestamps
        time.sleep(0.01)
        archive.save("sess-new", state={}, created_at="2026-03-01T00:00:00Z")
        sessions = archive.list_sessions()
        assert len(sessions) == 2
        assert sessions[0]["session_id"] == "sess-new"

    def test_list_max_results(self, tmp_path):
        archive = SessionArchive(tmp_path)
        for i in range(5):
            archive.save(f"sess-{i}", state={})
        sessions = archive.list_sessions(max_results=3)
        assert len(sessions) == 3

    def test_list_excludes_non_json(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-real", state={})
        # Create a non-json file
        (tmp_path / "sessions" / "notes.txt").write_text("hello")
        sessions = archive.list_sessions()
        assert len(sessions) == 1

    def test_list_skips_corrupt_files(self, tmp_path):
        archive = SessionArchive(tmp_path)
        archive.save("sess-good", state={})
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
        archive.save("sess-del", state={})
        assert archive.delete("sess-del") is True
        assert archive.get("sess-del") is None

    def test_delete_nonexistent(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert archive.delete("nope") is False


# ═══════════════════════════════════════════════════════════════════════════════
# 4. RETENTION ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════════


class TestRetention:
    def test_enforces_max_sessions(self, tmp_path, monkeypatch):
        import data_contract

        monkeypatch.setattr(data_contract, "MAX_PERSISTED_SESSIONS", 3)
        archive = SessionArchive(tmp_path)

        for i in range(5):
            archive.save(f"sess-{i:03d}", state={"n": i})
            time.sleep(0.01)  # Ensure distinct mtimes

        # Should only keep the 3 newest
        sessions = archive.list_sessions()
        assert len(sessions) == 3

    def test_retention_removes_oldest(self, tmp_path, monkeypatch):
        import data_contract

        monkeypatch.setattr(data_contract, "MAX_PERSISTED_SESSIONS", 2)
        archive = SessionArchive(tmp_path)

        archive.save("old", state={"n": 0})
        time.sleep(0.01)
        archive.save("mid", state={"n": 1})
        time.sleep(0.01)
        archive.save("new", state={"n": 2})

        # "old" should be gone
        assert archive.get("old") is None
        assert archive.get("mid") is not None
        assert archive.get("new") is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_archive_dir_created_on_first_save(self, tmp_path):
        archive = SessionArchive(tmp_path)
        assert not archive.archive_dir.exists()
        archive.save("first", state={})
        assert archive.archive_dir.is_dir()

    def test_large_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        big_state = {"rows": [{"id": i, "data": "x" * 100} for i in range(500)]}
        archive.save("big", state=big_state)
        result = archive.get("big")
        assert len(result["state"]["rows"]) == 500

    def test_special_characters_in_state(self, tmp_path):
        archive = SessionArchive(tmp_path)
        state = {"title": "Test <script>alert('xss')</script>", "emoji": "\U0001f680"}
        archive.save("special", state=state)
        result = archive.get("special")
        assert result["state"]["emoji"] == "\U0001f680"

    def test_max_persisted_sessions_constant(self):
        assert MAX_PERSISTED_SESSIONS == 100
