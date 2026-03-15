"""Tests for the audit logging system."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit import AuditLogger, _MAX_ENTRY_SIZE, _MAX_LOG_SIZE, _ROTATE_KEEP


# ---------------------------------------------------------------------------
# Enabled / disabled
# ---------------------------------------------------------------------------


class TestAuditEnabled:
    def test_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("OWG_AUDIT", raising=False)
        logger = AuditLogger()
        assert logger.enabled

    def test_disabled_when_zero(self, monkeypatch):
        monkeypatch.setenv("OWG_AUDIT", "0")
        logger = AuditLogger()
        assert not logger.enabled

    def test_enabled_when_one(self, monkeypatch):
        monkeypatch.setenv("OWG_AUDIT", "1")
        logger = AuditLogger()
        assert logger.enabled

    def test_disabled_no_write(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OWG_AUDIT", "0")
        monkeypatch.setenv("OWG_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        logger = AuditLogger()
        logger.log_tool_call(tool="openwebgoggles")
        assert not (tmp_path / "audit.jsonl").exists()


# ---------------------------------------------------------------------------
# Log path configuration
# ---------------------------------------------------------------------------


class TestLogPath:
    def test_default_path(self, monkeypatch):
        monkeypatch.delenv("OWG_AUDIT_LOG", raising=False)
        logger = AuditLogger()
        assert logger.path == Path.home() / ".openwebgoggles" / "audit.jsonl"

    def test_custom_path(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom" / "my-audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(custom))
        logger = AuditLogger()
        assert logger.path == custom

    def test_creates_parent_directory(self, monkeypatch, tmp_path):
        log_path = tmp_path / "nested" / "dir" / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)
        logger = AuditLogger()
        logger.log_tool_call(tool="test")
        assert log_path.exists()


# ---------------------------------------------------------------------------
# Tool call logging
# ---------------------------------------------------------------------------


class TestLogToolCall:
    def test_basic_tool_call(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_tool_call(
            tool="openwebgoggles",
            session="my-session",
            mode="browser",
            state_title="Deploy Review",
            state_status="pending_review",
        )

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "tool_call"
        assert entry["tool"] == "openwebgoggles"
        assert entry["session"] == "my-session"
        assert entry["mode"] == "browser"
        assert entry["title"] == "Deploy Review"
        assert entry["status"] == "pending_review"
        assert "ts" in entry

    def test_extra_fields(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_tool_call(tool="openwebgoggles_update", merge=True, append=False)

        entry = json.loads(log_path.read_text().strip())
        assert entry["merge"] is True
        assert entry["append"] is False

    def test_multiple_entries_append(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_tool_call(tool="openwebgoggles", session="a")
        logger.log_tool_call(tool="openwebgoggles_update", session="a")
        logger.log_tool_call(tool="openwebgoggles_close", session="a")

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 3
        assert json.loads(lines[0])["tool"] == "openwebgoggles"
        assert json.loads(lines[1])["tool"] == "openwebgoggles_update"
        assert json.loads(lines[2])["tool"] == "openwebgoggles_close"


# ---------------------------------------------------------------------------
# Action logging
# ---------------------------------------------------------------------------


class TestLogAction:
    def test_basic_action(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_action(
            action_id="approve",
            action_type="approve",
            session="deploy-1",
            value={"decision": "approved"},
        )

        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "user_action"
        assert entry["action_id"] == "approve"
        assert entry["action_type"] == "approve"
        assert entry["session"] == "deploy-1"
        assert entry["value"] == {"decision": "approved"}

    def test_action_with_no_value(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_action(action_id="cancel", action_type="reject")

        entry = json.loads(log_path.read_text().strip())
        assert "value" not in entry

    def test_large_value_truncated(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        big_value = "x" * 20_000
        logger.log_action(action_id="submit", action_type="submit", value=big_value)

        entry = json.loads(log_path.read_text().strip())
        assert entry["value_truncated"] is True
        assert entry["value_size"] > 10_000
        assert "value" not in entry


# ---------------------------------------------------------------------------
# Session event logging
# ---------------------------------------------------------------------------


class TestLogSessionEvent:
    def test_session_open(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_session_event("session_open", session="main", mode="browser")

        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "session_open"
        assert entry["session"] == "main"
        assert entry["mode"] == "browser"

    def test_session_close(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_session_event("session_close", session="main", message="Done.")

        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "session_close"
        assert entry["message"] == "Done."

    def test_session_save(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        logger.log_session_event("session_save", session="deploy", session_id="abc123")

        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "session_save"
        assert entry["session_id"] == "abc123"


# ---------------------------------------------------------------------------
# Entry size limits
# ---------------------------------------------------------------------------


class TestEntrySizeLimits:
    def test_oversized_entry_truncated(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        # Create an entry that exceeds _MAX_ENTRY_SIZE
        huge_extra = "y" * (_MAX_ENTRY_SIZE + 1000)
        logger.log_tool_call(tool="openwebgoggles", session="x", huge_data=huge_extra)

        entry = json.loads(log_path.read_text().strip())
        assert entry["truncated"] is True
        assert "huge_data" not in entry
        assert entry["tool"] == "openwebgoggles"


# ---------------------------------------------------------------------------
# Log rotation
# ---------------------------------------------------------------------------


class TestLogRotation:
    def test_rotation_on_size_limit(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        # Write a file just over the size limit
        log_path.write_text("x" * (_MAX_LOG_SIZE + 1))

        logger = AuditLogger()
        logger.log_tool_call(tool="test")

        # Original should have been rotated to .1
        assert (tmp_path / "audit.jsonl.1").exists()
        # New entry written to fresh file
        assert log_path.exists()
        entry = json.loads(log_path.read_text().strip())
        assert entry["tool"] == "test"

    def test_rotation_chain(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        # Create existing rotated files
        (tmp_path / "audit.jsonl.1").write_text("old-1")
        (tmp_path / "audit.jsonl.2").write_text("old-2")

        # Write current file over the limit
        log_path.write_text("x" * (_MAX_LOG_SIZE + 1))

        logger = AuditLogger()
        logger.log_tool_call(tool="test")

        # Chain should have shifted: .2→.3, .1→.2, current→.1
        assert (tmp_path / "audit.jsonl.1").exists()
        assert (tmp_path / "audit.jsonl.2").exists()
        assert (tmp_path / "audit.jsonl.3").exists()
        assert (tmp_path / "audit.jsonl.2").read_text() == "old-1"
        assert (tmp_path / "audit.jsonl.3").read_text() == "old-2"

    def test_oldest_rotated_deleted(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        # Fill all rotation slots
        for i in range(1, _ROTATE_KEEP + 1):
            (tmp_path / f"audit.jsonl.{i}").write_text(f"old-{i}")

        log_path.write_text("x" * (_MAX_LOG_SIZE + 1))

        logger = AuditLogger()
        logger.log_tool_call(tool="test")

        # Oldest (.3) should be gone, replaced by what was .2
        assert not (tmp_path / f"audit.jsonl.{_ROTATE_KEEP + 1}").exists()


# ---------------------------------------------------------------------------
# Read recent
# ---------------------------------------------------------------------------


class TestReadRecent:
    def test_read_empty(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        logger = AuditLogger()
        assert logger.read_recent() == []

    def test_read_entries(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        for i in range(5):
            logger.log_tool_call(tool=f"tool-{i}")

        entries = logger.read_recent(limit=3)
        assert len(entries) == 3
        # Newest first
        assert entries[0]["tool"] == "tool-4"
        assert entries[1]["tool"] == "tool-3"
        assert entries[2]["tool"] == "tool-2"

    def test_read_with_corrupted_lines(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))

        # Write mix of valid and invalid lines
        log_path.write_text('{"event":"tool_call","tool":"a"}\nnot-json\n{"event":"tool_call","tool":"b"}\n')

        logger = AuditLogger()
        entries = logger.read_recent(limit=10)
        assert len(entries) == 2
        assert entries[0]["tool"] == "b"
        assert entries[1]["tool"] == "a"

    def test_read_nonexistent_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OWG_AUDIT_LOG", str(tmp_path / "nope.jsonl"))
        logger = AuditLogger()
        assert logger.read_recent() == []


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


class TestErrorResilience:
    def test_write_failure_does_not_raise(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OWG_AUDIT_LOG", str(tmp_path / "readonly" / "audit.jsonl"))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        # Make parent read-only so write fails
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        try:
            logger = AuditLogger()
            # Should not raise
            logger.log_tool_call(tool="test")
        finally:
            readonly_dir.chmod(0o755)

    def test_json_serialization_of_non_serializable(self, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        # set() is not JSON-serializable, but default=str handles it
        logger.log_tool_call(tool="test", weird_value={1, 2, 3})

        entry = json.loads(log_path.read_text().strip())
        assert entry["tool"] == "test"
        # Set gets stringified
        assert "weird_value" in entry


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_writes(self, monkeypatch, tmp_path):
        import threading

        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()
        errors = []

        def write_entries(start: int) -> None:
            try:
                for i in range(20):
                    logger.log_tool_call(tool=f"thread-{start}-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_entries, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 100  # 5 threads × 20 entries

        # All lines must be valid JSON
        for line in lines:
            json.loads(line)
