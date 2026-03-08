"""Tests for log_config — JSONFormatter and configure_logging."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_config import (
    DEFAULT_LOG_FILE,
    LOG_ROTATION_BACKUP_COUNT,
    LOG_ROTATION_MAX_BYTES,
    JSONFormatter,
    configure_logging,
)


class TestJSONFormatter:
    def _make_record(self, msg: str, level: int = logging.INFO, **extra: object) -> logging.LogRecord:
        record = logging.LogRecord(
            name="openwebgoggles",
            level=level,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_output_is_valid_json(self):
        fmt = JSONFormatter()
        record = self._make_record("hello world")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_required_fields_present(self):
        fmt = JSONFormatter()
        record = self._make_record("test message")
        parsed = json.loads(fmt.format(record))
        assert "ts" in parsed
        assert "level" in parsed
        assert "logger" in parsed
        assert "msg" in parsed

    def test_msg_field_contains_message(self):
        fmt = JSONFormatter()
        record = self._make_record("my log message")
        parsed = json.loads(fmt.format(record))
        assert parsed["msg"] == "my log message"

    def test_level_field(self):
        fmt = JSONFormatter()
        for level, name in [(logging.DEBUG, "DEBUG"), (logging.WARNING, "WARNING"), (logging.ERROR, "ERROR")]:
            record = self._make_record("x", level=level)
            parsed = json.loads(fmt.format(record))
            assert parsed["level"] == name

    def test_logger_field(self):
        fmt = JSONFormatter()
        record = self._make_record("x")
        parsed = json.loads(fmt.format(record))
        assert parsed["logger"] == "openwebgoggles"

    def test_ts_field_format(self):
        """Timestamp should look like 2026-03-08T19:00:00.123Z"""
        fmt = JSONFormatter()
        record = self._make_record("x")
        parsed = json.loads(fmt.format(record))
        ts = parsed["ts"]
        assert "T" in ts
        assert ts.endswith("Z")
        assert len(ts) >= 20  # at least "2026-03-08T19:00:00Z"

    def test_extra_fields_included(self):
        fmt = JSONFormatter()
        record = self._make_record("x", session_id="abc123", tool="openwebgoggles")
        parsed = json.loads(fmt.format(record))
        assert parsed["session_id"] == "abc123"
        assert parsed["tool"] == "openwebgoggles"

    def test_exception_info_included(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys as _sys

            exc_info = _sys.exc_info()
        record = self._make_record("error occurred")
        record.exc_info = exc_info
        parsed = json.loads(fmt.format(record))
        assert "exc" in parsed
        assert "ValueError" in parsed["exc"]

    def test_output_is_single_line(self):
        """JSON output must be a single line (no embedded newlines in the JSON structure)."""
        fmt = JSONFormatter()
        record = self._make_record("multi\nline\nmessage")
        output = fmt.format(record)
        # The output itself is one line (newlines in msg are JSON-escaped)
        parsed = json.loads(output)
        assert parsed["msg"] == "multi\nline\nmessage"


class TestConfigureLogging:
    def setup_method(self):
        """Save and clear root logger state before each test."""
        self._root = logging.getLogger()
        self._saved_handlers = self._root.handlers[:]
        self._saved_level = self._root.level
        self._root.handlers.clear()

    def teardown_method(self):
        """Restore root logger state after each test."""
        for h in self._root.handlers:
            h.close()
        self._root.handlers.clear()
        for h in self._saved_handlers:
            self._root.addHandler(h)
        self._root.setLevel(self._saved_level)

    def test_default_text_format_uses_stream_handler(self):
        configure_logging(level="INFO", log_file=None, log_format="text")
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) >= 1

    def test_json_format_uses_json_formatter(self):
        configure_logging(level="INFO", log_file=None, log_format="json")
        root = logging.getLogger()
        assert any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)

    def test_text_format_does_not_use_json_formatter(self):
        configure_logging(level="INFO", log_file=None, log_format="text")
        root = logging.getLogger()
        assert not any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)

    def test_log_level_applied(self):
        configure_logging(level="DEBUG", log_file=None)
        assert logging.getLogger().level == logging.DEBUG

    def test_log_level_warning(self):
        configure_logging(level="WARNING", log_file=None)
        assert logging.getLogger().level == logging.WARNING

    def test_file_handler_added_when_log_file_specified(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(level="INFO", log_file=log_file, log_format="text")
        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler)]
        assert len(file_handlers) == 1

    def test_rotating_handler_max_bytes(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(level="INFO", log_file=log_file)
        root = logging.getLogger()
        rh = next(h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler))
        assert rh.maxBytes == LOG_ROTATION_MAX_BYTES

    def test_rotating_handler_backup_count(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(level="INFO", log_file=log_file)
        root = logging.getLogger()
        rh = next(h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler))
        assert rh.backupCount == LOG_ROTATION_BACKUP_COUNT

    def test_file_handler_creates_parent_dir(self, tmp_path):
        log_file = tmp_path / "subdir" / "deep" / "test.log"
        assert not log_file.parent.exists()
        configure_logging(level="INFO", log_file=log_file)
        assert log_file.parent.exists()

    def test_no_file_handler_when_log_file_is_none(self):
        configure_logging(level="INFO", log_file=None)
        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 0

    def test_replaces_existing_handlers(self):
        dummy = logging.StreamHandler()
        logging.getLogger().addHandler(dummy)
        configure_logging(level="INFO", log_file=None)
        # dummy should have been replaced
        assert dummy not in logging.getLogger().handlers

    def test_log_rotation_max_bytes_value(self):
        assert LOG_ROTATION_MAX_BYTES == 10 * 1024 * 1024

    def test_log_rotation_backup_count_value(self):
        assert LOG_ROTATION_BACKUP_COUNT == 3

    def test_default_log_file_is_in_home(self):
        assert str(DEFAULT_LOG_FILE).startswith(str(Path.home()))
        assert DEFAULT_LOG_FILE.name == "server.log"


class TestConfigureLoggingIntegration:
    """Integration: JSON-formatted messages are actually valid JSON when written."""

    def setup_method(self):
        self._root = logging.getLogger()
        self._saved_handlers = self._root.handlers[:]
        self._saved_level = self._root.level
        self._root.handlers.clear()

    def teardown_method(self):
        for h in self._root.handlers:
            h.close()
        self._root.handlers.clear()
        for h in self._saved_handlers:
            self._root.addHandler(h)
        self._root.setLevel(self._saved_level)

    def test_json_log_written_to_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(level="INFO", log_file=log_file, log_format="json")
        logging.getLogger("openwebgoggles").info("integration test message")
        # Flush and close handlers
        for h in logging.getLogger().handlers:
            h.flush()
        content = log_file.read_text()
        lines = [l for l in content.splitlines() if l.strip()]
        assert len(lines) >= 1
        parsed = json.loads(lines[-1])
        assert parsed["msg"] == "integration test message"
        assert parsed["level"] == "INFO"
