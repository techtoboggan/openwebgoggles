"""Logging configuration for OpenWebGoggles.

Provides:
- JSONFormatter  — structured JSON log lines for machine parsing / log aggregators
- configure_logging() — sets up handlers, level, optional rotating file output

Usage (webview server subprocess):
    from log_config import configure_logging, DEFAULT_LOG_FILE
    configure_logging(level="INFO", log_file=DEFAULT_LOG_FILE, log_format="text")
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path

DEFAULT_LOG_FILE: Path = Path.home() / ".openwebgoggles" / "server.log"

# Rotate at 10 MB, keep 3 backups (max ~40 MB on disk)
LOG_ROTATION_MAX_BYTES: int = 10 * 1024 * 1024
LOG_ROTATION_BACKUP_COUNT: int = 3

# Fields present on every LogRecord — excluded from "extra" JSON keys
_RECORD_RESERVED: frozenset[str] = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
    "message",
    "asctime",
}


class JSONFormatter(logging.Formatter):
    """Formats each log record as a single compact JSON line.

    Output fields:
        ts      — ISO 8601 UTC timestamp with milliseconds, e.g. "2026-03-08T19:00:00.123Z"
        level   — log level name (DEBUG / INFO / WARNING / ERROR / CRITICAL)
        logger  — logger name
        msg     — formatted message string
        exc     — formatted exception traceback (only if an exception is attached)
        <key>   — any extra fields passed via logging.extra={...}
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = record.getMessage()
        ts = self.formatTime(record, "%Y-%m-%dT%H:%M:%S")
        ts += f".{record.msecs:03.0f}Z"
        entry: dict[str, object] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.message,
        }
        # Attach any caller-supplied extra fields
        for key, val in record.__dict__.items():
            if key not in _RECORD_RESERVED and not key.startswith("_"):
                entry[key] = val
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    log_format: str = "text",
) -> None:
    """Configure the root logger for OpenWebGoggles.

    Replaces any existing handlers so this is safe to call at startup.

    Args:
        level: Log level string — DEBUG / INFO / WARNING / ERROR (default: INFO).
        log_file: Path to write logs to with rotation.  If None, only stderr is used.
        log_format: "text" (default, human-readable) or "json" (machine-parseable).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    formatter: logging.Formatter
    if log_format.lower() == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    handlers: list[logging.Handler] = []

    # Stderr handler — always present (also used by health-check failure reporting)
    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    handlers.append(stderr_handler)

    # Rotating file handler — only when log_file is specified
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=LOG_ROTATION_MAX_BYTES,
            backupCount=LOG_ROTATION_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Replace existing handlers atomically
    root.handlers.clear()
    for handler in handlers:
        root.addHandler(handler)
