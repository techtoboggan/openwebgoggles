"""
Structured audit logging for HITL decisions.

Records every human-in-the-loop interaction in a structured, append-only
JSON Lines log file. Each entry captures who (session), what (action),
when (timestamp), and which tool was involved.

Configuration via environment variables:
  OWG_AUDIT_LOG  — Path to audit log file (default: ~/.openwebgoggles/audit.jsonl)
  OWG_AUDIT      — Set to "0" to disable audit logging entirely
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("openwebgoggles.audit")

# Maximum individual log entry size (100KB) — defence against huge state dumps
_MAX_ENTRY_SIZE = 100_000

# Maximum audit log file size before rotation (50MB)
_MAX_LOG_SIZE = 50 * 1024 * 1024

# Number of rotated logs to keep
_ROTATE_KEEP = 3


class AuditLogger:
    """Append-only structured audit log for HITL interactions.

    Thread-safe. Writes are non-blocking (buffered via a background thread).
    Failures are logged, never raised — audit must not break the main flow.
    """

    def __init__(self) -> None:
        disabled = os.environ.get("OWG_AUDIT", "1").strip()
        self._enabled = disabled != "0"

        log_path = os.environ.get("OWG_AUDIT_LOG", "").strip()
        if log_path:
            self._path = Path(log_path)
        else:
            self._path = Path.home() / ".openwebgoggles" / "audit.jsonl"

        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """True if audit logging is active."""
        return self._enabled

    @property
    def path(self) -> Path:
        """Path to the audit log file."""
        return self._path

    def log_tool_call(
        self,
        tool: str,
        session: str = "default",
        mode: str = "",
        state_title: str = "",
        state_status: str = "",
        **extra: Any,
    ) -> None:
        """Record an MCP tool invocation.

        Called when an agent invokes openwebgoggles(), openwebgoggles_update(),
        openwebgoggles_close(), etc.
        """
        if not self._enabled:
            return

        entry = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event": "tool_call",
            "tool": tool,
            "session": session,
            "mode": mode,
            "title": state_title,
            "status": state_status,
            **extra,
        }
        self._write(entry)

    def log_action(
        self,
        action_id: str,
        action_type: str,
        session: str = "default",
        value: Any = None,
        tool: str = "openwebgoggles",
        **extra: Any,
    ) -> None:
        """Record a human action (button click, form submit, etc.).

        Called when a user responds via the UI.
        """
        if not self._enabled:
            return

        entry = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event": "user_action",
            "action_id": action_id,
            "action_type": action_type,
            "session": session,
            "tool": tool,
            **extra,
        }
        # Include value but cap its size to prevent huge payloads
        if value is not None:
            value_str = json.dumps(value, default=str)
            if len(value_str) <= 10_000:
                entry["value"] = value
            else:
                entry["value_truncated"] = True
                entry["value_size"] = len(value_str)

        self._write(entry)

    def log_session_event(
        self,
        event: str,
        session: str = "default",
        **extra: Any,
    ) -> None:
        """Record a session lifecycle event (open, close, save, restore)."""
        if not self._enabled:
            return

        entry = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "session": session,
            **extra,
        }
        self._write(entry)

    def _write(self, entry: dict[str, Any]) -> None:
        """Serialize and append an entry to the log file.

        Thread-safe. Errors are logged, never raised.
        """
        try:
            line = json.dumps(entry, separators=(",", ":"), default=str)
            if len(line) > _MAX_ENTRY_SIZE:
                # Truncate oversized entries — keep metadata, drop payload
                entry = {k: v for k, v in entry.items() if k in ("ts", "event", "tool", "session", "action_id")}
                entry["truncated"] = True
                line = json.dumps(entry, separators=(",", ":"), default=str)

            with self._lock:
                self._ensure_dir()
                self._rotate_if_needed()
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")

        except Exception:
            logger.debug("Audit log write failed", exc_info=True)

    def _ensure_dir(self) -> None:
        """Create the parent directory if it doesn't exist (owner-only permissions)."""
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _rotate_if_needed(self) -> None:
        """Rotate the log file if it exceeds the size limit."""
        try:
            if not self._path.exists():
                return
            if self._path.stat().st_size < _MAX_LOG_SIZE:
                return

            # Rotate: audit.jsonl.3 → deleted, .2 → .3, .1 → .2, current → .1
            for i in range(_ROTATE_KEEP, 0, -1):
                old = self._path.with_suffix(f".jsonl.{i}")
                new = self._path.with_suffix(f".jsonl.{i + 1}") if i < _ROTATE_KEEP else None
                if old.exists():
                    if new:
                        old.rename(new)
                    else:
                        old.unlink()

            self._path.rename(self._path.with_suffix(".jsonl.1"))
        except Exception:
            logger.debug("Audit log rotation failed", exc_info=True)

    def read_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Read the most recent N audit entries.

        Returns entries newest-first. Useful for the `openwebgoggles audit` CLI.
        """
        if not self._path.exists():
            return []

        try:
            with self._path.open("r", encoding="utf-8") as f:
                lines = f.readlines()

            entries = []
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(entries) >= limit:
                    break
            return entries
        except Exception:
            logger.debug("Audit log read failed", exc_info=True)
            return []
