"""
File-based JSON data contract for OpenWebGoggles server.
"""

from __future__ import annotations

import copy
import json
import os
import time
import uuid
from pathlib import Path


class DataContract:
    """Manages the file-based JSON data contract in .openwebgoggles/."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.manifest_path = self.data_dir / "manifest.json"
        self.state_path = self.data_dir / "state.json"
        self.actions_path = self.data_dir / "actions.json"

        # Track modification times for change detection
        self._mtimes: dict[str, float] = {}

    def read_json(self, path: Path) -> dict | None:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def write_json(self, path: Path, data: dict) -> None:
        tmp = path.with_suffix(".tmp")
        # Thread-safe restrictive permissions via os.open (avoids process-wide os.umask)
        content = json.dumps(data, indent=2)
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        tmp.replace(path)

    def get_manifest(self) -> dict | None:
        return self.read_json(self.manifest_path)

    def get_state(self) -> dict | None:
        return self.read_json(self.state_path)

    def get_actions(self) -> dict | None:
        return self.read_json(self.actions_path)

    def append_action(self, action: dict) -> dict:
        actions = self.get_actions() or {"version": 0, "actions": []}
        action["id"] = str(uuid.uuid4())
        action["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        actions["actions"].append(action)
        actions["version"] = actions.get("version", 0) + 1
        self.write_json(self.actions_path, actions)
        return actions

    def clear_state(self) -> None:
        """Delete the state file so the server starts with a clean slate.

        Called at server startup to prevent stale state from a previous session
        being served to newly connected clients.  The MCP server (browser mode)
        will write fresh state via write_state() once a new webview() call arrives.
        """
        try:
            self.state_path.unlink(missing_ok=True)
        except OSError:
            pass

    def clear_actions(self) -> int:
        actions = self.get_actions()
        count = len(actions["actions"]) if actions and "actions" in actions else 0
        self.write_json(self.actions_path, {"version": 0, "actions": []})
        return count

    def check_changes(self) -> list[str]:
        """Check for file modifications since last check. Returns list of changed file names."""
        changed = []
        for name, path in [
            ("state", self.state_path),
            ("actions", self.actions_path),
            ("manifest", self.manifest_path),
        ]:
            try:
                mtime = path.stat().st_mtime_ns
            except FileNotFoundError:
                continue
            if name in self._mtimes and self._mtimes[name] != mtime:
                changed.append(name)
            self._mtimes[name] = mtime
        return changed


def _strip_token(data: dict) -> dict:
    """Remove session token from a manifest dict (deep copy). Consistent across HTTP/WS paths."""
    safe = copy.deepcopy(data)
    if "session" in safe and "token" in safe["session"]:
        del safe["session"]["token"]
    return safe


# ---------------------------------------------------------------------------
# Session persistence archive
# ---------------------------------------------------------------------------

# Maximum number of session snapshots to retain
MAX_PERSISTED_SESSIONS = 100


class SessionArchive:
    """Manages persisted session snapshots in a ``sessions/`` subdirectory.

    Each snapshot is a JSON file named ``<session_id>.json`` containing the
    final state, actions taken, and metadata.
    """

    def __init__(self, data_dir: str | Path):
        self.archive_dir = Path(data_dir) / "sessions"

    def save(
        self,
        session_id: str,
        *,
        state: dict | None = None,
        actions: list | None = None,
        title: str | None = None,
        mode: str = "browser",
        created_at: str | None = None,
    ) -> Path:
        """Persist a session snapshot to disk.

        Returns the path of the written file.
        """
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        snapshot = {
            "session_id": session_id,
            "title": title or (state or {}).get("title", "Untitled"),
            "mode": mode,
            "created_at": created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "state": state or {},
            "actions": actions or [],
        }

        path = self.archive_dir / f"{session_id}.json"
        content = json.dumps(snapshot, indent=2)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)

        # Enforce retention limit — remove oldest sessions beyond MAX
        self._enforce_retention()
        return path

    def list_sessions(self, max_results: int = 50) -> list[dict]:
        """Return metadata of saved sessions, newest first."""
        if not self.archive_dir.is_dir():
            return []

        sessions = []
        for p in self.archive_dir.iterdir():
            if p.suffix != ".json":
                continue
            try:
                data = json.loads(p.read_text())
                sessions.append(
                    {
                        "session_id": data.get("session_id", p.stem),
                        "title": data.get("title", "Untitled"),
                        "mode": data.get("mode", "unknown"),
                        "created_at": data.get("created_at", ""),
                        "saved_at": data.get("saved_at", ""),
                    }
                )
            except (json.JSONDecodeError, OSError):
                continue

        # Sort by saved_at descending
        sessions.sort(key=lambda s: s.get("saved_at", ""), reverse=True)
        return sessions[:max_results]

    def get(self, session_id: str) -> dict | None:
        """Load a persisted session snapshot by ID."""
        path = self.archive_dir / f"{session_id}.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def delete(self, session_id: str) -> bool:
        """Delete a session snapshot. Returns True if deleted."""
        path = self.archive_dir / f"{session_id}.json"
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False

    def _enforce_retention(self) -> None:
        """Remove oldest sessions when count exceeds MAX_PERSISTED_SESSIONS."""
        if not self.archive_dir.is_dir():
            return

        snapshots = sorted(
            (p for p in self.archive_dir.iterdir() if p.suffix == ".json"),
            key=lambda p: p.stat().st_mtime,
        )

        while len(snapshots) > MAX_PERSISTED_SESSIONS:
            oldest = snapshots.pop(0)
            oldest.unlink(missing_ok=True)
