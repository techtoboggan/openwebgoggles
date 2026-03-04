#!/usr/bin/env python3
"""
OpenWebGoggles MCP Server — exposes browser-based HITL UIs as MCP tools.

Agents call openwebgoggles() to show an interactive UI and block until the user
responds.  The MCP server manages the full lifecycle: data directory setup,
subprocess launch, browser opening, state updates, and cleanup.

Install & configure:
    pipx install openwebgoggles
    openwebgoggles init claude      # or: openwebgoggles init opencode
"""

import asyncio
import atexit
import functools
import importlib
import importlib.metadata
import json
import logging
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

# Lazy-guard: init subcommands don't need mcp — let them work even when
# the mcp library is missing, broken, or has version conflicts.
_mcp_import_error: Exception | None = None
try:
    from mcp.server.fastmcp import Context, FastMCP
    from mcp.types import CallToolResult, TextContent
except Exception as exc:
    _mcp_import_error = exc

    class Context:  # type: ignore[no-redef]
        """Stub so type hints don't crash when mcp can't load."""

        async def report_progress(self, *a: Any, **kw: Any) -> None:
            pass

    class FastMCP:  # type: ignore[no-redef]
        """Stub so module-level decorators don't crash when mcp can't load."""

        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def tool(self, *a: Any, **kw: Any):  # noqa: ANN201
            def _decorator(fn):  # type: ignore[no-untyped-def]  # noqa: ANN001, ANN202
                return fn

            return _decorator


logger = logging.getLogger("openwebgoggles")

# SecurityGate — imported eagerly for validation in MCP tools
_security_gate = None
try:
    try:
        from .security_gate import SecurityGate
    except ImportError:
        from security_gate import SecurityGate  # noqa: I001

    _security_gate = SecurityGate()
except ImportError:
    logger.warning("SecurityGate not available — state validation disabled")
except Exception:
    logger.error("SecurityGate failed to initialize — state validation disabled", exc_info=True)


# ---------------------------------------------------------------------------
# Platform-aware data directory
# ---------------------------------------------------------------------------

_DATA_DIR_NAME = "openwebgoggles"


def _get_data_dir() -> Path:
    """Return the platform-appropriate persistent data directory.

    - Linux/macOS: ``$XDG_DATA_HOME/openwebgoggles`` (default ``~/.local/share/openwebgoggles``)
    - Windows: ``%LOCALAPPDATA%/openwebgoggles``
    """
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / _DATA_DIR_NAME


# ---------------------------------------------------------------------------
# Deep merge utility
# ---------------------------------------------------------------------------


MAX_MERGE_DEPTH = 20
_DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _deep_merge(base: dict, override: dict, _depth: int = 0) -> None:
    """Recursively merge *override* into *base*, mutating *base* in place.

    Rules:
    - dict + dict → recurse (up to MAX_MERGE_DEPTH levels)
    - list + list → replace (NOT append — append is surprising and hard to undo)
    - anything else → override wins

    Raises ValueError if nesting exceeds MAX_MERGE_DEPTH (defense-in-depth
    against stack overflow — SecurityGate also limits JSON nesting to 10).
    """
    if _depth > MAX_MERGE_DEPTH:
        raise ValueError(f"Merge depth exceeds maximum ({MAX_MERGE_DEPTH})")
    # Block prototype-pollution keys that could be dangerous when serialized to JS
    for key, value in override.items():
        if key in _DANGEROUS_KEYS:
            raise ValueError(f"Merge rejected: dangerous key {key!r}")
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value, _depth + 1)
        else:
            base[key] = value


# ---------------------------------------------------------------------------
# State presets — expand shorthand into full state schemas
# ---------------------------------------------------------------------------


def _expand_preset(preset: str, state: dict[str, Any]) -> dict[str, Any]:
    """Expand a preset name into a full state schema, merging user overrides.

    Template dicts (``base``) are dict literals constructed fresh on each call,
    so ``_deep_merge()`` mutating them in place is safe — no shared state between
    invocations.
    """
    s = dict(state)  # shallow copy so we can pop

    if preset == "progress":
        tasks = s.pop("tasks", [])
        pct = s.pop("percentage", None)
        title = s.pop("title", "Progress")
        base: dict[str, Any] = {
            "title": title,
            "status": "processing",
            "data": {
                "sections": [
                    {
                        "type": "progress",
                        "title": title if title != "Progress" else "",
                        "tasks": tasks,
                    }
                ]
            },
        }
        if pct is not None:
            base["data"]["sections"][0]["percentage"] = pct
        _deep_merge(base, s)
        return base

    if preset == "confirm":
        details = s.pop("details", None)
        title = s.pop("title", "Confirm")
        message = s.pop("message", "")
        base = {
            "title": title,
            "message": message,
            "status": "pending_review",
            "data": {"sections": []},
            "actions_requested": [
                {"id": "confirm", "label": "Confirm", "type": "approve"},
                {"id": "cancel", "label": "Cancel", "type": "reject"},
            ],
        }
        if details:
            base["data"]["sections"].append({"type": "text", "content": details, "format": "markdown"})
        _deep_merge(base, s)
        return base

    if preset == "log":
        lines = s.pop("lines", [])
        max_lines = s.pop("maxLines", 500)
        title = s.pop("title", "Log")
        base = {
            "title": title,
            "status": "processing",
            "data": {
                "sections": [
                    {
                        "type": "log",
                        "title": title if title != "Log" else "",
                        "lines": lines,
                        "autoScroll": True,
                        "maxLines": max_lines,
                    }
                ]
            },
        }
        _deep_merge(base, s)
        return base

    raise ValueError(f"Unknown preset: {preset!r}")


# ---------------------------------------------------------------------------
# WebviewSession — manages one webview server subprocess + data contract
# ---------------------------------------------------------------------------


class WebviewSession:
    """Manages a single webview server subprocess and its file-based data contract."""

    DEFAULT_HTTP_PORT = 18420
    DEFAULT_WS_PORT = 18421
    MAX_PORT_ATTEMPTS = 10
    HEALTH_TIMEOUT = 15.0
    POLL_INTERVAL = 0.5
    PROGRESS_INTERVAL = 10.0

    def __init__(self, work_dir: Path | None = None, open_browser: bool = True):
        self.work_dir = work_dir or Path.cwd()
        self.data_dir = work_dir if work_dir else _get_data_dir()
        self.process: subprocess.Popen | None = None
        self.session_token: str = ""
        self.session_id: str = ""
        self.http_port: int = self.DEFAULT_HTTP_PORT
        self.ws_port: int = self.DEFAULT_WS_PORT
        self._started: bool = False
        self._state_version: int = 0
        self._state_lock = threading.Lock()  # Protects read-merge-write in merge_state
        self._open_browser_on_start: bool = open_browser
        self._chrome_process: subprocess.Popen | None = None
        self._chrome_profile: str | None = None
        self._lock_fd: int | None = None  # flock file descriptor

    # -- Singleton enforcement -----------------------------------------------

    def _kill_stale_server(self) -> None:
        """Check for a stale webview server from a previous session and kill it.

        This handles the case where a prior MCP server process crashed without
        cleaning up its webview subprocess, or where the editor spawned multiple
        MCP server processes that each launched a webview.
        """
        pid_file = self.data_dir / ".server.pid"
        if not pid_file.exists():
            return

        try:
            raw = pid_file.read_text().strip()
            if not raw.isdigit():
                pid_file.unlink(missing_ok=True)
                return
            pid = int(raw)
        except (OSError, ValueError):
            return

        # Don't kill our own subprocess
        if self.process and self.process.pid == pid:
            return

        # Check if the PID is alive and is actually a Python/webview process
        try:
            os.kill(pid, 0)  # Signal 0 = existence check, doesn't kill
        except OSError:
            # Process doesn't exist — stale PID file
            logger.info("Removing stale PID file (pid=%d no longer running).", pid)
            pid_file.unlink(missing_ok=True)
            return

        # Verify the process is actually a webview server (prevent PID reuse attacks)
        try:
            import subprocess as _sp

            result = _sp.run(  # noqa: S603
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=5,
            )
            cmd = result.stdout.strip()
            if cmd and "webview_server" not in cmd and "python" not in cmd.lower():
                logger.warning(
                    "PID %d is alive but not a webview server (cmd=%s). Removing stale PID file.",
                    pid,
                    cmd[:80],
                )
                pid_file.unlink(missing_ok=True)
                return
        except Exception:
            pass  # If we can't verify, proceed with caution (kill is still user-scoped)

        # PID is alive — kill it
        logger.warning("Killing stale webview server (pid=%d) from previous session.", pid)
        try:
            os.kill(pid, 15)  # SIGTERM
            # Give it a moment to exit gracefully
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except OSError:
                    break
            else:
                # Still alive after 5s — force kill
                try:
                    os.kill(pid, 9)  # SIGKILL
                except OSError:
                    pass
        except OSError:
            pass
        pid_file.unlink(missing_ok=True)

    def _acquire_lock(self) -> None:
        """Acquire an exclusive flock on .server.lock to prevent concurrent starts.

        Uses non-blocking flock so a second MCP server instance immediately
        detects that a lock is held, cleans up the stale process, then retries.
        """
        import fcntl

        self.data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.data_dir / ".server.lock"
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Lock held by another process — kill stale server and retry
            logger.warning("Lock held by another process — cleaning up stale server.")
            os.close(fd)
            self._kill_stale_server()
            # Retry with blocking lock (short timeout via the loop below)
            fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
            for _attempt in range(6):  # ~3 seconds
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    time.sleep(0.5)
            else:
                os.close(fd)
                raise RuntimeError("Cannot acquire webview lock — another instance may be running")
        self._lock_fd = fd
        # Write our PID into the lock file for debugging
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, str(os.getpid()).encode())

    def _release_lock(self) -> None:
        """Release the flock and close the lock file descriptor."""
        import fcntl

        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None

    # -- Public API ---------------------------------------------------------

    async def ensure_started(self, app: str = "dynamic") -> None:
        """Idempotent: create data dir, copy app, start server if not running."""
        if self._started and self.is_alive():
            return

        # If process died mid-session, clean up before restarting
        if self._started and not self.is_alive():
            logger.warning("Webview subprocess died — restarting.")
            self._cleanup_process()

        # Singleton enforcement: kill stale servers, acquire exclusive lock
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._kill_stale_server()
        self._acquire_lock()

        (self.data_dir / "apps").mkdir(exist_ok=True)

        self._copy_app(app)
        self.session_token = secrets.token_hex(32)
        self.session_id = str(uuid.uuid4())
        self.http_port, self.ws_port = self._find_free_ports()
        self._write_manifest(app)
        self._init_data_contract()
        self._set_permissions()

        # Launch subprocess
        scripts_dir = Path(__file__).resolve().parent
        server_py = scripts_dir / "webview_server.py"
        sdk_path = self._find_assets_dir() / "sdk" / "openwebgoggles-sdk.js"

        env = os.environ.copy()
        env["OCV_SESSION_TOKEN"] = self.session_token

        self.process = subprocess.Popen(
            [
                sys.executable,
                str(server_py),
                "--data-dir",
                str(self.data_dir),
                "--http-port",
                str(self.http_port),
                "--ws-port",
                str(self.ws_port),
                "--sdk-path",
                str(sdk_path),
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        if not await self._health_check():
            stderr = ""
            if self.process.stderr:
                try:
                    import select

                    if select.select([self.process.stderr], [], [], 0)[0]:
                        stderr = self.process.stderr.read(500).decode(errors="replace")
                except Exception:
                    pass
                finally:
                    # M3: Ensure stderr pipe is closed on failure to prevent fd leak
                    try:
                        self.process.stderr.close()
                    except Exception:
                        pass
            self.process.kill()
            self.process = None
            raise RuntimeError(f"Webview server failed to start: {stderr}")

        self._started = True
        # Close stderr pipe to prevent buffer deadlock (errors already reported via health check)
        if self.process and self.process.stderr:
            self.process.stderr.close()
        global _atexit_registered
        if not _atexit_registered:
            atexit.register(self._atexit_cleanup)
            _atexit_registered = True

        if self._open_browser_on_start:
            self._open_browser()
            self._open_browser_on_start = False

    def _write_state_locked(self, state: dict[str, Any]) -> None:
        """Internal: write state while lock is already held."""
        self._state_version += 1
        state.setdefault("version", self._state_version)
        state["version"] = self._state_version
        state.setdefault("updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        state.setdefault("status", "waiting_input")
        self._write_json(self.data_dir / "state.json", state)

    def write_state(self, state: dict[str, Any]) -> None:
        """Atomic write to state.json with auto-incrementing version."""
        with self._state_lock:
            self._write_state_locked(state)

    def read_state(self) -> dict[str, Any]:
        """Read current state.json."""
        return self._read_json(self.data_dir / "state.json") or {}

    def merge_state(
        self,
        partial: dict[str, Any],
        validator: Any | None = None,
    ) -> dict[str, Any]:
        """Deep merge partial state into current state, then write.

        Uses _state_lock to prevent TOCTOU races between read and write.

        Args:
            partial: Partial state to merge into current state.
            validator: Optional callable(merged_dict) that raises on invalid
                state.  Called **after** merge but **before** writing to disk,
                so invalid merged states never touch the filesystem.
        """
        with self._state_lock:
            current = self.read_state()
            _deep_merge(current, partial)
            if validator:
                validator(current)  # raises on failure — write is skipped
            self._write_state_locked(current)
            return current

    def read_actions(self) -> dict[str, Any]:
        """Read current actions.json."""
        return self._read_json(self.data_dir / "actions.json") or {"version": 0, "actions": []}

    def clear_actions(self) -> None:
        """Reset actions.json to empty."""
        self._write_json(self.data_dir / "actions.json", {"version": 0, "actions": []})

    async def wait_for_action(
        self,
        timeout: float = 300.0,
        on_progress: Any | None = None,
    ) -> dict[str, Any] | None:
        """Poll actions.json until a user action appears, or timeout.

        Internal actions (action_id starting with ``_``, e.g. ``_page_switch``)
        are navigation bookkeeping and do **not** break the wait.  Only
        explicit user actions (approve / reject / submit buttons) count.

        Args:
            timeout: Maximum seconds to wait.
            on_progress: Optional ``async callable(elapsed, total)`` invoked
                every :pyattr:`PROGRESS_INTERVAL` seconds to keep the MCP
                connection alive (prevents client-side -32001 timeouts).
        """
        actions_path = self.data_dir / "actions.json"
        start = time.monotonic()
        deadline = start + timeout
        last_progress = start

        while time.monotonic() < deadline:
            try:
                data = json.loads(actions_path.read_text())
                actions = data.get("actions", [])
                # Filter: only user-initiated actions break the wait.
                # Internal actions (prefixed with _) like _page_switch are
                # navigation bookkeeping and are ignored here.
                user_actions = [a for a in actions if not str(a.get("action_id", "")).startswith("_")]
                if user_actions:
                    return data
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            now = time.monotonic()
            if on_progress and (now - last_progress) >= self.PROGRESS_INTERVAL:
                elapsed = now - start
                try:
                    await on_progress(elapsed, timeout)
                except Exception:
                    pass  # Never let progress reporting break the wait loop
                last_progress = now

            await asyncio.sleep(self.POLL_INTERVAL)

        return None

    async def close(self, message: str = "Session complete.") -> None:
        """Notify browser clients, kill Chrome and the subprocess."""
        if self.process and self.is_alive():
            # Try graceful close via HTTP API
            try:
                body = json.dumps({"message": message, "delay_ms": 1000}).encode()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{self.http_port}/_api/close",
                    data=body,
                    headers={
                        "Authorization": f"Bearer {self.session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=3)  # nosec B310 — localhost-only health check
            except Exception:
                pass

            await asyncio.sleep(1.0)

        self._cleanup_chrome()
        self._cleanup_process()
        self._started = False

    def is_alive(self) -> bool:
        """Check if the webview subprocess is still running."""
        if self.process is None:
            return False
        return self.process.poll() is None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    # -- Internal helpers ---------------------------------------------------

    def _find_assets_dir(self) -> Path:
        """Locate the assets/ directory (works for both dev and installed)."""
        # Development: __file__ is scripts/mcp_server.py, assets is ../assets
        repo_root = Path(__file__).resolve().parent.parent
        dev_assets = repo_root / "assets"
        if dev_assets.is_dir():
            return dev_assets
        # Installed as package: assets bundled alongside scripts/
        pkg_assets = Path(__file__).resolve().parent / "assets"
        if pkg_assets.is_dir():
            return pkg_assets
        raise FileNotFoundError(f"Cannot find assets directory. Expected at {dev_assets} or {pkg_assets}")

    def _copy_app(self, app_name: str) -> None:
        """Find and copy the app + SDK to the data directory."""
        # Reject absolute paths and path traversal before any filesystem access.
        # Pathlib resolves `Path(base) / "/abs"` to `/abs` on Unix, so an absolute
        # app_name would silently escape the assets directory.
        _app_path = Path(app_name)
        if _app_path.is_absolute() or ".." in _app_path.parts or app_name.startswith("."):
            raise FileNotFoundError(
                f"App '{app_name}' not found. App names must be simple names (no '/', '..', or leading '.')."
            )

        assets_dir = self._find_assets_dir()
        repo_root = Path(__file__).resolve().parent.parent

        # Search order: built-in apps, examples
        candidates = [
            assets_dir / "apps" / app_name,
            repo_root / "examples" / app_name,
        ]
        app_src = None
        for candidate in candidates:
            if candidate.is_dir():
                app_src = candidate
                break

        if app_src is None:
            available = []
            apps_dir = assets_dir / "apps"
            if apps_dir.is_dir():
                available.extend(d.name for d in apps_dir.iterdir() if d.is_dir())
            examples_dir = repo_root / "examples"
            if examples_dir.is_dir():
                available.extend(d.name for d in examples_dir.iterdir() if d.is_dir())
            raise FileNotFoundError(f"App '{app_name}' not found. Available: {', '.join(available) or 'none'}")

        dest = self.data_dir / "apps" / app_name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(app_src, dest)

        # Copy all SDK files (.js) into the app directory
        sdk_dir = assets_dir / "sdk"
        if sdk_dir.is_dir():
            for sdk_file in sdk_dir.iterdir():
                if sdk_file.suffix == ".js":
                    shutil.copy2(sdk_file, dest / sdk_file.name)

    def _write_manifest(self, app_name: str) -> None:
        """Write manifest.json with session metadata."""
        manifest = {
            "version": "1.0",
            "app": {
                "name": app_name,
                "entry": f"{app_name}/index.html",
                "title": app_name,
            },
            "session": {
                "id": self.session_id,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "token": "REDACTED",
            },
            "server": {
                "http_port": self.http_port,
                "ws_port": self.ws_port,
                "host": "127.0.0.1",
            },
        }
        self._write_json(self.data_dir / "manifest.json", manifest)

    def _init_data_contract(self) -> None:
        """Write initial state.json and actions.json."""
        self._state_version = 0
        self._write_json(
            self.data_dir / "state.json",
            {
                "version": 0,
                "status": "initializing",
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "title": "Initializing...",
                "message": "",
                "data": {},
                "actions_requested": [],
            },
        )
        self._write_json(
            self.data_dir / "actions.json",
            {
                "version": 0,
                "actions": [],
            },
        )

    def _set_permissions(self) -> None:
        """Restrict file permissions on sensitive contract files."""
        try:
            os.chmod(self.data_dir, 0o700)
            for name in ("manifest.json", "state.json", "actions.json"):
                path = self.data_dir / name
                if path.exists():
                    os.chmod(path, 0o600)
        except OSError:
            pass  # Windows doesn't support Unix permissions

    def _find_free_ports(self) -> tuple[int, int]:
        """Find two consecutive free ports, starting from defaults.

        Note: There is a TOCTOU race between checking port availability and the
        subprocess binding to it. This is mitigated by the health check in
        ensure_started(), which will detect a bind failure and raise RuntimeError.
        """
        http_port = self.DEFAULT_HTTP_PORT
        for _ in range(self.MAX_PORT_ATTEMPTS):
            ws_port = http_port + 1
            if self._port_available(http_port) and self._port_available(ws_port):
                return http_port, ws_port
            http_port += 2
        raise RuntimeError(
            f"Could not find free ports after {self.MAX_PORT_ATTEMPTS} attempts "
            f"(tried {self.DEFAULT_HTTP_PORT}-{http_port - 1})"
        )

    @staticmethod
    def _port_available(port: int) -> bool:
        """Check if a TCP port is available to bind.

        TOCTOU note: The port may be claimed between this check and the
        subprocess bind. The health check in ensure_started() catches this
        case and raises RuntimeError, which the caller retries.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return True
        except OSError:
            return False

    async def _health_check(self) -> bool:
        """Poll /_health until the server is ready."""
        url = f"http://127.0.0.1:{self.http_port}/_health"
        deadline = time.monotonic() + self.HEALTH_TIMEOUT

        while time.monotonic() < deadline:
            # Also check process hasn't died
            if self.process and self.process.poll() is not None:
                return False
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:  # nosec B310 — localhost-only
                    if resp.status == 200:
                        return True
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
            await asyncio.sleep(0.5)

        return False

    def _open_browser(self) -> None:  # pragma: no cover
        """Open the webview in Chrome app mode, or fall back to default browser."""
        url = self.url
        chrome_bin = self._find_chrome()
        opened = False

        if chrome_bin:
            try:
                self._chrome_profile = tempfile.mkdtemp(prefix="ocv-chrome-")
                chrome_args = [
                    chrome_bin,
                    f"--app={url}",
                    f"--user-data-dir={self._chrome_profile}",
                    "--no-first-run",
                    "--disable-default-apps",
                    "--window-size=960,800",
                ]

                # Position the window on the same screen as the terminal
                pos = self._get_cursor_screen_position()
                if pos is not None:
                    chrome_args.append(f"--window-position={pos[0]},{pos[1]}")

                self._chrome_process = subprocess.Popen(
                    chrome_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                opened = True
            except Exception:
                self._chrome_process = None
                # Clean up the temp directory created for Chrome's user data
                if self._chrome_profile is not None:
                    shutil.rmtree(self._chrome_profile, ignore_errors=True)
                self._chrome_profile = None

        if not opened:
            webbrowser.open(url)

    @staticmethod
    def _get_cursor_screen_position() -> tuple[int, int] | None:  # pragma: no cover
        """Get a window position on the same screen as the mouse cursor.

        Uses macOS CoreGraphics via ctypes (no deps, no permissions) to read
        the cursor location, then offsets a 960x800 window near it.
        Returns None on non-macOS or if detection fails.
        """
        if platform.system() != "Darwin":
            return None

        try:
            import ctypes
            import ctypes.util

            cg_path = ctypes.util.find_library("CoreGraphics")
            cf_path = ctypes.util.find_library("CoreFoundation")
            if not cg_path or not cf_path:
                return None

            cg = ctypes.CDLL(cg_path)
            cf = ctypes.CDLL(cf_path)

            class CGPoint(ctypes.Structure):
                _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

            cg.CGEventCreate.restype = ctypes.c_void_p
            cg.CGEventCreate.argtypes = [ctypes.c_void_p]
            cg.CGEventGetLocation.restype = CGPoint
            cg.CGEventGetLocation.argtypes = [ctypes.c_void_p]
            cf.CFRelease.restype = None
            cf.CFRelease.argtypes = [ctypes.c_void_p]

            event = cg.CGEventCreate(None)
            if not event:
                return None

            loc = cg.CGEventGetLocation(event)
            cf.CFRelease(event)

            # Place the window near the cursor, nudged left/up so it
            # doesn't land right under the pointer
            chrome_w, chrome_h = 960, 800
            pos_x = max(0, int(loc.x) - chrome_w // 2)
            pos_y = max(0, int(loc.y) - chrome_h // 2)

            return (pos_x, pos_y)

        except Exception:
            return None

    def _cleanup_chrome(self) -> None:  # pragma: no cover
        """Kill the Chrome process we spawned and remove its temp profile."""
        if self._chrome_process is not None:
            try:
                self._chrome_process.terminate()
                try:
                    self._chrome_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._chrome_process.kill()
                    self._chrome_process.wait(timeout=2)
            except Exception:
                pass
            self._chrome_process = None

        if self._chrome_profile is not None:
            try:
                shutil.rmtree(self._chrome_profile, ignore_errors=True)
            except Exception:
                pass
            self._chrome_profile = None

    @staticmethod
    def _find_chrome() -> str | None:  # pragma: no cover
        """Detect a Chromium-based browser."""
        if platform.system() == "Darwin":
            candidates = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c

        if platform.system() == "Windows":
            candidates = [
                os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c

        # Linux / PATH-based detection
        for name in ("google-chrome-stable", "google-chrome", "chromium-browser", "chromium"):
            path = shutil.which(name)
            if path:
                return path

        return None

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | None:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _write_json(path: Path, data: dict[str, Any]) -> None:
        tmp = path.with_suffix(".tmp")
        # Thread-safe restrictive permissions via os.open (avoids process-wide os.umask)
        content = json.dumps(data, indent=2)
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        tmp.replace(path)

    def _cleanup_process(self) -> None:
        """Kill subprocess if running and release the server lock."""
        if self.process is not None:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            except Exception:
                pass
            self.process = None

        # Remove PID file
        pid_file = self.data_dir / ".server.pid"
        if pid_file.exists():
            try:
                pid_file.unlink()
            except OSError:
                pass

        # Release the flock so the next session can start cleanly
        self._release_lock()

    def _atexit_cleanup(self) -> None:  # pragma: no cover
        """Safety net: kill subprocess and Chrome on interpreter exit."""
        self._cleanup_chrome()
        self._cleanup_process()


# ---------------------------------------------------------------------------
# MCP Server — exposes tools backed by WebviewSession
# ---------------------------------------------------------------------------

_session: WebviewSession | None = None
_session_lock: asyncio.Lock | None = None
_atexit_registered: bool = False


def _get_session_lock() -> asyncio.Lock:
    global _session_lock
    if _session_lock is None:
        _session_lock = asyncio.Lock()
    return _session_lock


async def _get_session() -> WebviewSession:
    """Get or create the global WebviewSession."""
    global _session
    async with _get_session_lock():
        if _session is None:
            _session = WebviewSession(open_browser=True)
        return _session


# ---------------------------------------------------------------------------
# Auto-reload: detect pipx/pip upgrades and restart seamlessly
# ---------------------------------------------------------------------------

_active_tool_calls: int = 0
_active_tool_calls_lock: asyncio.Lock | None = None


def _get_tool_calls_lock() -> asyncio.Lock:
    global _active_tool_calls_lock
    if _active_tool_calls_lock is None:
        _active_tool_calls_lock = asyncio.Lock()
    return _active_tool_calls_lock


# Note: _reload_pending and _signal_reload_requested are plain bools written from
# a signal handler thread and read from the asyncio loop. This relies on CPython's
# GIL making bool assignment atomic (a single STORE_NAME bytecode). This is safe in
# practice on CPython but technically implementation-defined. The proper fix would be
# a self-pipe (os.write + asyncio.add_reader), but the GIL guarantee is sufficient
# for this use case and avoids unnecessary complexity.
_reload_pending: bool = False
_reload_task: asyncio.Task | None = None
_RELOAD_CHECK_INTERVAL = 30  # seconds
_MAX_MONITOR_ERRORS = 10  # give up after this many consecutive errors

# Signal-triggered restart (SIGUSR1 from `openwebgoggles restart`)
_signal_reload_requested: bool = False


def _sigusr1_handler(signum: int, frame: Any) -> None:  # noqa: ARG001
    """Handle SIGUSR1 by setting a flag for the event loop to pick up.

    Async-signal-safe: this handler only sets a plain bool flag. No logging,
    no I/O, no lock acquisition, no memory allocation. The asyncio loop polls
    the flag via _signal_reload_monitor() and handles the actual reload logic.
    """
    global _signal_reload_requested
    _signal_reload_requested = True


def _task_done_callback(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks so they don't vanish silently."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Background task %r crashed: %s", task.get_name(), exc, exc_info=exc)


# MCP server PID file — written on startup so `openwebgoggles restart` can find us
_MCP_PID_DIR: Path | None = None


def _get_installed_version_info() -> tuple[str, Path | None]:
    """Return (version_string, dist_info_path) for the installed package.

    Returns ("unknown", None) when running from source without pip install.
    """
    try:
        dist = importlib.metadata.distribution("openwebgoggles")
        version = dist.metadata["Version"]
        dist_path = getattr(dist, "_path", None)
        if dist_path is not None:
            dist_path = Path(dist_path)
        return (version, dist_path)
    except importlib.metadata.PackageNotFoundError:
        return ("unknown", None)


def _get_site_packages_dirs() -> list[Path]:
    """Return candidate site-packages directories for the current environment."""
    dirs: list[Path] = []
    for p in sys.path:
        pp = Path(p)
        if pp.name == "site-packages" and pp.is_dir():
            dirs.append(pp)
    return dirs


def _read_version_fresh(dist_info_hint: Path | None = None) -> str:
    """Read installed version by reading METADATA file directly from disk.

    Bypasses importlib.metadata caches entirely, which don't always flush
    in pipx/venv installs after ``pip install --upgrade``.

    Strategy: (1) read METADATA from the known dist-info hint path,
    (2) fall back to scanning site-packages for any openwebgoggles dist-info,
    (3) fall back to importlib as last resort.
    """
    # Strategy 1: Direct file read from known dist-info path
    if dist_info_hint is not None:
        metadata_file = dist_info_hint / "METADATA"
        try:
            if metadata_file.is_file():
                for line in metadata_file.read_text(encoding="utf-8").splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass

    # Strategy 2: Scan site-packages for any openwebgoggles dist-info
    for site_dir in _get_site_packages_dirs():
        try:
            for entry in site_dir.iterdir():
                if entry.name.startswith("openwebgoggles-") and entry.name.endswith(".dist-info"):
                    metadata_file = entry / "METADATA"
                    try:
                        if metadata_file.is_file():
                            for line in metadata_file.read_text(encoding="utf-8").splitlines():
                                if line.startswith("Version:"):
                                    return line.split(":", 1)[1].strip()
                    except OSError:
                        continue
        except OSError:
            continue

    # Strategy 3: Fall back to importlib as last resort
    importlib.invalidate_caches()
    try:
        dist = importlib.metadata.distribution("openwebgoggles")
        return dist.metadata["Version"]
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


_stale_version_msg: str = ""


async def _notify_host_stale(message: str) -> None:
    """Attempt to send a log notification to the MCP host about staleness.

    Best-effort — if the MCP session is not available or the notification
    fails, the stale flag in _track_tool_call is the fallback.
    """
    try:
        server = getattr(mcp, "_mcp_server", None) or getattr(mcp, "server", None)
        if server is not None and hasattr(server, "send_log_message"):
            await server.send_log_message(level="error", data=message)
            logger.info("Sent stale notification to MCP host")
    except Exception:
        logger.debug("Could not send stale notification to MCP host (will notify on next tool call)")


def _mark_stale(old_version: str, new_version: str) -> None:
    """Mark the server as stale after a package upgrade.

    Instead of os.execv() (which breaks the MCP stdio protocol by restarting
    the handshake mid-session), we set a flag so subsequent tool calls return
    a clear error asking the user/agent to restart the MCP server.
    Also sends a best-effort log notification to the MCP host.
    """
    global _stale_version_msg
    _stale_version_msg = (
        f"OpenWebGoggles was updated ({old_version} → {new_version}) "
        f"but the MCP server is still running the old version. "
        f"Please restart the MCP server to pick up the new version."
    )
    logger.warning(_stale_version_msg)
    # Best-effort MCP notification (non-blocking)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_notify_host_stale(_stale_version_msg))
    except RuntimeError:
        pass  # No event loop — notification will happen via tool call rejection


async def _version_monitor() -> None:  # noqa: C901 — TODO: decompose version comparison logic
    """Background task: poll for package version changes and mark server stale.

    Two-tier detection: cheap mtime check every 30s, full version read only
    when the dist-info directory changes.  The initial metadata lookup runs
    in an executor to avoid blocking the MCP lifespan startup (which would
    cause -32001 timeout errors from the host).
    """
    global _reload_pending

    # Defer initial metadata lookup to a thread so lifespan yields immediately
    loop = asyncio.get_running_loop()
    startup_version, dist_info_path = await loop.run_in_executor(None, _get_installed_version_info)
    if startup_version == "unknown":
        logger.info("Package not installed via pip — version monitor disabled.")
        return

    logger.info("Version monitor started: v%s", startup_version)

    last_mtime: float | None = None
    if dist_info_path and dist_info_path.is_dir():
        try:
            last_mtime = dist_info_path.stat().st_mtime
        except OSError:
            pass

    consecutive_errors = 0

    while True:
        await asyncio.sleep(_RELOAD_CHECK_INTERVAL)

        try:
            # Tier 1: cheap mtime check
            mtime_changed = False
            if dist_info_path is not None and dist_info_path.is_dir():
                try:
                    current_mtime = dist_info_path.stat().st_mtime
                    if last_mtime is None or current_mtime != last_mtime:
                        mtime_changed = True
                    last_mtime = current_mtime
                except OSError:
                    # Directory gone — package is being upgraded
                    mtime_changed = True
            else:
                # Path lost or gone — always try a version read to recover
                mtime_changed = True

            if not mtime_changed:
                consecutive_errors = 0  # healthy cycle
                continue

            # Tier 2: full version read (only after mtime change)
            current_version = _read_version_fresh(dist_info_hint=dist_info_path)

            if current_version == "unknown":
                # Package temporarily missing during upgrade — retry next cycle.
                # Do NOT clear dist_info_path: we need it for recovery.
                last_mtime = None
                consecutive_errors = 0  # expected during upgrade, not an error
                continue

            # Re-discover dist-info path if we lost it (e.g. after upgrade)
            if dist_info_path is None or not dist_info_path.is_dir():
                _, dist_info_path = _get_installed_version_info()
                if dist_info_path and dist_info_path.is_dir():
                    try:
                        last_mtime = dist_info_path.stat().st_mtime
                    except OSError:
                        last_mtime = None

            if current_version == startup_version:
                # Mtime changed but same version — no upgrade
                consecutive_errors = 0
                continue

            # Version changed — mark server as stale
            logger.info(
                "Package updated: %s -> %s — marking server as stale",
                startup_version,
                current_version,
            )
            _reload_pending = True
            _mark_stale(startup_version, current_version)

            # Close webview session gracefully so a restart gets a clean slate
            global _session
            async with _get_session_lock():
                if _session is not None:
                    try:
                        await _session.close(message="Server needs restart (package updated).")
                    except Exception:
                        pass
                    _session = None

            # Stop monitoring — we've already flagged the staleness
            return

        except asyncio.CancelledError:
            return
        except (OSError, ValueError, RuntimeError, ImportError, StopIteration):
            consecutive_errors += 1
            if consecutive_errors >= _MAX_MONITOR_ERRORS:
                logger.error(
                    "Version monitor giving up after %d consecutive errors",
                    consecutive_errors,
                )
                return
            backoff = min(_RELOAD_CHECK_INTERVAL * (2.0**consecutive_errors), 300)
            logger.exception(
                "Version monitor error (attempt %d/%d, retry in %.0fs)",
                consecutive_errors,
                _MAX_MONITOR_ERRORS,
                backoff,
            )
            await asyncio.sleep(backoff)


async def _signal_reload_monitor() -> None:
    """Background task: poll for SIGUSR1 flag and trigger seamless restart."""
    global _reload_pending, _signal_reload_requested

    while True:
        await asyncio.sleep(0.5)
        if not _signal_reload_requested:
            continue

        # Reset flag immediately to prevent re-triggering every 0.5s
        _signal_reload_requested = False
        logger.info("SIGUSR1 received — reloading server.")
        _reload_pending = True

        # Wait for in-flight tool calls to drain (up to 60s)
        drain_deadline = time.monotonic() + 60
        while time.monotonic() < drain_deadline:
            async with _get_tool_calls_lock():
                if _active_tool_calls == 0:
                    break
            await asyncio.sleep(1)

        # Close webview session gracefully
        global _session
        async with _get_session_lock():
            if _session is not None:
                try:
                    await _session.close(message="Server reloading (restart requested).")
                except Exception:
                    pass
                _session = None

        _mark_stale("current", "reload-requested")


def _track_tool_call(fn):  # type: ignore[no-untyped-def]
    """Decorator: track in-flight tool calls for safe reload."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        global _active_tool_calls
        if _reload_pending:
            return {"error": _stale_version_msg or "Server needs restart after a package update."}
        async with _get_tool_calls_lock():
            _active_tool_calls += 1
        try:
            return await fn(*args, **kwargs)
        finally:
            async with _get_tool_calls_lock():
                _active_tool_calls -= 1

    return wrapper


# ---------------------------------------------------------------------------
# MCP Lifespan
# ---------------------------------------------------------------------------


def _write_mcp_pid() -> None:
    """Write our PID so ``openwebgoggles restart`` / ``status`` can find us.

    Never crashes the server — PID file is a convenience for CLI commands.
    """
    global _MCP_PID_DIR
    try:
        data_dir = _get_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        pid_file = data_dir / ".mcp.pid"
        fd = os.open(str(pid_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, str(os.getpid()).encode())
        finally:
            os.close(fd)
        _MCP_PID_DIR = data_dir
    except OSError:
        pass


def _cleanup_mcp_pid() -> None:
    """Remove .mcp.pid on shutdown."""
    if _MCP_PID_DIR is not None:
        pid_file = _MCP_PID_DIR / ".mcp.pid"
        try:
            # Only remove if it's our PID (os.execv reuses PID, so check)
            if pid_file.exists() and pid_file.read_text().strip() == str(os.getpid()):
                pid_file.unlink(missing_ok=True)
        except OSError:
            pass


@asynccontextmanager
async def lifespan(server: FastMCP):
    """MCP server lifecycle: version monitor + signal monitor on start, cleanup on shutdown."""
    global _reload_task

    # Register/re-register SIGUSR1 handler so it works even if main() was bypassed
    if platform.system() != "Windows":
        signal.signal(signal.SIGUSR1, _sigusr1_handler)

    # Create background tasks with names + done callbacks for crash visibility
    _reload_task = asyncio.create_task(_version_monitor(), name="version-monitor")
    _reload_task.add_done_callback(_task_done_callback)
    signal_task = asyncio.create_task(_signal_reload_monitor(), name="signal-monitor")
    signal_task.add_done_callback(_task_done_callback)

    # Write PID file so `openwebgoggles restart` and `openwebgoggles status` can find us
    _write_mcp_pid()

    yield

    # Cancel monitors
    if _reload_task is not None:
        _reload_task.cancel()
        try:
            await _reload_task
        except asyncio.CancelledError:
            pass
        _reload_task = None

    signal_task.cancel()
    try:
        await signal_task
    except asyncio.CancelledError:
        pass

    # Clean up PID file and webview session
    _cleanup_mcp_pid()

    global _session
    if _session is not None:
        try:
            await _session.close(message="MCP server shutting down.")
        except Exception:
            pass
        _session = None


# ---------------------------------------------------------------------------
# MCP Apps — dual-mode support (native iframe vs browser fallback)
# ---------------------------------------------------------------------------

_RESOURCE_URI = "ui://openwebgoggles/dynamic"

# Set to True when a host fetches the UI resource (proves MCP Apps support)
_host_fetched_ui_resource: bool = False

# Cached mode: "app" | "browser" | None (None = not yet determined)
_cached_mode: str | None = None


class AppModeState:
    """In-memory state for MCP Apps mode — no subprocess, no filesystem.

    When the host supports MCP Apps, state flows through structuredContent
    in tool results rather than state.json/actions.json on disk.
    """

    MAX_ACTION_QUEUE = 1000  # Cap to prevent unbounded memory growth

    def __init__(self) -> None:
        self.state: dict[str, Any] = {}
        # Start version at current epoch-ms so each server restart produces versions
        # strictly larger than any previous session.  The MCP Apps iframe has a
        # monotonicity guard (_isStateDowngrade) that rejects version <= current —
        # without this, a server restart (resetting to v1) would be silently ignored
        # by an iframe that already holds state from the previous process.
        self.state_version: int = int(time.time() * 1000)
        self.actions: list[dict[str, Any]] = []
        self._state_lock = threading.Lock()
        self._actions_lock = threading.Lock()

    def write_state(self, state: dict[str, Any]) -> None:
        with self._state_lock:
            self.state_version += 1
            state["version"] = self.state_version
            self.state = state

    def merge_state(
        self,
        partial: dict[str, Any],
        validator: Callable | None = None,
    ) -> dict[str, Any]:
        with self._state_lock:
            merged = json.loads(json.dumps(self.state))  # deep copy
            _deep_merge(merged, partial)
            if validator:
                validator(merged)
            self.state_version += 1
            merged["version"] = self.state_version
            self.state = merged
            return merged

    def read_actions(self) -> list[dict[str, Any]]:
        with self._actions_lock:
            return list(self.actions)

    def read_and_clear_actions(self) -> list[dict[str, Any]]:
        """Atomically read and clear — prevents lost actions between read+clear."""
        with self._actions_lock:
            actions = list(self.actions)
            self.actions.clear()
            return actions

    def add_action(self, action: dict[str, Any]) -> None:
        with self._actions_lock:
            if len(self.actions) >= self.MAX_ACTION_QUEUE:
                logger.warning("MCP Apps: Action queue full (%d), dropping oldest", self.MAX_ACTION_QUEUE)
                self.actions.pop(0)
            self.actions.append(action)

    def clear_actions(self) -> None:
        with self._actions_lock:
            self.actions.clear()

    def clear(self) -> None:
        with self._state_lock:
            self.state = {}
            # Reset to a new timestamp epoch so the next session always wins the
            # downgrade check in the iframe, even if the iframe stayed open.
            self.state_version = int(time.time() * 1000)
        self.clear_actions()


_app_mode_state: AppModeState | None = None

_DIAG_LOG = _get_data_dir() / "mode-diag.log"


def _write_diag(fn: str, lines: list[str], *, result: object = None) -> None:
    """Append diagnostic info to a persistent file + stderr."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    msg = f"[{ts}] {fn}: {' | '.join(lines)}"
    if result is not None:
        msg += f" -> {result}"
    print(f"[OWG] {msg}", file=sys.stderr)
    try:
        with open(_DIAG_LOG, "a") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def _check_host_supports_ui(ctx: Context | None) -> bool:
    """Check client capabilities for io.modelcontextprotocol/ui extension.

    MCP Apps hosts advertise UI support during the initialize handshake.

    Detection strategies (tried in order):
    1. capabilities.extensions has "io.modelcontextprotocol/ui" (Claude Desktop direct)
    2. capabilities.experimental has "io.modelcontextprotocol/ui"
    3. clientInfo.name is "local-agent-mode-*" — Claude Code's MCP client name when
       running as an agent host. Claude Code renders structuredContent from tool
       results as an inline preview pane (MCP Apps mode).
    4. _host_fetched_ui_resource flag (set when resources/read was called for ui://)
    """
    diag: list[str] = []
    if ctx is not None:
        try:
            client_params = ctx.session.client_params
            client_info = getattr(client_params, "clientInfo", None)
            client_name = getattr(client_info, "name", "") if client_info else ""
            caps = client_params.capabilities
            diag.append(f"client={client_name}")
            diag.append(f"extra={getattr(caps, 'model_extra', {})}")

            # Strategy 1: extensions field (Claude Desktop direct connection)
            extensions = getattr(caps, "extensions", None)
            if isinstance(extensions, dict) and "io.modelcontextprotocol/ui" in extensions:
                _write_diag("check_ui", diag, result="MATCH:extensions")
                return True

            # Strategy 2: experimental field
            if caps.experimental and "io.modelcontextprotocol/ui" in caps.experimental:
                _write_diag("check_ui", diag, result="MATCH:experimental")
                return True

            # Strategy 3: "local-agent-mode-*" — Claude Code's agent MCP client name.
            # Claude Code renders structuredContent inline as a preview pane.
            if isinstance(client_name, str) and client_name.startswith("local-agent-mode-"):
                _write_diag("check_ui", diag, result="MATCH:local-agent-bridge")
                return True

            diag.append(f"exp={caps.experimental}")
        except Exception as exc:
            diag.append(f"ERR:{exc!r}")
    else:
        diag.append("ctx=None")
    diag.append(f"fetched={_host_fetched_ui_resource}")
    _write_diag("check_ui", diag, result=_host_fetched_ui_resource)
    return _host_fetched_ui_resource


def _resolve_mode(ctx: Context | None) -> str:
    """Resolve and cache the operating mode. Returns 'app' or 'browser'.

    Once determined, the mode is cached for the session lifetime.
    Call _reset_mode() (via openwebgoggles_close) to clear the cache.
    """
    global _cached_mode  # noqa: PLW0603
    if _cached_mode is not None:
        _write_diag("resolve", [f"cached={_cached_mode}"])
        return _cached_mode
    if _check_host_supports_ui(ctx):
        _cached_mode = "app"
    elif ctx is not None:
        # Only cache browser mode when we have a real ctx (to avoid
        # prematurely locking in browser mode before ctx is available)
        _cached_mode = "browser"
    result = _cached_mode or "browser"
    _write_diag("resolve", [f"ctx={'yes' if ctx else 'no'}", f"mode={result}"])
    return result


def _reset_mode() -> None:
    """Reset the cached mode (called by openwebgoggles_close)."""
    global _cached_mode  # noqa: PLW0603
    _cached_mode = None


def _stop_any_running_server() -> None:
    """Kill any webview server subprocess found via PID files in known data dirs.

    Called by openwebgoggles_close() so end-to-end cleanup works regardless of
    whether the server was started by WebviewSession (browser mode) or externally
    (e.g. ``openwebgoggles init`` / dev preview).  Checks three locations:
      • <cwd>/.openwebgoggles/   — normal project-level data dir
      • <cwd>/.openwebgoggles-dev/ — standalone dev / preview-start data dir
      • ~/.openwebgoggles/        — user-level data dir

    SIGTERM is sent so the server can flush and clean up; errors (process already
    dead, permission denied, etc.) are silently ignored.
    """
    cwd = Path.cwd()
    data_dirs = [
        cwd / ".openwebgoggles",
        cwd / ".openwebgoggles-dev",
        Path.home() / ".openwebgoggles",
    ]
    for data_dir in data_dirs:
        pid_file = data_dir / ".server.pid"
        if not pid_file.exists():
            continue
        pid_str = pid_file.read_text().strip()
        if not pid_str.isdigit():
            continue  # Corrupt/foreign PID file — leave it alone
        pid = int(pid_str)
        remove = False
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Stopped webview server (PID %d) from %s", pid, data_dir)
            remove = True
        except ProcessLookupError:
            remove = True  # Already dead — stale PID file, clean up
        except PermissionError:
            pass  # Not our process — leave it
        except Exception:
            logger.debug("Could not stop server at %s", data_dir, exc_info=True)
        if remove:
            try:
                pid_file.unlink(missing_ok=True)
            except OSError:
                pass


def _is_app_mode() -> bool:
    """Check if we're running in MCP Apps mode.

    Uses the cached mode if available, otherwise falls back to the
    resource-fetch flag for backward compatibility.
    """
    return _cached_mode == "app" or _host_fetched_ui_resource


def _get_app_state() -> AppModeState:
    """Get or create the app-mode state singleton."""
    global _app_mode_state  # noqa: PLW0603
    if _app_mode_state is None:
        _app_mode_state = AppModeState()
    return _app_mode_state


def _get_bundled_html() -> str:
    """Get the bundled HTML for the MCP Apps resource."""
    try:
        try:
            from .bundler import bundle_html
        except ImportError:
            from bundler import bundle_html  # noqa: I001
        return bundle_html()
    except Exception:
        logger.error("Failed to bundle HTML for MCP Apps resource", exc_info=True)
        return "<html><body><p>Error: Failed to load OpenWebGoggles UI</p></body></html>"


def _make_merge_validator() -> Callable | None:
    """Build a post-merge SecurityGate validator (or None if no gate)."""
    if not _security_gate:
        return None

    def _validate_merged(merged_state: dict) -> None:
        merged_raw = json.dumps(merged_state, separators=(",", ":"))
        valid, err, _ = _security_gate.validate_state(merged_raw)
        if not valid:
            raise ValueError(f"Merged state validation failed: {err}")

    return _validate_merged


mcp = FastMCP(
    "openwebgoggles",
    instructions="""\
Human-in-the-loop (HITL) UI panels for agents. Show interactive data, forms, and dashboards; collect structured user input.

## When to use these tools

Use openwebgoggles instead of plain text or AskUserQuestion when ANY of these apply:

- **Multiple items to review**: Lists of PRs, issues, findings, migrations, configs, etc. \
where the user needs to act on each one (approve/reject/edit/skip).
- **Complex decisions with forms**: When you need more than a yes/no — dropdowns, text \
fields, checkboxes, or multi-field input.
- **Structured data review**: Tables, key-value pairs, nested objects, or arrays where \
visual layout helps comprehension.
- **Multi-step workflows**: Wizards, sequential approvals, or processes where you call \
openwebgoggles repeatedly for each step.
- **Batch operations**: When the user needs to triage, categorize, or make choices across \
many items at once.
- **Rich context alongside a decision**: When showing code diffs, logs, configs, or \
detailed context that would be hard to read as plain text.

Do NOT use these tools for simple single-choice questions with 2-3 options — use \
AskUserQuestion for those.

## CRITICAL: Step-by-step wizard for multiple items

When the user needs to review/decide on multiple items (issues, PRs, findings, configs, \
migrations, etc.), ALWAYS present them **one at a time** as a step-by-step wizard. \
NEVER dump all items into a single long scrolling page.

For N items, call openwebgoggles N times in sequence:
- Show "Item 1 of N" with context + form for that item
- Collect the response, then show "Item 2 of N", etc.
- After the last item, show a summary and call openwebgoggles_close

Each step should show:
1. An "items" section with just the current item (title + subtitle)
2. A "text" section with detail/context about that item
3. A "form" section with the decision fields for that item
4. Navigation buttons: "Next →" (approve) and optionally "← Previous" (ghost)
5. The message should say "Item X of N"

Example — step 1 of a 3-item wizard:
```
openwebgoggles({
  "title": "Issue Triage",
  "message": "Issue 1 of 3",
  "status": "pending_review",
  "data": {"sections": [
    {"type": "items", "title": "Issue #42", "items": [
      {"title": "Login timeout on slow connections", "subtitle": "Bug | 3 days ago | 4 comments"}
    ]},
    {"type": "text", "content": "Detailed description of the issue..."},
    {"type": "form", "title": "Your Decision", "fields": [
      {"key": "priority", "label": "Priority", "type": "select", "options": ["Critical", "High", "Medium", "Low"]},
      {"key": "assignee", "label": "Assignee", "type": "text", "placeholder": "GitHub username..."},
      {"key": "action", "label": "Decision", "type": "select", "options": ["Fix this sprint", "Backlog", "Needs more info", "Won't fix"]},
      {"key": "notes", "label": "Notes", "type": "textarea", "placeholder": "Optional..."}
    ]}
  ]},
  "actions_requested": [
    {"id": "next", "label": "Next Issue →", "type": "approve"},
    {"id": "skip_all", "label": "Skip All", "type": "ghost"}
  ]
})
```

Then call openwebgoggles again for item 2, then 3, etc. Collect all responses, \
then show a summary and call openwebgoggles_close.

## Quick patterns

**Single item review or form input**:
```
openwebgoggles({
  "title": "Configuration",
  "data": {"sections": [
    {"type": "form", "fields": [
      {"key": "name", "label": "Name", "type": "text"},
      {"key": "env", "label": "Environment", "type": "select", "options": ["dev", "prod"]},
      {"key": "confirm", "label": "I confirm", "type": "checkbox"}
    ]}
  ]},
  "actions_requested": [{"id": "submit", "label": "Submit", "type": "approve"}]
})
```

## Markdown support

Any text content can be rendered as formatted markdown instead of plain text. \
Add a `format: "markdown"` flag to opt in:

- **Top-level message**: add `"message_format": "markdown"` to the state object
- **Text sections**: add `"format": "markdown"` to the section object
- **Static fields**: add `"format": "markdown"` to the field object
- **Field descriptions**: add `"description_format": "markdown"` to the field object
- **Item titles/subtitles**: add `"format": "markdown"` to the item object

Without the flag, content renders as plain escaped text (default).

Example — text section with markdown:
```
{"type": "text", "content": "## Summary\\n\\n- **Fixed** auth bug\\n- Added `retry` logic\\n\\n```python\\ndef retry(fn):\\n    ...\\n```", "format": "markdown"}
```

## Rich section types

Beyond form/items/text/actions, these section types are available:

**progress** — Task progress tracker (pair with `openwebgoggles_update` for live updates):
```
{"type": "progress", "title": "Running Tests", "tasks": [
  {"label": "Unit tests", "status": "completed"},
  {"label": "Integration", "status": "in_progress"},
  {"label": "E2E", "status": "pending"}
], "percentage": 45}
```
Task statuses: pending, in_progress, completed, failed, skipped.

**log** — Scrolling terminal output (supports ANSI colors):
```
{"type": "log", "title": "Build Output", "lines": ["$ npm run build", "Building..."], "autoScroll": true, "maxLines": 500}
```

**diff** — Unified diff with line numbers and color:
```
{"type": "diff", "title": "Changes", "content": "--- a/file.py\\n+++ b/file.py\\n@@ -1,3 +1,3 @@\\n def hello():\\n-    print('old')\\n+    print('new')"}
```

**table** — Sortable data table (optional row selection):
```
{"type": "table", "title": "Results", "columns": [
  {"key": "name", "label": "Test"}, {"key": "status", "label": "Status"}
], "rows": [{"name": "auth", "status": "pass"}], "selectable": true}
```

**tabs** — Tabbed content (client-side switching, no round-trip):
```
{"type": "tabs", "tabs": [
  {"id": "overview", "label": "Overview", "sections": [{"type": "text", "content": "..."}]},
  {"id": "details", "label": "Details", "sections": [{"type": "form", "fields": [...]}]}
]}
```

## Non-blocking updates with openwebgoggles_update

Use `openwebgoggles_update` to push UI changes without waiting for user action. \
This is ideal for progress tracking, streaming logs, and live status:

```
openwebgoggles_update({"status": "processing", "message": "Running tests..."}, merge=True)
```

Or use presets for common patterns:
```
openwebgoggles_update({"tasks": [...], "percentage": 50}, preset="progress")
```

## Field validation

Fields support client-side validation with `required`, `pattern`, `minLength`, `maxLength`:
```
{"key": "email", "type": "email", "label": "Email", "required": true,
 "pattern": "^[^@]+@[^@]+$", "errorMessage": "Enter a valid email"}
```
Required fields block form submission until filled. Errors show inline.

## Conditional fields (behaviors)

Show/hide fields or enable/disable buttons based on other field values:
```
{"data": {"sections": [...]},
 "behaviors": [
   {"when": {"field": "type", "equals": "custom"}, "show": ["custom_name"]},
   {"when": {"field": "confirm", "checked": true}, "enable": ["submit"]}
]}
```

## Layout system

Use `layout` + `panels` for multi-panel layouts:
```
{"layout": {"type": "sidebar", "sidebarWidth": "280px"},
 "panels": {
   "sidebar": {"sections": [{"type": "items", "items": [...]}]},
   "main": {"sections": [{"type": "text", "content": "..."}]}
}}
```
Layout types: sidebar, split.
""",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# MCP Apps: advertise io.modelcontextprotocol/ui extension in server capabilities
# ---------------------------------------------------------------------------
# The MCP Apps spec requires bidirectional negotiation: both client AND server
# must advertise the extension during initialize.  FastMCP doesn't expose a
# direct API for setting server extensions, so we wrap get_capabilities() on
# the low-level server to inject the extension field.

_original_get_capabilities = mcp._mcp_server.get_capabilities


def _patched_get_capabilities(*args, **kwargs):  # type: ignore[no-untyped-def]  # noqa: ANN002, ANN003, ANN201
    caps = _original_get_capabilities(*args, **kwargs)
    # ServerCapabilities has extra="allow" so this field serializes through
    caps.extensions = {  # type: ignore[attr-defined]
        "io.modelcontextprotocol/ui": {
            "mimeTypes": ["text/html;profile=mcp-app"],
        },
    }
    return caps


mcp._mcp_server.get_capabilities = _patched_get_capabilities


# ---------------------------------------------------------------------------
# MCP Apps resource — serves bundled HTML for native iframe rendering
# ---------------------------------------------------------------------------


@mcp.resource(
    _RESOURCE_URI,
    name="OpenWebGoggles Dynamic UI",
    description="Interactive dashboard renderer for MCP Apps hosts",
    mime_type="text/html;profile=mcp-app",
    meta={"ui": {}},
)
def dynamic_app_resource() -> str:
    """Return the bundled HTML for the dynamic renderer (MCP Apps mode)."""
    global _host_fetched_ui_resource, _cached_mode  # noqa: PLW0603
    _host_fetched_ui_resource = True
    _cached_mode = "app"
    logger.info("MCP Apps: Host fetched UI resource — switching to app mode")
    return _get_bundled_html()


# ---------------------------------------------------------------------------
# MCP Apps action receiver — app-only tool called by the iframe
# ---------------------------------------------------------------------------


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI, "visibility": ["app"]}})
@_track_tool_call
async def _owg_action(
    action_id: str,
    action_type: str,
    value: Any = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Receive a user action from the MCP App iframe.

    This tool is called by the embedded iframe (via tools/call through the host)
    when the user clicks a button or submits a form. Actions are stored in an
    in-memory queue that the agent reads via openwebgoggles_read().
    """
    if _resolve_mode(None) != "app":
        return {"error": "Not in MCP Apps mode"}

    # Reject internal action_ids (underscore prefix is reserved for navigation bookkeeping)
    if action_id.startswith("_"):
        return {"error": "action_id starting with '_' is reserved for internal use"}

    action: dict[str, Any] = {
        "action_id": action_id,
        "type": action_type,
        "value": value,
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if context:
        action["context"] = context

    # Validate action via SecurityGate (use validate_action, not validate_state)
    if _security_gate:
        valid, err = _security_gate.validate_action(action)
        if not valid:
            return {"error": f"Action rejected by security gate: {err}"}

    app_state = _get_app_state()
    app_state.add_action(action)
    return {"received": True}


# ---------------------------------------------------------------------------
# MCP Tools — OpenWebGoggles HITL interface
# ---------------------------------------------------------------------------


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI}})
@_track_tool_call
async def openwebgoggles(
    state: dict[str, Any],
    timeout: int = 300,
    app: str = "dynamic",
    preset: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Show an interactive UI panel and wait for the user to respond.

    Use this whenever you need a human in the loop: approval workflows,
    code/PR review, data display, structured input collection, progress
    tracking, or any time the agent needs to show results and wait for
    feedback. This is the primary tool for human-in-the-loop (HITL) interactions.

    Trigger on any scenario such as:
    - "approve / review / confirm" — show data and collect approval
    - "show me / display / visualize" — render tables, charts, metrics
    - "fill out / input / collect" — present a form and gather responses
    - "waiting for user / need feedback" — block until user acts

    Pass a state object describing the UI; this tool blocks until the user
    clicks an action button, then returns their response.

    The state object schema:
      - title (str): Header title
      - message (str, optional): Description/instructions shown to the user
      - message_format (str, optional): Set to "markdown" to render message as markdown
      - message_className (str, optional): CSS class(es) to add to the message box
      - status (str, optional): Badge text (e.g. "pending_review", "waiting_input")
      - custom_css (str, optional): Custom CSS injected as a <style> tag (validated for safety)
      - data (dict): UI layout with optional "sections" array. Each section has:
          - type: "form" | "items" | "text" | "actions" | "progress" | "log" | "diff" | "table" | "tabs" | "metric" | "chart"
          - title (str, optional): Section heading
          - id (str, optional): Section identifier (included in action context)
          - format (str, optional): Set to "markdown" for markdown rendering
          - className (str, optional): CSS class(es) to add to this section
          - fields (list): For "form" sections — input fields
          - items (list): For "items" sections — list rows
          - content (str): For "text" and "diff" sections
          - actions (list): Buttons within the section
          - tasks (list): For "progress" sections — [{label, status}]
          - percentage (number): For "progress" sections — 0-100
          - lines (list): For "log" sections — array of log line strings
          - columns (list): For "table" sections — [{key, label}]
          - rows (list): For "table" sections — array of row objects
          - clickable (bool): For "table" sections — enable row click drill-down
          - clickActionId (str): For "table" sections — action ID sent on row click
          - navigateToField (str): For "table" sections — row field containing page key for client-side navigation
          - tabs (list): For "tabs" sections — [{id, label, sections: [...]}]
          - cards (list): For "metric" sections — [{label, value, unit?, change?, changeDirection?, sparkline?}]
          - chartType (str): For "chart" sections — "bar"|"line"|"area"|"pie"|"donut"|"sparkline"
            Chart data can be provided as data: {labels, datasets} OR as columns/rows (same format as table sections).
      - pages (dict, optional): Multi-page SPA navigation. Each key is a page ID:
          {page_id: {label, hidden?: bool, data: {sections: [...]}, actions_requested?: [...]}}
          When present, renders a navigation bar for instant client-side page switching.
          Set hidden: true on a page to exclude it from the nav bar (still reachable via navigateTo).
      - showNav (bool, optional): Show the page navigation bar. Default: true.
          Set to false when navigation is handled entirely through navigateTo buttons/items/tables.
      - activePage (str, optional): Which page to show initially (must be a key in pages)
      - actions_requested (list): Top-level action buttons, each with:
          - id (str): Unique action identifier
          - label (str): Button text
          - type/style: "approve"|"reject"|"submit"|"primary"|"danger"|"success"|"warning"|"ghost"
          - navigateTo (str, optional): Page key for client-side navigation (no agent round-trip)
      - behaviors (list, optional): Client-side conditional field rules.
          Each: {when: {field, equals|in|checked|...}, show|hide|enable|disable: [keys]}
      - layout (dict, optional): Multi-panel layout. {type: "sidebar"|"split", sidebarWidth?}
      - panels (dict, optional): Panel content. {sidebar: {sections}, main: {sections}}

    Field types: text, textarea, number, select, checkbox, email, url, static
    Each field: {key, label, type, value?, default?, placeholder?, description?, options?, format?,
                 required?, pattern?, minLength?, maxLength?, errorMessage?}
    Items: {title, subtitle?, id?, format?, className?, actions?, navigateTo?}

    Custom styling:
      - className: Available on sections, fields, and items. Alphanumeric + hyphens + spaces.
      - custom_css: Raw CSS string. Dangerous patterns (expression, @import, javascript:url, etc.) are blocked.
      - Built-in utility classes (no custom_css needed):
        owg-diff-add, owg-diff-remove, owg-diff-context (diff highlighting)
        owg-mono, owg-code (monospace text)
        owg-pill, owg-pill-green/red/blue/yellow/neutral (badge pills)
        owg-callout-info/warn/error/success (callout boxes)
        owg-text-green/red/blue/yellow/muted/dim (text colors)
        owg-compact, owg-no-border, owg-zebra (layout helpers for item lists)

    Presets (shorthand for common patterns):
      - preset="progress": state={tasks: [...], percentage: N}
      - preset="confirm": state={title, message, details?}
      - preset="log": state={lines: [...], maxLines?}

    Returns the user's response with an "actions" array, where each action has:
      - action_id: Which button was clicked
      - type: Action type
      - value: Collected form data (dict) or boolean
      - context (optional): {item_index, item_id, section_index, section_id} for per-item actions

    Example:
        result = openwebgoggles({
            "title": "Code Review",
            "message": "Please review these changes.",
            "data": {
                "sections": [
                    {"type": "text", "title": "Summary", "content": "Refactored auth module"},
                    {"type": "form", "title": "Feedback", "fields": [
                        {"key": "comments", "label": "Comments", "type": "textarea"}
                    ]}
                ]
            },
            "actions_requested": [
                {"id": "approve", "label": "Approve", "type": "approve"},
                {"id": "reject", "label": "Request Changes", "type": "reject"}
            ]
        })

    Example — review a list of items with per-item actions:
        result = openwebgoggles({
            "title": "PR Triage",
            "message": "Review these pull requests.",
            "data": {"sections": [
                {"type": "items", "title": "Open PRs", "items": [
                    {"title": "#42 Fix auth bug", "subtitle": "2 files, +15 -3"},
                    {"title": "#43 Add dark mode", "subtitle": "8 files, +230 -45"},
                    {"title": "#44 Bump deps", "subtitle": "1 file, +5 -5"}
                ]},
                {"type": "form", "title": "Batch Action", "fields": [
                    {"key": "action", "label": "Apply to all", "type": "select",
                     "options": ["Approve", "Request changes", "Skip"]}
                ]}
            ]},
            "actions_requested": [
                {"id": "apply", "label": "Apply", "type": "approve"},
                {"id": "cancel", "label": "Cancel", "type": "reject"}
            ]
        })
    """
    if preset:
        try:
            state = _expand_preset(preset, state)
        except ValueError as e:
            return {"error": str(e)}

    # Validate eagerly so the agent gets a clear error; use sanitized state
    # (which has aliases normalized to canonical values) for everything downstream.
    if _security_gate:
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, sanitized = _security_gate.validate_state(raw)
        if not valid:
            return {"error": f"State validation failed: {err}"}
        state = sanitized

    mode = _resolve_mode(ctx)

    # ── App mode: return immediately with structuredContent ─────────────
    # The host renders an iframe AFTER the tool returns, so we must NOT
    # block here.  User actions arrive via _owg_action → openwebgoggles_read().
    if mode == "app":
        app_state = _get_app_state()
        app_state.clear_actions()
        app_state.write_state(state)
        title = state.get("title", "Webview")
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=(
                        f'UI ready: "{title}". '
                        "Tell the user to click the **Preview** button (▶) in the tool result "
                        "to open the interactive panel, then poll openwebgoggles_read() for their response."
                    ),
                )
            ],
            structuredContent=state,
        )

    # ── Browser mode: start subprocess, block until user acts ──────────
    session = await _get_session()
    await session.ensure_started(app)
    session.clear_actions()
    session.write_state(state)

    async def _progress(elapsed: float, total: float) -> None:
        if ctx:
            await ctx.report_progress(elapsed, total)

    result = await session.wait_for_action(
        timeout=timeout,
        on_progress=_progress if ctx else None,
    )
    if result is None:
        return {"error": f"Timed out after {timeout}s waiting for user action."}
    return result


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI}})
@_track_tool_call
async def openwebgoggles_read(clear: bool = False) -> dict[str, Any]:
    """Read the current user actions from the OpenWebGoggles panel.

    Poll this after openwebgoggles() returns (MCP Apps / Claude Desktop) to
    check if the human has submitted a response. Use in a polling loop:
    call openwebgoggles_read() repeatedly until actions are present.

    Returns the actions array (may be empty if no response yet).
    Set clear=True to clear actions after reading so the next poll starts fresh.
    """
    mode = _resolve_mode(None)

    # ── App mode: read from in-memory queue ────────────────────────────
    if mode == "app":
        app_state = _get_app_state()
        if clear:
            # Atomic read+clear prevents losing actions submitted between read and clear
            actions = app_state.read_and_clear_actions()
        else:
            actions = app_state.read_actions()
        return {"version": len(actions), "actions": actions}

    # ── Browser mode ───────────────────────────────────────────────────
    session = await _get_session()
    if not session._started:
        return {"version": 0, "actions": []}

    actions = session.read_actions()
    if clear and actions.get("actions"):
        session.clear_actions()

    return actions


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI}})
@_track_tool_call
async def openwebgoggles_update(
    state: dict[str, Any],
    merge: bool = False,
    preset: str | None = None,
    app: str = "dynamic",
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Push a live UI update to the open OpenWebGoggles panel without blocking.

    Use this to stream progress updates, append log lines, swap data, or
    change status while the panel is open — without waiting for the human
    to act. Ideal for long-running tasks where you want to show real-time
    feedback (e.g. build progress, live metrics, step-by-step status).

    Args:
        state: The state object (same schema as openwebgoggles).
        merge: If True, deep-merge into existing state instead of full replacement.
               Dicts are merged recursively. Lists are replaced, not appended.
        preset: Optional preset name to expand state from shorthand.
                "progress" — takes {tasks: [...], percentage: N}
                "confirm" — takes {title, message, details?}
                "log" — takes {lines: [...], maxLines?}
        app: App to use (default: "dynamic").

    Returns: {"updated": true, "version": N}
    """
    if preset:
        try:
            state = _expand_preset(preset, state)
        except ValueError as e:
            return {"error": str(e)}

    # Validate eagerly; use sanitized state (aliases normalized) for everything downstream.
    if _security_gate:
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, sanitized = _security_gate.validate_state(raw)
        if not valid:
            return {"error": f"State validation failed: {err}"}
        state = sanitized

    validator = _make_merge_validator()
    mode = _resolve_mode(ctx)

    # ── App mode: update in-memory state, return structuredContent ─────
    if mode == "app":
        app_state = _get_app_state()
        if merge:
            try:
                merged = app_state.merge_state(state, validator=validator)
            except ValueError as e:
                return {"error": str(e)}
            return CallToolResult(
                content=[TextContent(type="text", text=f"Updated (v{app_state.state_version})")],
                structuredContent=merged,
            )
        app_state.write_state(state)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Updated (v{app_state.state_version})")],
            structuredContent=state,
        )

    # ── Browser mode ───────────────────────────────────────────────────
    session = await _get_session()
    try:
        await session.ensure_started(app)
    except Exception:
        logger.warning("Failed to start webview", exc_info=True)
        return {"error": "Failed to start webview server"}

    # Do NOT clear actions — preserve pending user actions
    if merge:
        try:
            merged = session.merge_state(state, validator=validator)
        except ValueError as e:
            return {"error": str(e)}
        return {"updated": True, "version": merged.get("version", 0)}

    session.write_state(state)
    return {"updated": True, "version": session._state_version}


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI}})
@_track_tool_call
async def openwebgoggles_status() -> dict[str, Any]:
    """Check whether an OpenWebGoggles human-in-the-loop session is active.

    Returns the session state without modifying anything. Use before calling
    openwebgoggles_read() or openwebgoggles_update() to verify a panel is open.
    """
    mode = _resolve_mode(None)

    # ── App mode ───────────────────────────────────────────────────────
    if mode == "app":
        app_state = _get_app_state()
        return {
            "active": bool(app_state.state),
            "mode": "mcp_apps",
            "version": app_state.state_version,
        }

    # ── Browser mode ───────────────────────────────────────────────────
    async with _get_session_lock():
        if _session is None or not _session._started:
            return {"active": False, "mode": "browser"}
        return {
            "active": True,
            "mode": "browser",
            "alive": _session.is_alive(),
            "url": _session.url,
            "session_id": _session.session_id,
        }


@mcp.tool(meta={"ui": {"resourceUri": _RESOURCE_URI}})
@_track_tool_call
async def openwebgoggles_close(message: str = "Session complete.") -> dict[str, Any]:
    """Close the OpenWebGoggles panel and end the human-in-the-loop session.

    Shows a farewell message to the user before closing. Blocks until the
    browser window is confirmed closed. Idempotent — safe to call even if
    no session is active. Always call this when the HITL workflow is complete.
    """
    global _session, _app_mode_state, _host_fetched_ui_resource
    # Validate close message for XSS before passing to browser
    if _security_gate and message:
        xss_warnings = _security_gate._scan_xss(message, "webview_close.message")
        if xss_warnings:
            return {"error": f"Close message rejected by security gate: {xss_warnings[0]}"}

    mode = _resolve_mode(None)

    # ── App mode: clear in-memory state and reset mode ─────────────────
    if mode == "app":
        _host_fetched_ui_resource = False
        _reset_mode()
        if _app_mode_state is not None:
            _app_mode_state.clear()
        _stop_any_running_server()
        return {"status": "ok", "message": "Webview closed."}

    # ── Browser mode ───────────────────────────────────────────────────
    _reset_mode()
    async with _get_session_lock():
        if _session is None or not _session._started:
            _stop_any_running_server()
            return {"status": "ok", "message": "No active session."}

        try:
            await _session.close(message=message)
        except Exception:
            logger.warning("Error closing session", exc_info=True)
            _stop_any_running_server()
            return {"error": "Failed to close session"}

        _session = None
        _stop_any_running_server()
        return {"status": "ok", "message": "Webview closed."}


# ---------------------------------------------------------------------------
# Init command — bootstrap OpenWebGoggles for a specific editor
# ---------------------------------------------------------------------------

_EDITORS = ["claude", "claude-desktop", "opencode"]

# Default config directories per editor (when user doesn't specify a target).
# Claude Code uses project-level .mcp.json, so cwd is the right default.
# Claude Desktop uses a global config at ~/Library/Application Support/Claude/.
# OpenCode has a global config at ~/.config/opencode/, which makes more sense
# as a default since you typically want the MCP server available everywhere.
_EDITOR_DEFAULT_DIRS: dict[str, Path | None] = {
    "claude": None,  # None means cwd
    "claude-desktop": None,  # handled specially — platform-specific global config
    "opencode": Path.home() / ".config" / "opencode",
}

# Accepted aliases for the MCP server config key.  Editors and registries may
# use different names (e.g. "webview", "open-webview") — we treat all of these
# as equivalent so `doctor` and `init` work regardless of the key chosen.
_SERVER_NAME_ALIASES: frozenset[str] = frozenset(
    {
        "openwebgoggles",
        "open-webgoggles",
        "open-web-goggles",
        "openwebview",
        "open-webview",
        "open-web-view",
        "webview",
        "owg",
    }
)


def _find_server_key(servers: dict[str, Any]) -> str | None:
    """Return the first config key that matches a known server alias, or None."""
    for key in servers:
        if key.lower().replace("_", "-") in _SERVER_NAME_ALIASES:
            return key
    return None


def _resolve_binary() -> str:
    """Find the absolute path to the openwebgoggles binary.

    Since this function runs *inside* the openwebgoggles process, we can
    resolve it reliably without depending on PATH at runtime.
    """
    # Best: shutil.which finds us in the current PATH
    found = shutil.which("openwebgoggles")
    if found:
        return str(Path(found).resolve())

    # Fallback: we're running as a console_script, so sys.argv[0] is the binary
    argv0 = Path(sys.argv[0])
    if argv0.exists():
        return str(argv0.resolve())

    # Last resort: bare name (will need PATH at runtime)
    return "openwebgoggles"


_CLAUDE_SETTINGS = {
    "permissions": {
        "allow": [
            "mcp__openwebgoggles__openwebgoggles",
            "mcp__openwebgoggles__openwebgoggles_read",
            "mcp__openwebgoggles__openwebgoggles_close",
            "mcp__openwebgoggles__openwebgoggles_update",
            "mcp__openwebgoggles__openwebgoggles_status",
        ]
    }
}

# Permission strings written by older versions (tool rename: webview_* → openwebgoggles_*).
# Removed automatically by `init` and flagged by `doctor`.
_DEPRECATED_PERMISSIONS: frozenset[str] = frozenset(
    {
        "mcp__openwebgoggles__webview",
        "mcp__openwebgoggles__webview_read",
        "mcp__openwebgoggles__webview_close",
        "mcp__openwebgoggles__webview_update",
        "mcp__openwebgoggles__webview_status",
    }
)


def _init_claude(root: Path, global_mode: bool = False) -> None:
    """Set up .mcp.json and .claude/settings.json for Claude Code.

    When global_mode=True, root should be Path.home() so files land at
    ~/.mcp.json and ~/.claude/settings.json — making openwebgoggles available
    in every project without per-project init.
    """
    root.mkdir(parents=True, exist_ok=True)
    binary = _resolve_binary()
    print(f"  binary: {binary}")
    mcp_config = {"mcpServers": {"openwebgoggles": {"command": binary}}}

    # --- .mcp.json ---
    mcp_path = root / ".mcp.json"
    if mcp_path.exists():
        existing = json.loads(mcp_path.read_text())
        servers = existing.setdefault("mcpServers", {})
        existing_key = _find_server_key(servers)
        if existing_key:
            print(f"  {mcp_path}: {existing_key} already configured, skipping.")
        else:
            servers["openwebgoggles"] = mcp_config["mcpServers"]["openwebgoggles"]
            mcp_path.write_text(json.dumps(existing, indent=2) + "\n")
            print(f"  {mcp_path}: added openwebgoggles server.")
    else:
        mcp_path.write_text(json.dumps(mcp_config, indent=2) + "\n")
        print(f"  {mcp_path}: created.")

    # --- .claude/settings.json ---
    claude_dir = root / ".claude"
    claude_dir.mkdir(exist_ok=True)
    settings_path = claude_dir / "settings.json"
    needed = set(_CLAUDE_SETTINGS["permissions"]["allow"])

    if settings_path.exists():
        existing = json.loads(settings_path.read_text())
        allow_list = existing.setdefault("permissions", {}).setdefault("allow", [])
        already = set(allow_list)
        missing = needed - already
        deprecated = [p for p in allow_list if p in _DEPRECATED_PERMISSIONS]
        for dep in deprecated:
            allow_list.remove(dep)
        if missing or deprecated:
            allow_list.extend(sorted(missing))
            settings_path.write_text(json.dumps(existing, indent=2) + "\n")
            parts = []
            if missing:
                parts.append(f"added {len(missing)} permission(s)")
            if deprecated:
                parts.append(f"removed {len(deprecated)} stale permission(s)")
            print(f"  {settings_path}: {', '.join(parts)}.")
        else:
            print(f"  {settings_path}: permissions already present, skipping.")
    else:
        settings_path.write_text(json.dumps(_CLAUDE_SETTINGS, indent=2) + "\n")
        print(f"  {settings_path}: created.")

    # --- Claude Desktop (global config) ---
    print("\n  [Claude Desktop]")
    _setup_claude_desktop_config(binary)

    scope = "globally (all projects)" if global_mode else f"for project: {root}"
    print(f"\nDone! Configured {scope}. Restart Claude Code and Claude Desktop to pick up the new MCP server.")


def _get_claude_desktop_config_path() -> Path:
    """Return the platform-specific Claude Desktop config path."""
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
    # Linux / fallback
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def _setup_claude_desktop_config(binary: str) -> None:
    """Write the Claude Desktop config entry (shared by init claude and init claude-desktop)."""
    config_path = _get_claude_desktop_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    server_entry: dict[str, Any] = {"command": binary}

    if config_path.exists():
        existing = json.loads(config_path.read_text())
        servers = existing.setdefault("mcpServers", {})
        existing_key = _find_server_key(servers)
        if existing_key:
            print(f"  {config_path}: {existing_key} already configured, skipping.")
        else:
            servers["openwebgoggles"] = server_entry
            config_path.write_text(json.dumps(existing, indent=2) + "\n")
            print(f"  {config_path}: added openwebgoggles server.")
    else:
        config = {"mcpServers": {"openwebgoggles": server_entry}}
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"  {config_path}: created.")


def _init_claude_desktop(_root: Path) -> None:
    """Set up claude_desktop_config.json for Claude Desktop.

    The root argument is ignored — Claude Desktop always uses the global
    platform-specific config path.
    """
    binary = _resolve_binary()
    print(f"  binary: {binary}")
    _setup_claude_desktop_config(binary)
    print("\nDone! Fully quit and relaunch Claude Desktop to pick up the new MCP server.")


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC, preserving strings.

    Uses a simple state machine so that comments inside quoted strings
    (e.g. ``"https://example.com"``) are left untouched.
    """
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        # Inside a string — copy until closing quote
        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2  # skip escaped char
                elif text[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            result.append(text[i:j])
            i = j
        # Line comment
        elif text[i : i + 2] == "//":
            # Skip to end of line
            end = text.find("\n", i)
            i = end if end != -1 else n
        # Block comment
        elif text[i : i + 2] == "/*":
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else n
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


def _init_opencode(root: Path) -> None:
    """Set up opencode.json for OpenCode.

    Default target is ~/.config/opencode/ (global config), so the MCP server
    is available in every project.  Pass a project directory to create a
    project-specific override instead.
    """
    root.mkdir(parents=True, exist_ok=True)
    binary = _resolve_binary()
    print(f"  binary: {binary}")
    server_entry = {"type": "local", "command": [binary], "enabled": True}
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {"openwebgoggles": server_entry},
    }

    # OpenCode supports both opencode.json and opencode.jsonc.
    # Detect which one exists; prefer .jsonc if it's the only one,
    # .json if both exist (higher precedence in OpenCode).
    config_path = root / "opencode.json"
    jsonc_path = root / "opencode.jsonc"

    if jsonc_path.exists() and not config_path.exists():
        config_path = jsonc_path

    if config_path.exists():
        raw = config_path.read_text()
        # Strip // and /* */ comments for .jsonc files so json.loads works.
        # Must skip comments inside strings (e.g. "https://...").
        if config_path.suffix == ".jsonc":
            raw = _strip_jsonc_comments(raw)
        existing = json.loads(raw)
        mcp_servers = existing.setdefault("mcp", {})
        existing_key = _find_server_key(mcp_servers)
        if existing_key:
            print(f"  {config_path}: {existing_key} already configured, skipping.")
        else:
            mcp_servers["openwebgoggles"] = server_entry
            # Write back as plain JSON (comments are lost, but the config is valid)
            config_path.write_text(json.dumps(existing, indent=2) + "\n")
            print(f"  {config_path}: added openwebgoggles server.")
            if config_path.suffix == ".jsonc":
                print("  note: comments were stripped during rewrite (JSON doesn't support comments).")
    else:
        config_path.write_text(json.dumps(opencode_config, indent=2) + "\n")
        print(f"  {config_path}: created.")

    global_dir = Path.home() / ".config" / "opencode"
    is_global = root.resolve() == global_dir.resolve()
    if is_global:
        print("\nDone! This is the global config — OpenWebGoggles will be available in all projects.")
    else:
        print(f"\nDone! This is a project-specific config in {root}.")
    print("Restart OpenCode to pick up the new MCP server.")


def _init_usage() -> None:
    """Print init subcommand usage."""
    print("Usage: openwebgoggles init <editor> [target_dir] [--global]\n")
    print("Set up OpenWebGoggles for your editor.\n")
    print("Editors:")
    print("  claude          Claude Code + Claude Desktop (sets up both)")
    print("                  Default target: current directory (project-level)")
    print("                  Use --global to write ~/.mcp.json + ~/.claude/settings.json")
    print("  claude-desktop  Claude Desktop only — adds to claude_desktop_config.json")
    print("                  Uses the global platform-specific config path")
    print("  opencode        OpenCode — creates opencode.json")
    print("                  Default target: ~/.config/opencode/ (global, all projects)\n")
    print("Examples:")
    print("  openwebgoggles init claude              # set up Claude Code for this project")
    print("  openwebgoggles init claude --global     # set up Claude Code for ALL projects")
    print("  openwebgoggles init claude-desktop       # set up Claude Desktop only")
    print("  openwebgoggles init opencode             # set up OpenCode globally")
    print("  openwebgoggles init opencode .           # set up OpenCode for this project only")
    print("  openwebgoggles init claude ~/my-proj     # set up a specific project for Claude")


_INIT_DISPATCH = {
    "claude": _init_claude,
    "claude-desktop": _init_claude_desktop,
    "opencode": _init_opencode,
}


# ---------------------------------------------------------------------------
# CLI subcommands: restart, status, doctor
# ---------------------------------------------------------------------------


def _find_data_dir(explicit: Path | None = None) -> Path:
    """Resolve the persistent data directory for PID files, state, etc."""
    if explicit is not None:
        return explicit
    return _get_data_dir()


def _read_pid_file(path: Path) -> int | None:
    """Read a PID file and return the PID if the process is alive."""
    if not path.exists():
        return None
    try:
        raw = path.read_text().strip()
        if not raw.isdigit():
            return None
        pid = int(raw)
        os.kill(pid, 0)  # existence check
        return pid
    except (OSError, ValueError):
        return None


# -- restart ----------------------------------------------------------------


def _cmd_restart() -> None:
    """Find the running MCP server and trigger a seamless restart via SIGUSR1."""
    data_dir_arg = None
    if len(sys.argv) > 2:
        data_dir_arg = Path(sys.argv[2])

    data_dir = _find_data_dir(data_dir_arg)
    mcp_pid_file = data_dir / ".mcp.pid"

    pid = _read_pid_file(mcp_pid_file)
    if pid is None:
        # Try the webview server PID as a fallback hint
        webview_pid = _read_pid_file(data_dir / ".server.pid")
        if webview_pid is not None:
            print("Found a running webview server but no MCP server PID file.")
            print("The MCP server may be running under an older version.")
            print(f"You can manually kill the webview server (PID {webview_pid}) and restart your editor.")
        else:
            print("No running MCP server found.")
            print()
            print("To start one:")
            print("  openwebgoggles init claude    # set up for Claude Code")
            print("  openwebgoggles init opencode  # set up for OpenCode")
            print("  Then restart your editor.")
        sys.exit(1)

    if platform.system() == "Windows":
        # No SIGUSR1 on Windows — kill the process (editor will restart it)
        print(f"Windows: terminating MCP server (PID {pid}) — your editor will restart it.")
        try:
            os.kill(pid, 15)  # SIGTERM
        except OSError as e:
            print(f"Failed to terminate process: {e}", file=sys.stderr)
            sys.exit(1)
        print("Done. The editor should restart the MCP server automatically.")
        return

    # Unix: send SIGUSR1 for seamless in-place restart
    print(f"Sending restart signal to MCP server (PID {pid})...")
    try:
        os.kill(pid, signal.SIGUSR1)
    except OSError as e:
        print(f"Failed to send signal: {e}", file=sys.stderr)
        sys.exit(1)

    # Wait briefly and verify the process is still alive (it should be — same PID after execv)
    time.sleep(1)
    try:
        os.kill(pid, 0)
        print(f"MCP server restarted successfully (PID {pid}).")
    except OSError:
        print(f"MCP server (PID {pid}) exited — your editor should restart it automatically.")


# -- status -----------------------------------------------------------------


def _cmd_status() -> None:
    """Show the current state of the MCP server and webview."""
    data_dir_arg = None
    if len(sys.argv) > 2:
        data_dir_arg = Path(sys.argv[2])

    data_dir = _find_data_dir(data_dir_arg)

    print("OpenWebGoggles Status")
    print()

    # MCP server
    mcp_pid = _read_pid_file(data_dir / ".mcp.pid")
    if mcp_pid is not None:
        print(f"  MCP server:    running (PID {mcp_pid})")
    else:
        print("  MCP server:    not running")

    # Webview server
    webview_pid = _read_pid_file(data_dir / ".server.pid")
    manifest = None
    manifest_path = data_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    if webview_pid is not None and manifest:
        http_port = manifest.get("server", {}).get("http_port", "?")
        print(f"  Webview:       running (PID {webview_pid}, port {http_port})")

        # Try hitting the health endpoint
        try:
            url = f"http://127.0.0.1:{http_port}/_health"
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=2)  # nosec B310
            health = json.loads(resp.read())
            uptime_s = health.get("uptime", 0)
            ws_clients = health.get("ws_clients", 0)
            mins, secs = divmod(int(uptime_s), 60)
            if mins > 0:
                print(f"  Uptime:        {mins}m {secs}s")
            else:
                print(f"  Uptime:        {secs}s")
            print(f"  WS clients:    {ws_clients}")
        except Exception:
            print("  Health:        unreachable (server may be starting up)")

        # Session info
        session = manifest.get("session", {})
        app_name = manifest.get("app", {}).get("name", "unknown")
        session_id = session.get("id", "unknown")
        print(f"  Session:       {session_id[:8]} ({app_name} app)")
    elif webview_pid is not None:
        print(f"  Webview:       running (PID {webview_pid})")
    else:
        print("  Webview:       not running")

    if mcp_pid is None and webview_pid is None:
        print()
        print("  To start: openwebgoggles init claude  (then restart your editor)")


# -- doctor -----------------------------------------------------------------


def _cmd_doctor() -> None:  # noqa: C901 — TODO: extract per-check diagnostic functions
    """Diagnose the OpenWebGoggles setup and environment."""
    data_dir_arg = None
    if len(sys.argv) > 2:
        data_dir_arg = Path(sys.argv[2])

    print("OpenWebGoggles Doctor")
    print()

    ok_count = 0
    warn_count = 0

    def ok(msg: str) -> None:
        nonlocal ok_count
        ok_count += 1
        print(f"  [ok] {msg}")

    def warn(msg: str) -> None:
        nonlocal warn_count
        warn_count += 1
        print(f"  [!!] {msg}")

    # Python version
    v = sys.version_info
    if v >= (3, 11):
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        warn(f"Python {v.major}.{v.minor}.{v.micro} — 3.11+ required")

    # Core dependencies
    for pkg in ("websockets", "PyNaCl", "mcp"):
        try:
            dist = importlib.metadata.distribution(pkg)
            ok(f"{pkg} {dist.metadata['Version']}")
        except importlib.metadata.PackageNotFoundError:
            warn(f"{pkg} not installed")

    # Binary resolution
    binary = shutil.which("openwebgoggles")
    if binary:
        ok(f"Binary: {binary}")
    else:
        warn("Binary not on PATH (run with full path or check pipx)")

    # Config files
    cwd = Path(data_dir_arg) if data_dir_arg else Path.cwd()

    # Check for Claude Code config
    mcp_json = cwd / ".mcp.json"
    if mcp_json.exists():
        try:
            cfg = json.loads(mcp_json.read_text())
            servers = cfg.get("mcpServers", {})
            server_key = _find_server_key(servers)
            if server_key:
                ok(f".mcp.json: {server_key} configured")
                # Verify binary path matches
                cmd = servers[server_key].get("command", "")
                if binary and cmd and Path(cmd).resolve() == Path(binary).resolve():
                    ok("Config binary path matches installed binary")
                elif binary and cmd:
                    warn(f"Config binary ({cmd}) differs from installed ({binary})")
            else:
                warn(".mcp.json exists but openwebgoggles not configured")
        except (json.JSONDecodeError, OSError):
            warn(".mcp.json exists but is invalid JSON")
    else:
        # Check OpenCode config
        opencode_json = cwd / "opencode.json"
        global_opencode = Path.home() / ".config" / "opencode" / "opencode.json"
        found_config = False
        for cfg_path in (opencode_json, global_opencode):
            if cfg_path.exists():
                try:
                    cfg = json.loads(cfg_path.read_text())
                    server_key = _find_server_key(cfg.get("mcp", {}))
                    if server_key:
                        ok(f"{cfg_path.name}: {server_key} configured")
                        found_config = True
                        break
                except (json.JSONDecodeError, OSError):
                    pass
        if not found_config:
            warn("No editor config found (run: openwebgoggles init claude)")

    # Stale permissions from old 'webview' tool name (pre-rename migration)
    for sp in (cwd / ".claude" / "settings.json", Path.home() / ".claude" / "settings.json"):
        if sp.exists():
            try:
                scfg = json.loads(sp.read_text())
                allow = scfg.get("permissions", {}).get("allow", [])
                stale = [p for p in allow if p in _DEPRECATED_PERMISSIONS]
                if stale:
                    warn(
                        f"{sp}: {len(stale)} stale permission(s) from old 'webview' tool name"
                        " — run: openwebgoggles init claude"
                    )
            except (json.JSONDecodeError, OSError):
                pass

    # Stale processes
    data_dir = _find_data_dir(data_dir_arg)
    stale_cleaned = False

    for pid_name in (".mcp.pid", ".server.pid"):
        pid_file = data_dir / pid_name
        if pid_file.exists():
            try:
                raw = pid_file.read_text().strip()
                if raw.isdigit():
                    pid = int(raw)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        # PID is dead — stale file
                        pid_file.unlink(missing_ok=True)
                        warn(f"Stale {pid_name} (PID {pid}) — cleaned up")
                        stale_cleaned = True
            except OSError:
                pass

    if not stale_cleaned:
        ok("No stale PID files")

    # Lock file
    lock_file = data_dir / ".server.lock"
    if lock_file.exists():
        # Check if it's held by a live process
        try:
            import fcntl
        except ImportError:
            warn("Cannot check lock file (fcntl unavailable on this platform)")
        else:
            try:
                fd = os.open(str(lock_file), os.O_RDONLY)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    # Lock was free — if no server is running, it's stale
                    webview_pid = _read_pid_file(data_dir / ".server.pid")
                    if webview_pid is None:
                        ok("Lock file present but not held (no conflict)")
                    else:
                        ok("Lock file OK")
                except OSError:
                    ok("Lock file held by running server")
                finally:
                    os.close(fd)
            except OSError:
                ok("No lock conflicts")
    else:
        ok("No lock file (clean state)")

    print()
    if warn_count == 0:
        print(f"  All {ok_count} checks passed!")
    else:
        print(f"  {ok_count} passed, {warn_count} issue(s) found.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_SUBCOMMANDS: dict[str, Any] = {}  # populated after all functions are defined


def _print_usage() -> None:
    """Print top-level usage."""
    print("Usage: openwebgoggles <command> [options]\n")
    print("Commands:")
    print("  (none)        Run MCP server (stdio transport)")
    print("  init          Bootstrap config for your editor")
    print("  restart       Restart the running MCP server")
    print("  status        Show server status and health")
    print("  doctor        Diagnose setup and environment")
    print()
    print("Run 'openwebgoggles <command>' for command-specific help.")


def main():
    """Entry point for the openwebgoggles console script.

    Usage:
        openwebgoggles                        # Run MCP server (stdio transport)
        openwebgoggles init <editor> [dir]    # Bootstrap for an editor
        openwebgoggles restart [dir]          # Restart running MCP server
        openwebgoggles status [dir]           # Show server status
        openwebgoggles doctor [dir]           # Diagnose setup
    """
    cmd = sys.argv[1] if len(sys.argv) > 1 else None

    if cmd == "init":
        if len(sys.argv) < 3 or sys.argv[2] not in _INIT_DISPATCH:
            _init_usage()
            return
        editor = sys.argv[2]
        remaining = sys.argv[3:]
        global_mode = "--global" in remaining
        path_args = [a for a in remaining if not a.startswith("-")]
        if path_args:
            target = Path(path_args[0])
        elif global_mode and editor == "claude":
            target = Path.home()
        else:
            target = _EDITOR_DEFAULT_DIRS.get(editor) or Path.cwd()
        if global_mode and editor == "claude":
            _init_claude(target, global_mode=True)
        else:
            _INIT_DISPATCH[editor](target)
        return

    if cmd == "restart":
        _cmd_restart()
        return

    if cmd == "status":
        _cmd_status()
        return

    if cmd == "doctor":
        _cmd_doctor()
        return

    if cmd in ("help", "--help", "-h"):
        _print_usage()
        return

    if cmd is not None and cmd.startswith("-"):
        _print_usage()
        return

    # Default: run MCP server (stdio transport)
    if _mcp_import_error is not None:
        print(f"Error: failed to load mcp library: {_mcp_import_error}", file=sys.stderr)
        print("Install with: pipx install openwebgoggles  (or: pip install openwebgoggles)", file=sys.stderr)
        sys.exit(1)

    # Register SIGUSR1 handler for `openwebgoggles restart`
    if platform.system() != "Windows":
        signal.signal(signal.SIGUSR1, _sigusr1_handler)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,  # MCP uses stdout for JSON-RPC; logs go to stderr
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
