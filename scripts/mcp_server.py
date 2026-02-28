#!/usr/bin/env python3
"""
OpenWebGoggles MCP Server — exposes browser-based HITL UIs as MCP tools.

Agents call webview() to show an interactive UI and block until the user
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
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

# Lazy-guard: init subcommands don't need mcp — let them work even when
# the mcp library is missing, broken, or has version conflicts.
_mcp_import_error: Exception | None = None
try:
    from mcp.server.fastmcp import Context, FastMCP
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
    from security_gate import SecurityGate

    _security_gate = SecurityGate()
except ImportError:
    logger.warning("SecurityGate not available — state validation disabled")
except Exception:
    logger.error("SecurityGate failed to initialize — state validation disabled", exc_info=True)


# ---------------------------------------------------------------------------
# Deep merge utility
# ---------------------------------------------------------------------------


MAX_MERGE_DEPTH = 20


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
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value, _depth + 1)
        else:
            base[key] = value


# ---------------------------------------------------------------------------
# State presets — expand shorthand into full state schemas
# ---------------------------------------------------------------------------


def _expand_preset(preset: str, state: dict[str, Any]) -> dict[str, Any]:
    """Expand a preset name into a full state schema, merging user overrides."""
    s = dict(state)  # shallow copy so we can pop

    if preset == "progress":
        tasks = s.pop("tasks", [])
        pct = s.pop("percentage", None)
        base: dict[str, Any] = {
            "title": s.get("title", "Progress"),
            "status": "processing",
            "data": {
                "sections": [
                    {
                        "type": "progress",
                        "title": s.get("title", ""),
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
        base = {
            "title": s.get("title", "Confirm"),
            "message": s.get("message", ""),
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
        base = {
            "title": s.get("title", "Log"),
            "status": "processing",
            "data": {
                "sections": [
                    {
                        "type": "log",
                        "title": s.get("title", ""),
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
        self.data_dir = self.work_dir / ".opencode" / "webview"
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
            self.process.kill()
            self.process = None
            raise RuntimeError(f"Webview server failed to start: {stderr}")

        self._started = True
        # Close stderr pipe to prevent buffer deadlock (errors already reported via health check)
        if self.process and self.process.stderr:
            self.process.stderr.close()
        atexit.register(self._atexit_cleanup)

        if self._open_browser_on_start:
            self._open_browser()
            self._open_browser_on_start = False

    def write_state(self, state: dict[str, Any]) -> None:
        """Atomic write to state.json with auto-incrementing version."""
        self._state_version += 1
        state.setdefault("version", self._state_version)
        state["version"] = self._state_version
        state.setdefault("updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        state.setdefault("status", "waiting_input")
        self._write_json(self.data_dir / "state.json", state)

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
            self.write_state(current)
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
                if data.get("actions"):
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
        if _app_path.is_absolute() or ".." in _app_path.parts:
            raise FileNotFoundError(f"App '{app_name}' not found. App names must be simple names (no '/' or '..').")

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
        """Check if a TCP port is available to bind."""
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

    def _open_browser(self) -> None:
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
                self._chrome_profile = None

        if not opened:
            webbrowser.open(url)

    @staticmethod
    def _get_cursor_screen_position() -> tuple[int, int] | None:
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

    def _cleanup_chrome(self) -> None:
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
    def _find_chrome() -> str | None:
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
        tmp.write_text(json.dumps(data, indent=2))
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

    def _atexit_cleanup(self) -> None:
        """Safety net: kill subprocess and Chrome on interpreter exit."""
        self._cleanup_chrome()
        self._cleanup_process()


# ---------------------------------------------------------------------------
# MCP Server — exposes tools backed by WebviewSession
# ---------------------------------------------------------------------------

_session: WebviewSession | None = None
_session_lock = asyncio.Lock()


async def _get_session() -> WebviewSession:
    """Get or create the global WebviewSession."""
    global _session
    async with _session_lock:
        if _session is None:
            _session = WebviewSession(open_browser=True)
        return _session


# ---------------------------------------------------------------------------
# Auto-reload: detect pipx/pip upgrades and restart seamlessly
# ---------------------------------------------------------------------------

_active_tool_calls: int = 0
_active_tool_calls_lock = asyncio.Lock()
_reload_pending: bool = False
_reload_task: asyncio.Task | None = None
_RELOAD_CHECK_INTERVAL = 30  # seconds


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


def _read_version_fresh() -> str:
    """Read installed version bypassing importlib caches (Python 3.12+)."""
    importlib.invalidate_caches()
    try:
        dist = importlib.metadata.distribution("openwebgoggles")
        return dist.metadata["Version"]
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _exec_reload() -> None:
    """Replace the current process with a fresh interpreter via os.execv.

    On Unix this is seamless — same PID, same stdin/stdout/stderr pipes.
    The MCP client never sees a disconnect.
    """
    executable = sys.executable
    args = [executable] + sys.argv

    logger.info("Reloading: exec %s %s", executable, " ".join(sys.argv))

    if platform.system() == "Windows":
        logger.warning("Windows does not support in-place exec. The MCP client will need to restart the server.")

    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(executable, args)  # noqa: S606 — intentional self-restart


async def _version_monitor() -> None:
    """Background task: poll for package version changes and exec to reload.

    Two-tier detection: cheap mtime check every 30s, full version read only
    when the dist-info directory changes.
    """
    global _reload_pending

    startup_version, dist_info_path = _get_installed_version_info()
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

    while True:
        await asyncio.sleep(_RELOAD_CHECK_INTERVAL)

        try:
            # Tier 1: cheap mtime check
            mtime_changed = False
            if dist_info_path is not None:
                try:
                    current_mtime = dist_info_path.stat().st_mtime
                    if last_mtime is not None and current_mtime != last_mtime:
                        mtime_changed = True
                    last_mtime = current_mtime
                except OSError:
                    # Directory gone — package is being upgraded
                    mtime_changed = True
            else:
                mtime_changed = True

            if not mtime_changed:
                continue

            # Tier 2: full version read (only after mtime change)
            current_version = _read_version_fresh()

            if current_version == "unknown":
                # Package temporarily missing during upgrade — retry next cycle
                dist_info_path = None
                last_mtime = None
                continue

            if current_version == startup_version:
                # Mtime changed but same version — update path in case it moved
                _, dist_info_path = _get_installed_version_info()
                if dist_info_path and dist_info_path.is_dir():
                    last_mtime = dist_info_path.stat().st_mtime
                continue

            # Version changed — trigger reload
            logger.info(
                "Package updated: %s -> %s — reloading server",
                startup_version,
                current_version,
            )
            _reload_pending = True

            # Wait for in-flight tool calls to drain (up to 60s)
            drain_deadline = time.monotonic() + 60
            while time.monotonic() < drain_deadline:
                async with _active_tool_calls_lock:
                    if _active_tool_calls == 0:
                        break
                await asyncio.sleep(1)

            # Close webview session gracefully
            global _session
            if _session is not None:
                try:
                    await _session.close(message="Server reloading (package updated).")
                except Exception:
                    pass
                _session = None

            _exec_reload()

        except asyncio.CancelledError:
            return
        except Exception:
            logger.exception("Version monitor error (will retry)")


def _track_tool_call(fn):  # type: ignore[no-untyped-def]
    """Decorator: track in-flight tool calls for safe reload."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        global _active_tool_calls
        if _reload_pending:
            return {"error": "Server is reloading after a package update. Please retry in a moment."}
        async with _active_tool_calls_lock:
            _active_tool_calls += 1
        try:
            return await fn(*args, **kwargs)
        finally:
            async with _active_tool_calls_lock:
                _active_tool_calls -= 1

    return wrapper


# ---------------------------------------------------------------------------
# MCP Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(server: FastMCP):
    """MCP server lifecycle: version monitor on start, cleanup on shutdown."""
    global _reload_task
    _reload_task = asyncio.create_task(_version_monitor())

    yield

    # Cancel version monitor
    if _reload_task is not None:
        _reload_task.cancel()
        try:
            await _reload_task
        except asyncio.CancelledError:
            pass
        _reload_task = None

    # Clean up webview session
    global _session
    if _session is not None:
        try:
            await _session.close(message="MCP server shutting down.")
        except Exception:
            pass
        _session = None


mcp = FastMCP(
    "openwebgoggles",
    instructions="""\
Browser-based HITL UIs for CLI agents. Show interactive webviews and collect user input.

## When to use these tools

Use webview instead of plain text or AskUserQuestion when ANY of these apply:

- **Multiple items to review**: Lists of PRs, issues, findings, migrations, configs, etc. \
where the user needs to act on each one (approve/reject/edit/skip).
- **Complex decisions with forms**: When you need more than a yes/no — dropdowns, text \
fields, checkboxes, or multi-field input.
- **Structured data review**: Tables, key-value pairs, nested objects, or arrays where \
visual layout helps comprehension.
- **Multi-step workflows**: Wizards, sequential approvals, or processes where you call \
webview repeatedly for each step.
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

For N items, call webview N times in sequence:
- Show "Item 1 of N" with context + form for that item
- Collect the response, then show "Item 2 of N", etc.
- After the last item, show a summary and call webview_close

Each step should show:
1. An "items" section with just the current item (title + subtitle)
2. A "text" section with detail/context about that item
3. A "form" section with the decision fields for that item
4. Navigation buttons: "Next →" (approve) and optionally "← Previous" (ghost)
5. The message should say "Item X of N"

Example — step 1 of a 3-item wizard:
```
webview({
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

Then call webview again for item 2, then 3, etc. Collect all responses, \
then show a summary and call webview_close.

## Quick patterns

**Single item review or form input**:
```
webview({
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

**progress** — Task progress tracker (pair with `webview_update` for live updates):
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

## Non-blocking updates with webview_update

Use `webview_update` to push UI changes without waiting for user action. \
This is ideal for progress tracking, streaming logs, and live status:

```
webview_update({"status": "processing", "message": "Running tests..."}, merge=True)
```

Or use presets for common patterns:
```
webview_update({"tasks": [...], "percentage": 50}, preset="progress")
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


@mcp.tool()
@_track_tool_call
async def webview(
    state: dict[str, Any],
    timeout: int = 300,
    app: str = "dynamic",
    preset: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Show an interactive webview UI and wait for the user to respond.

    This is the primary tool for human-in-the-loop interactions. Pass a state
    object describing the UI and this tool blocks until the user clicks an
    action button.

    The state object schema:
      - title (str): Header title
      - message (str, optional): Description/instructions shown to the user
      - message_format (str, optional): Set to "markdown" to render message as markdown
      - message_className (str, optional): CSS class(es) to add to the message box
      - status (str, optional): Badge text (e.g. "pending_review", "waiting_input")
      - custom_css (str, optional): Custom CSS injected as a <style> tag (validated for safety)
      - data (dict): UI layout with optional "sections" array. Each section has:
          - type: "form" | "items" | "text" | "actions" | "progress" | "log" | "diff" | "table" | "tabs"
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
          - tabs (list): For "tabs" sections — [{id, label, sections: [...]}]
      - actions_requested (list): Top-level action buttons, each with:
          - id (str): Unique action identifier
          - label (str): Button text
          - type/style: "approve"|"reject"|"submit"|"primary"|"danger"|"success"|"warning"|"ghost"
      - behaviors (list, optional): Client-side conditional field rules.
          Each: {when: {field, equals|in|checked|...}, show|hide|enable|disable: [keys]}
      - layout (dict, optional): Multi-panel layout. {type: "sidebar"|"split", sidebarWidth?}
      - panels (dict, optional): Panel content. {sidebar: {sections}, main: {sections}}

    Field types: text, textarea, number, select, checkbox, email, url, static
    Each field: {key, label, type, value?, default?, placeholder?, description?, options?, format?,
                 required?, pattern?, minLength?, maxLength?, errorMessage?}
    Items: {title, subtitle?, id?, format?, className?, actions?}

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
        result = webview({
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
        result = webview({
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

    # Validate eagerly so the agent gets a clear error
    if _security_gate:
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = _security_gate.validate_state(raw)
        if not valid:
            return {"error": f"State validation failed: {err}"}

    session = await _get_session()
    try:
        await session.ensure_started(app)
    except Exception as e:
        return {"error": f"Failed to start webview: {e}"}

    session.clear_actions()
    session.write_state(state)

    async def _report_progress(elapsed: float, total: float) -> None:
        if ctx is not None:
            await ctx.report_progress(elapsed, total, message="Waiting for user response…")

    result = await session.wait_for_action(
        timeout=float(timeout),
        on_progress=_report_progress,
    )
    if result is None:
        return {"error": "Timeout waiting for user response", "timeout_seconds": timeout}

    return result


@mcp.tool()
@_track_tool_call
async def webview_read(clear: bool = False) -> dict[str, Any]:
    """Read the current user actions from the webview.

    Use after webview() to check if the user has responded (polling pattern).
    Returns the actions array, or an empty array if no response yet.

    Set clear=True to clear actions after reading so the next read starts fresh.
    """
    session = await _get_session()
    if not session._started:
        return {"version": 0, "actions": []}

    actions = session.read_actions()
    if clear and actions.get("actions"):
        session.clear_actions()

    return actions


@mcp.tool()
@_track_tool_call
async def webview_update(
    state: dict[str, Any],
    merge: bool = False,
    preset: str | None = None,
    app: str = "dynamic",
) -> dict[str, Any]:
    """Update the webview state without blocking for a response.

    Use this to push UI updates (progress, status changes, new data) while
    the webview is open, without waiting for user action.

    Args:
        state: The state object (same schema as webview).
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

    # Validate eagerly so the agent gets a clear error
    if _security_gate:
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = _security_gate.validate_state(raw)
        if not valid:
            return {"error": f"State validation failed: {err}"}

    session = await _get_session()
    try:
        await session.ensure_started(app)
    except Exception as e:
        return {"error": f"Failed to start webview: {e}"}

    # Do NOT clear actions — preserve pending user actions
    if merge:
        # Validate the FINAL merged state BEFORE writing to disk.
        # Two individually valid payloads can merge into an invalid composite.
        def _validate_merged(merged_state: dict) -> None:
            if _security_gate:
                merged_raw = json.dumps(merged_state, separators=(",", ":"))
                valid, err, _ = _security_gate.validate_state(merged_raw)
                if not valid:
                    raise ValueError(f"Merged state validation failed: {err}")

        try:
            merged = session.merge_state(state, validator=_validate_merged)
        except ValueError as e:
            return {"error": str(e)}
        return {"updated": True, "version": merged.get("version", 0)}
    else:
        session.write_state(state)
        return {"updated": True, "version": session._state_version}


@mcp.tool()
@_track_tool_call
async def webview_status() -> dict[str, Any]:
    """Check whether a webview session is currently active.

    Returns the session state without modifying anything.
    """
    global _session
    if _session is None or not _session._started:
        return {"active": False}
    return {
        "active": True,
        "alive": _session.is_alive(),
        "url": _session.url,
        "session_id": _session.session_id,
    }


@mcp.tool()
@_track_tool_call
async def webview_close(message: str = "Session complete.") -> dict[str, Any]:
    """Close the webview session and stop the server.

    Shows a farewell message to the user before closing. Blocks until the
    browser window is confirmed closed. Idempotent — safe to call even if
    no session is active. Always call this when done with the webview.
    """
    global _session
    if _session is None or not _session._started:
        return {"status": "ok", "message": "No active session."}

    try:
        await _session.close(message=message)
    except Exception as e:
        return {"error": f"Error closing session: {e}"}

    _session = None
    return {"status": "ok", "message": "Webview closed."}


# ---------------------------------------------------------------------------
# Init command — bootstrap OpenWebGoggles for a specific editor
# ---------------------------------------------------------------------------

_EDITORS = ["claude", "opencode"]

# Default config directories per editor (when user doesn't specify a target).
# Claude Code uses project-level .mcp.json, so cwd is the right default.
# OpenCode has a global config at ~/.config/opencode/, which makes more sense
# as a default since you typically want the MCP server available everywhere.
_EDITOR_DEFAULT_DIRS: dict[str, Path | None] = {
    "claude": None,  # None means cwd
    "opencode": Path.home() / ".config" / "opencode",
}


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
            "mcp__openwebgoggles__webview",
            "mcp__openwebgoggles__webview_read",
            "mcp__openwebgoggles__webview_close",
        ]
    }
}


def _init_claude(root: Path) -> None:
    """Set up .mcp.json and .claude/settings.json for Claude Code."""
    root.mkdir(parents=True, exist_ok=True)
    binary = _resolve_binary()
    print(f"  binary: {binary}")
    mcp_config = {"mcpServers": {"openwebgoggles": {"command": binary}}}

    # --- .mcp.json ---
    mcp_path = root / ".mcp.json"
    if mcp_path.exists():
        existing = json.loads(mcp_path.read_text())
        servers = existing.setdefault("mcpServers", {})
        if "openwebgoggles" in servers:
            print(f"  {mcp_path}: openwebgoggles already configured, skipping.")
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
        if missing:
            allow_list.extend(sorted(missing))
            settings_path.write_text(json.dumps(existing, indent=2) + "\n")
            print(f"  {settings_path}: added {len(missing)} permission(s).")
        else:
            print(f"  {settings_path}: permissions already present, skipping.")
    else:
        settings_path.write_text(json.dumps(_CLAUDE_SETTINGS, indent=2) + "\n")
        print(f"  {settings_path}: created.")

    print("\nDone! Restart Claude Code to pick up the new MCP server.")


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
        if "openwebgoggles" in mcp_servers:
            print(f"  {config_path}: openwebgoggles already configured, skipping.")
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
    print("Usage: openwebgoggles init <editor> [target_dir]\n")
    print("Set up OpenWebGoggles for your editor.\n")
    print("Editors:")
    print("  claude      Claude Code — creates .mcp.json + .claude/settings.json")
    print("              Default target: current directory (project-level)")
    print("  opencode    OpenCode — creates opencode.json")
    print("              Default target: ~/.config/opencode/ (global, all projects)\n")
    print("Examples:")
    print("  openwebgoggles init claude          # set up current project for Claude Code")
    print("  openwebgoggles init opencode         # set up OpenCode globally")
    print("  openwebgoggles init opencode .       # set up OpenCode for this project only")
    print("  openwebgoggles init claude ~/my-proj # set up a specific project for Claude Code")


_INIT_DISPATCH = {
    "claude": _init_claude,
    "opencode": _init_opencode,
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the openwebgoggles console script.

    Usage:
        openwebgoggles                        # Run MCP server (stdio transport)
        openwebgoggles init <editor> [dir]    # Bootstrap for an editor
    """
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        if len(sys.argv) < 3 or sys.argv[2] not in _INIT_DISPATCH:
            _init_usage()
            return

        editor = sys.argv[2]
        if len(sys.argv) > 3:
            target = Path(sys.argv[3])
        else:
            target = _EDITOR_DEFAULT_DIRS.get(editor) or Path.cwd()
        _INIT_DISPATCH[editor](target)
        return

    # Init commands don't need mcp, but the server does.
    if _mcp_import_error is not None:
        print(f"Error: failed to load mcp library: {_mcp_import_error}", file=sys.stderr)
        print("Install with: pipx install openwebgoggles  (or: pip install openwebgoggles)", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,  # MCP uses stdout for JSON-RPC; logs go to stderr
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
