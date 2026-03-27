"""
WebviewSession and related utilities.

Manages a single webview server subprocess and its file-based data contract,
plus platform-aware data directory resolution and deep-merge utilities.
"""

import asyncio
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
from pathlib import Path
from typing import Any

try:
    from .exceptions import AssetError, LockError, MergeError, SessionError
except ImportError:
    from exceptions import AssetError, LockError, MergeError, SessionError  # noqa: I001

logger = logging.getLogger("openwebgoggles")

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
        raise MergeError(f"Merge depth exceeds maximum ({MAX_MERGE_DEPTH})")
    # Block prototype-pollution keys that could be dangerous when serialized to JS
    for key, value in override.items():
        if key in _DANGEROUS_KEYS:
            raise MergeError(f"Merge rejected: dangerous key {key!r}")
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value, _depth + 1)
        else:
            base[key] = value


# ---------------------------------------------------------------------------
# WebviewSession — manages one webview server subprocess + data contract
# ---------------------------------------------------------------------------

# Module-local flag for atexit registration; intentionally separate from
# mcp_server._atexit_registered so each module manages its own state.
_atexit_registered: bool = False


class WebviewSession:
    """Manages a single webview server subprocess and its file-based data contract."""

    DEFAULT_HTTP_PORT = 18420
    DEFAULT_WS_PORT = 18421
    MAX_PORT_ATTEMPTS = 10
    HEALTH_TIMEOUT = 15.0
    POLL_INTERVAL = 0.5
    PROGRESS_INTERVAL = 5.0

    def __init__(self, work_dir: Path | None = None, open_browser: bool = True, remote: bool = False):
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
        # Remote mode: bind to 0.0.0.0 instead of 127.0.0.1 for SSH/Codespaces/Gitpod
        self._remote: bool = remote
        self._bind_host: str = "0.0.0.0" if remote else "127.0.0.1"  # noqa: S104
        self._display_host: str = socket.gethostname() if remote else "127.0.0.1"

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
                raise LockError("Cannot acquire webview lock — another instance may be running")
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

        try:
            from .log_config import DEFAULT_LOG_FILE
        except ImportError:
            from log_config import DEFAULT_LOG_FILE  # noqa: I001

        cmd = [
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
            "--log-file",
            str(DEFAULT_LOG_FILE),
        ]
        if self._remote:
            cmd.append("--remote")

        self.process = subprocess.Popen(
            cmd,
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
            raise SessionError(f"Webview server failed to start: {stderr}")

        self._started = True
        # Close stderr pipe to prevent buffer deadlock (errors already reported via health check)
        if self.process and self.process.stderr:
            self.process.stderr.close()
        global _atexit_registered
        if not _atexit_registered:
            import atexit

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

    def append_state(
        self,
        partial: dict[str, Any],
        validator: Any | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Append list values in *partial* to existing state lists.

        Non-list values are set directly (like merge). List values are appended
        to the corresponding list in the current state. Returns a tuple of
        (full_updated_state, patch_ops) where patch_ops is a list of
        ``{"op": "append"|"set", "path": "dot.path", "value": ...}`` dicts.

        The patch_ops can be broadcast as a ``state_patch`` WS message so
        clients can apply the delta without a full state replacement.
        """
        with self._state_lock:
            current = self.read_state()
            ops: list[dict[str, Any]] = []
            self._collect_append_ops(current, partial, "", ops)
            if validator:
                validator(current)
            self._write_state_locked(current)
            # Include new version in ops for client-side monotonicity
            return current, ops

    @staticmethod
    def _collect_append_ops(
        base: dict[str, Any],
        patch: dict[str, Any],
        prefix: str,
        ops: list[dict[str, Any]],
    ) -> None:
        """Walk *patch* and mutate *base* in place, collecting patch ops."""
        for key, value in patch.items():
            if key in _DANGEROUS_KEYS:
                raise MergeError(f"Append rejected: dangerous key {key!r}")
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, list) and isinstance(base.get(key), list):
                base[key].extend(value)
                ops.append({"op": "append", "path": path, "value": value})
            elif isinstance(value, dict) and isinstance(base.get(key), dict):
                WebviewSession._collect_append_ops(base[key], value, path, ops)
            else:
                base[key] = value
                ops.append({"op": "set", "path": path, "value": value})

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
        return f"http://{self._display_host}:{self.http_port}"

    # -- Internal helpers ---------------------------------------------------

    def _find_assets_dir(self) -> Path:
        """Locate the assets/ directory (works for both dev and installed)."""
        # Prefer mcp_server.__file__ if available so that test patches on
        # mock.patch("mcp_server.__file__") take effect (backward compat).
        import sys

        mcp_mod = sys.modules.get("mcp_server")
        base_file = getattr(mcp_mod, "__file__", None) or __file__
        # Development: scripts/mcp_server.py → repo root / assets
        repo_root = Path(base_file).resolve().parent.parent
        dev_assets = repo_root / "assets"
        if dev_assets.is_dir():
            return dev_assets
        # Installed as package: assets bundled alongside scripts/
        pkg_assets = Path(base_file).resolve().parent / "assets"
        if pkg_assets.is_dir():
            return pkg_assets
        raise AssetError(f"Cannot find assets directory. Expected at {dev_assets} or {pkg_assets}")

    def _copy_app(self, app_name: str) -> None:
        """Find and copy the app + SDK to the data directory."""
        # Reject absolute paths and path traversal before any filesystem access.
        # Pathlib resolves `Path(base) / "/abs"` to `/abs` on Unix, so an absolute
        # app_name would silently escape the assets directory.
        _app_path = Path(app_name)
        if _app_path.is_absolute() or ".." in _app_path.parts or app_name.startswith("."):
            raise AssetError(
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
            raise AssetError(f"App '{app_name}' not found. Available: {', '.join(available) or 'none'}")

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

        # Playground app needs the dynamic app's rendering modules
        if app_name == "playground":
            dynamic_dir = assets_dir / "apps" / "dynamic"
            if dynamic_dir.is_dir():
                for module in ("utils.js", "sections.js", "charts.js", "validation.js", "behaviors.js"):
                    src_file = dynamic_dir / module
                    if src_file.is_file():
                        shutil.copy2(src_file, dest / module)
                # Extract CSS from dynamic index.html for playground preview
                self._extract_dynamic_css(dynamic_dir / "index.html", dest / "dynamic-styles.css")

    @staticmethod
    def _extract_dynamic_css(index_html: Path, dest_css: Path) -> None:
        """Extract <style> content from dynamic/index.html into a standalone CSS file."""
        import re as _re

        text = index_html.read_text(encoding="utf-8")
        # Extract content between first <style> and </style>
        match = _re.search(r"<style>(.*?)</style>", text, _re.DOTALL)
        if match:
            dest_css.write_text(match.group(1).strip(), encoding="utf-8")

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
                "host": self._display_host,
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
        raise SessionError(
            f"Could not find free ports after {self.MAX_PORT_ATTEMPTS} attempts "
            f"(tried {self.DEFAULT_HTTP_PORT}-{http_port - 1})"
        )

    def _port_available(self, port: int) -> bool:
        """Check if a TCP port is available to bind.

        TOCTOU note: The port may be claimed between this check and the
        subprocess bind. The health check in ensure_started() catches this
        case and raises RuntimeError, which the caller retries.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self._bind_host, port))
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
