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
import functools
import importlib  # noqa: F401 — kept for test patching: mcp_server.importlib.metadata.*
import importlib.metadata  # noqa: F401 — kept for test patching
import json
import logging
import os
import platform
import shutil  # noqa: F401 — kept for test patching: mock.patch("mcp_server.shutil.which")
import signal
import sys
import threading
import time
import uuid
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
# Session utilities — imported from session.py
# ---------------------------------------------------------------------------
try:
    from session import MAX_MERGE_DEPTH, WebviewSession, _DANGEROUS_KEYS, _DATA_DIR_NAME, _deep_merge, _get_data_dir  # noqa: I001, E402
except ImportError:
    from scripts.session import (  # type: ignore[no-redef]  # noqa: E402, I001
        MAX_MERGE_DEPTH,  # noqa: F401
        WebviewSession,  # noqa: F401
        _DANGEROUS_KEYS,  # noqa: F401
        _DATA_DIR_NAME,  # noqa: F401
        _deep_merge,  # noqa: F401
        _get_data_dir,  # noqa: F401
    )

# ---------------------------------------------------------------------------
# Data contract utilities — imported from data_contract.py
# ---------------------------------------------------------------------------
try:
    from data_contract import SessionArchive  # noqa: I001, E402
except ImportError:
    from scripts.data_contract import SessionArchive  # type: ignore[no-redef]  # noqa: E402, I001

# ---------------------------------------------------------------------------
# Monitor utilities — imported from monitor.py
# ---------------------------------------------------------------------------
try:
    from monitor import _get_installed_version_info, _task_done_callback  # noqa: I001, E402
except ImportError:
    from scripts.monitor import _get_installed_version_info, _task_done_callback  # type: ignore[no-redef]  # noqa: E402

# ---------------------------------------------------------------------------
# CLI utilities — imported from cli.py
# ---------------------------------------------------------------------------
try:
    from cli import (  # noqa: I001, E402
        _CLAUDE_SETTINGS,
        _DEPRECATED_PERMISSIONS,
        _EDITORS,
        _SERVER_NAME_ALIASES,
        _cmd_doctor,
        _cmd_logs,  # noqa: F401
        _cmd_restart,
        _cmd_dev,  # noqa: F401
        _cmd_scaffold,  # noqa: F401
        _cmd_status,
        _find_server_key,
        _get_claude_desktop_config_path,
        _init_claude_desktop,
        _init_opencode,
        _init_usage,
        _parse_dev_args,  # noqa: F401
        _parse_logs_args,  # noqa: F401
        _parse_scaffold_args,  # noqa: F401
        _print_usage,
        _read_pid_file,
        _resolve_binary,
        _setup_claude_desktop_config,
        _strip_jsonc_comments,
    )
    from cli import _find_data_dir as _find_data_dir_impl  # noqa: I001, E402
except ImportError:
    from scripts.cli import (  # type: ignore[no-redef]  # noqa: E402, F401, I001
        _CLAUDE_SETTINGS,
        _DEPRECATED_PERMISSIONS,
        _EDITORS,
        _SERVER_NAME_ALIASES,
        _cmd_dev,
        _cmd_doctor,
        _cmd_logs,
        _cmd_restart,
        _cmd_scaffold,
        _cmd_status,
        _find_server_key,
        _get_claude_desktop_config_path,
        _init_claude_desktop,
        _init_opencode,
        _init_usage,
        _parse_dev_args,
        _parse_logs_args,
        _parse_scaffold_args,
        _print_usage,
        _read_pid_file,
        _resolve_binary,
        _setup_claude_desktop_config,
        _strip_jsonc_comments,
    )
    from scripts.cli import _find_data_dir as _find_data_dir_impl  # type: ignore[no-redef]  # noqa: E402, F401


def _find_data_dir(explicit: Path | None = None) -> Path:
    """Resolve the persistent data directory for PID files, state, etc."""
    return _find_data_dir_impl(explicit)


# ---------------------------------------------------------------------------
# State presets — expand shorthand into full state schemas
# ---------------------------------------------------------------------------


def _preset_progress(s: dict[str, Any]) -> dict[str, Any]:
    tasks = s.pop("tasks", [])
    pct = s.pop("percentage", None)
    title = s.pop("title", "Progress")
    base: dict[str, Any] = {
        "title": title,
        "status": "processing",
        "data": {"sections": [{"type": "progress", "title": title if title != "Progress" else "", "tasks": tasks}]},
    }
    if pct is not None:
        base["data"]["sections"][0]["percentage"] = pct
    _deep_merge(base, s)
    return base


def _preset_confirm(s: dict[str, Any]) -> dict[str, Any]:
    details = s.pop("details", None)
    title = s.pop("title", "Confirm")
    message = s.pop("message", "")
    base: dict[str, Any] = {
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


def _preset_log(s: dict[str, Any]) -> dict[str, Any]:
    lines = s.pop("lines", [])
    max_lines = s.pop("maxLines", 500)
    title = s.pop("title", "Log")
    base: dict[str, Any] = {
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


def _preset_form_wizard(s: dict[str, Any]) -> dict[str, Any]:
    steps = s.pop("steps", [])
    title = s.pop("title", "Wizard")
    current_step = s.pop("step", 0)
    total = len(steps)
    pages: dict[str, Any] = {}
    for i, step in enumerate(steps):
        step_title = step.get("title", f"Step {i + 1}")
        sections: list[dict[str, Any]] = []
        if step.get("message"):
            sections.append({"type": "text", "content": step["message"], "format": "markdown"})
        if step.get("fields"):
            sections.append({"type": "form", "title": step_title, "fields": step["fields"]})
        nav: list[dict[str, Any]] = []
        if i > 0:
            nav.append({"id": f"prev_{i}", "label": "← Previous", "type": "ghost"})
        nav.append(
            {
                "id": "submit" if i == total - 1 else f"next_{i}",
                "label": "Submit" if i == total - 1 else "Next →",
                "type": "approve",
            }
        )
        pages[f"step_{i}"] = {"sections": sections, "actions_requested": nav}
    base: dict[str, Any] = {
        "title": title,
        "message": f"Step {current_step + 1} of {total}" if total > 0 else "",
        "status": "pending_review",
        "pages": pages,
        "active_page": f"step_{current_step}",
    }
    _deep_merge(base, s)
    return base


def _preset_triage(s: dict[str, Any]) -> dict[str, Any]:
    items = s.pop("items", [])
    title = s.pop("title", "Triage")
    current = s.pop("current", 0)
    total = len(items)
    item = items[current] if items and current < total else {}
    item_title = item.get("title", f"Item {current + 1}")
    sections: list[dict[str, Any]] = []
    if item.get("description"):
        sections.append({"type": "text", "content": item["description"], "format": "markdown"})
    sections.append(
        {"type": "items", "title": item_title, "items": [{"title": item_title, "subtitle": item.get("subtitle", "")}]}
    )
    base: dict[str, Any] = {
        "title": title,
        "message": f"Item {current + 1} of {total}",
        "status": "pending_review",
        "data": {"sections": sections},
        "actions_requested": [
            {"id": "approve", "label": "Approve", "type": "approve"},
            {"id": "reject", "label": "Reject", "type": "reject"},
            {"id": "skip", "label": "Skip", "type": "ghost"},
        ],
    }
    _deep_merge(base, s)
    return base


def _preset_dashboard(s: dict[str, Any]) -> dict[str, Any]:
    metrics = s.pop("metrics", [])
    title = s.pop("title", "Dashboard")
    columns = s.pop("columns", min(len(metrics), 4) or 4)
    cards = [
        {
            "label": m.get("label", ""),
            "value": m.get("value", ""),
            **({"delta": m["delta"]} if "delta" in m else {}),
            **({"trend": m["trend"]} if "trend" in m else {}),
        }
        for m in metrics
    ]
    base: dict[str, Any] = {
        "title": title,
        "status": "complete",
        "data": {"sections": [{"type": "metric", "columns": columns, "cards": cards}]},
    }
    _deep_merge(base, s)
    return base


def _preset_table_actions(s: dict[str, Any]) -> dict[str, Any]:
    columns = s.pop("columns", [])
    rows = s.pop("rows", [])
    actions = s.pop(
        "actions",
        [
            {"id": "confirm", "label": "Confirm", "type": "approve"},
            {"id": "cancel", "label": "Cancel", "type": "reject"},
        ],
    )
    title = s.pop("title", "Review")
    base: dict[str, Any] = {
        "title": title,
        "status": "pending_review",
        "data": {"sections": [{"type": "table", "columns": columns, "rows": rows}]},
        "actions_requested": actions,
    }
    _deep_merge(base, s)
    return base


def _preset_stepper(s: dict[str, Any]) -> dict[str, Any]:
    steps = s.pop("steps", [])
    title = s.pop("title", "Progress")
    message = s.pop("message", "")
    pct = s.pop("percentage", None)
    sec: dict[str, Any] = {
        "type": "progress",
        "title": "",
        "tasks": [{"label": step.get("label", ""), "status": step.get("status", "pending")} for step in steps],
    }
    if pct is not None:
        sec["percentage"] = pct
    base: dict[str, Any] = {"title": title, "status": "processing", "data": {"sections": [sec]}}
    if message:
        base["message"] = message
    _deep_merge(base, s)
    return base


_PRESET_HANDLERS: dict[str, Any] = {
    "progress": _preset_progress,
    "confirm": _preset_confirm,
    "log": _preset_log,
    "form-wizard": _preset_form_wizard,
    "triage": _preset_triage,
    "dashboard": _preset_dashboard,
    "table-actions": _preset_table_actions,
    "stepper": _preset_stepper,
}


def _expand_preset(preset: str, state: dict[str, Any]) -> dict[str, Any]:
    """Expand a preset name into a full state schema, merging user overrides.

    Template dicts are constructed fresh on each call, so ``_deep_merge()``
    mutating them in place is safe — no shared state between invocations.

    Available presets:
        - ``progress``: single progress bar section (tasks, percentage, title)
        - ``confirm``: approve/cancel dialog (title, message, details)
        - ``log``: scrolling log output (lines, maxLines, title)
        - ``form-wizard``: multi-step form pages (steps, title, step)
        - ``triage``: item-by-item review with approve/reject (items, title, current)
        - ``dashboard``: metric cards grid (metrics, title, columns)
        - ``table-actions``: table with action buttons (columns, rows, actions, title)
        - ``stepper``: step progress tracker (steps, title, message, percentage)
    """
    handler = _PRESET_HANDLERS.get(preset)
    if handler is None:
        raise ValueError(f"Unknown preset: {preset!r}")
    return handler(dict(state))  # shallow copy so handlers can pop freely


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


# MCP server PID file — written on startup so `openwebgoggles restart` can find us
_MCP_PID_DIR: Path | None = None


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
        self.persist_enabled: bool = False
        self.session_id: str = str(uuid.uuid4())

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
            # Give up to 2 s to exit gracefully, then force-kill
            for _ in range(20):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)  # probe — raises ProcessLookupError if dead
                except ProcessLookupError:
                    break  # exited cleanly
            else:
                os.kill(pid, signal.SIGKILL)
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


def _get_session_archive() -> SessionArchive:
    """Get a SessionArchive for persisting session snapshots."""
    data_dir = os.environ.get("OWG_DATA_DIR", "")
    if not data_dir:
        data_dir = str(Path.home() / ".local" / "share" / "openwebgoggles")
    return SessionArchive(data_dir)


def _persist_session(
    session_id: str,
    state: dict[str, Any],
    result: dict[str, Any],
    *,
    mode: str = "browser",
) -> None:
    """Save a session snapshot to disk (fire-and-forget)."""
    try:
        archive = _get_session_archive()
        actions = result.get("actions", [])
        archive.save(session_id, state=state, actions=actions, mode=mode)
        logger.info("Session %s persisted (%s mode)", session_id[:8], mode)
    except Exception:
        logger.warning("Failed to persist session %s", session_id[:8], exc_info=True)


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
    persist: bool = False,
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
      - theme (str, optional): UI color scheme — "dark" (default), "light", or "system" (follows OS)
      - persist (bool, optional): Save session state on completion for later restore via openwebgoggles_restore()
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
      - preset="form-wizard": state={steps: [{title, fields, message?}], step: 0}
      - preset="triage": state={items: [{title, subtitle?, description?}], current: 0}
      - preset="dashboard": state={metrics: [{label, value, delta?, trend?}], columns?}
      - preset="table-actions": state={columns, rows, actions?, title?}
      - preset="stepper": state={steps: [{label, status}], percentage?, message?}

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
        app_state.persist_enabled = persist
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

    # Persist final state + actions if requested
    if persist:
        _persist_session(session.session_id, state, result, mode="browser")

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
                "form-wizard" — takes {steps: [{title, fields, message?}], step: N}
                "triage" — takes {items: [{title, subtitle?, description?}], current: N}
                "dashboard" — takes {metrics: [{label, value, delta?, trend?}], columns?}
                "table-actions" — takes {columns, rows, actions?, title?}
                "stepper" — takes {steps: [{label, status}], percentage?, message?}
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
            if _app_mode_state.persist_enabled:
                _persist_session(
                    _app_mode_state.session_id,
                    _app_mode_state.state,
                    {"actions": _app_mode_state.read_actions()},
                    mode="app",
                )
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
# Session persistence tools
# ---------------------------------------------------------------------------


@mcp.tool()
@_track_tool_call
async def openwebgoggles_sessions(max_results: int = 20) -> dict[str, Any]:
    """List persisted session snapshots.

    Returns metadata for previously saved sessions (newest first).
    Sessions are saved when persist=True is passed to the openwebgoggles() tool.

    Each entry includes: session_id, title, mode, created_at, saved_at.
    Use session_id with openwebgoggles_restore() to reload a previous session's state.
    """
    archive = _get_session_archive()
    sessions = archive.list_sessions(max_results=max_results)
    return {"count": len(sessions), "sessions": sessions}


@mcp.tool()
@_track_tool_call
async def openwebgoggles_restore(session_id: str) -> dict[str, Any]:
    """Restore a previously persisted session snapshot.

    Loads the state and actions from a saved session. The returned state
    can be passed directly to openwebgoggles() to resume the UI.

    Args:
        session_id: The session ID from openwebgoggles_sessions().
    """
    archive = _get_session_archive()
    snapshot = archive.get(session_id)
    if snapshot is None:
        return {"error": f"Session not found: {session_id}"}
    return {
        "session_id": snapshot.get("session_id"),
        "title": snapshot.get("title"),
        "mode": snapshot.get("mode"),
        "created_at": snapshot.get("created_at"),
        "saved_at": snapshot.get("saved_at"),
        "state": snapshot.get("state", {}),
        "actions": snapshot.get("actions", []),
    }


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


_INIT_DISPATCH = {
    "claude": _init_claude,
    "claude-desktop": _init_claude_desktop,
    "opencode": _init_opencode,
}


def _dispatch_subcommand(cmd: str | None) -> bool:
    """Handle subcommands that exit before starting the MCP server.

    Returns True if a subcommand was handled (caller should return), False
    if no subcommand matched and the MCP server should start.
    """
    if cmd == "init":
        if len(sys.argv) < 3 or sys.argv[2] not in _INIT_DISPATCH:
            _init_usage()
            return True
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
        return True

    if cmd == "restart":
        _cmd_restart()
        return True

    if cmd == "status":
        _cmd_status()
        return True

    if cmd == "doctor":
        _cmd_doctor()
        return True

    if cmd == "logs":
        from cli import _cmd_logs, _parse_logs_args

        n_lines, follow = _parse_logs_args(sys.argv[2:])
        _cmd_logs(lines=n_lines, tail=follow)
        return True

    if cmd == "scaffold":
        from cli import _cmd_scaffold, _parse_scaffold_args

        app_name, out_dir, force = _parse_scaffold_args(sys.argv[2:])
        sys.exit(_cmd_scaffold(app_name, output_dir=out_dir, force=force))

    if cmd == "dev":
        from cli import _cmd_dev, _parse_dev_args

        app_name, data_dir, http_port, ws_port, watch_dirs = _parse_dev_args(sys.argv[2:])
        sys.exit(_cmd_dev(app_name, data_dir=data_dir, http_port=http_port, ws_port=ws_port, watch_dirs=watch_dirs))

    if cmd == "playground":
        from cli import _cmd_playground, _parse_playground_args

        http_port, ws_port, no_open = _parse_playground_args(sys.argv[2:])
        sys.exit(_cmd_playground(http_port=http_port, ws_port=ws_port, no_open=no_open))

    if cmd in ("help", "--help", "-h") or (cmd is not None and cmd.startswith("-")):
        _print_usage()
        return True

    return False


def main():
    """Entry point for the openwebgoggles console script.

    Usage:
        openwebgoggles                          # Run MCP server (stdio transport)
        openwebgoggles init <editor> [dir]      # Bootstrap for an editor
        openwebgoggles restart [dir]            # Restart running MCP server
        openwebgoggles status [dir]             # Show server status
        openwebgoggles doctor [dir]             # Diagnose setup
        openwebgoggles logs [--lines N] [-f]    # Show server log
        openwebgoggles scaffold <app> [-o DIR]  # Create custom app scaffold
        openwebgoggles dev <app> [--watch-dir D] # Start dev server with hot-reload
        openwebgoggles playground [--no-open]   # Interactive state playground
    """
    cmd = sys.argv[1] if len(sys.argv) > 1 else None

    if _dispatch_subcommand(cmd):
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
