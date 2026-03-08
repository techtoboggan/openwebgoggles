"""
CLI subcommands and init logic for OpenWebGoggles.

Contains all command-line interface functions: editor init helpers, status,
restart, and doctor diagnostics.  The entry point (main) and the init dispatch
table stay in mcp_server.py to allow tests to mock them at that namespace.
"""

import importlib
import importlib.metadata
import json
import os
import platform
import shutil
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EDITORS = ["claude", "claude-desktop", "opencode"]

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

# ---------------------------------------------------------------------------
# Server key resolution
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Claude Desktop init
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# OpenCode init
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# CLI subcommands: restart, status, doctor
# ---------------------------------------------------------------------------


def _find_data_dir(explicit: Path | None = None) -> Path:
    """Resolve the persistent data directory for PID files, state, etc."""
    if explicit is not None:
        return explicit
    # Import here to avoid circular imports; session is a sibling module.
    try:
        from session import _get_data_dir  # noqa: I001
    except ImportError:
        from scripts.session import _get_data_dir  # type: ignore[no-redef]
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
    import signal

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


# -- top-level usage --------------------------------------------------------


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
