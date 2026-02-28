# Plan: MCP Restart CLI & Lifecycle Management

## Context

OpenWebGoggles already has solid automatic restart/recovery internals:
- **Webview subprocess**: auto-restarts on crash (detected in `ensure_started`)
- **Package upgrades**: `os.execv()` self-reload via version monitor
- **Stale servers**: killed on startup via PID file + flock
- **Keep-alive**: progress pings every 10s prevent MCP timeout

But there's **no user-facing CLI** to restart, diagnose, or check status — and no docs explaining how restart works. If something goes sideways, users are stuck reading source code.

## What We're Building

Three new CLI subcommands + a restart reference doc. Zero config required — they auto-discover running instances from `.openwebgoggles/` session files.

### 1. `openwebgoggles restart` — The Hero Command

**What it does:** Finds the running MCP server and triggers a seamless restart.

**Mechanism:**
- Register a `SIGUSR1` handler in the MCP server that triggers `os.execv()` (reuses the existing `_exec_reload()` function)
- The `restart` CLI reads `.openwebgoggles/.server.pid` to find the webview server PID, then walks up to find the parent MCP server PID
- Sends `SIGUSR1` to the MCP server process → seamless restart, same PID, same stdio pipes, editor never notices
- Falls back: if no running instance found, prints clear instructions ("No running MCP server found. Start one with: openwebgoggles init claude")
- Windows: no `SIGUSR1`, so fall back to killing the process (editor will auto-restart it)

**Usage:**
```bash
openwebgoggles restart              # restart MCP server for current project
openwebgoggles restart --data-dir . # explicit data dir
```

### 2. `openwebgoggles status` — Quick Health Check

**What it does:** Shows whether the MCP + webview are running, ports, uptime, session info.

**Mechanism:**
- Reads `.openwebgoggles/manifest.json` for session metadata (ports, app, session ID)
- Hits `http://127.0.0.1:{port}/_health` for live status (uptime, ws_clients)
- Checks if the PID in `.server.pid` is alive
- Shows the MCP server PID (from new `.mcp.pid` file we'll write on startup)

**Output example:**
```
OpenWebGoggles Status
  MCP server:    running (PID 12345)
  Webview:       running (PID 12346, port 8765)
  WebSocket:     2 clients connected
  Uptime:        4m 32s
  Session:       a1b2c3d4 (dynamic app)
```

If nothing's running:
```
OpenWebGoggles Status
  MCP server:    not running
  Webview:       not running

  To start: openwebgoggles init claude  (then restart your editor)
```

### 3. `openwebgoggles doctor` — Setup Diagnostics

**What it does:** Validates the environment and config, catches common setup problems.

**Checks:**
- Python version (3.11+ required)
- Core dependencies installed (websockets, PyNaCl, mcp)
- Binary resolves correctly (`which openwebgoggles`)
- Config file exists and is valid JSON (`.mcp.json` or `opencode.json`)
- Config points to correct binary path (catches stale paths after reinstall)
- No stale lock files or orphaned processes
- Webview server health (if running)

**Output example:**
```
OpenWebGoggles Doctor

  [ok] Python 3.12.1
  [ok] websockets 13.1
  [ok] PyNaCl 1.5.0
  [ok] mcp 1.2.0
  [ok] Binary: /home/user/.local/bin/openwebgoggles
  [ok] .mcp.json found, valid config
  [ok] Binary path in config matches installed path
  [!!] Stale lock file found — cleaning up
  [ok] No orphaned processes

  All checks passed!
```

### 4. Documentation: `references/restart-guide.md`

Covers:
- **Automatic restart** — what the server handles on its own (subprocess crash, package upgrade, stale server cleanup)
- **Manual restart** — when and how to use `openwebgoggles restart`
- **Editor-specific restart** — how to restart from within Claude Code (`/mcp`) and OpenCode
- **Troubleshooting** — common issues and `openwebgoggles doctor` usage
- **How it works under the hood** — signal handling, `os.execv()`, PID discovery

## Implementation Steps

### Step 1: Signal handler for restart
- In `mcp_server.py`, register `SIGUSR1` handler in `main()` that sets a flag
- In the MCP event loop, check the flag and call `_exec_reload()` (same drain + graceful close pattern as version monitor)
- Write MCP server PID to `.openwebgoggles/.mcp.pid` on startup

### Step 2: `restart` subcommand
- Add `_cmd_restart()` function in `mcp_server.py`
- Discover PID from `.openwebgoggles/.mcp.pid`
- Send `SIGUSR1`, wait briefly, verify process restarted
- Add to `main()` dispatch

### Step 3: `status` subcommand
- Add `_cmd_status()` function
- Read manifest.json, .mcp.pid, .server.pid
- Hit /_health endpoint
- Pretty-print results

### Step 4: `doctor` subcommand
- Add `_cmd_doctor()` function
- Run all diagnostic checks
- Print pass/fail results
- Auto-fix what's safe to fix (stale locks)

### Step 5: Documentation
- Create `references/restart-guide.md`
- Update README.md Quick Start section with mention of new commands
- Update CLI usage help text

### Step 6: Tests
- Test signal handler triggers reload flag
- Test `restart` finds PID and sends signal
- Test `status` reads manifest and health correctly
- Test `doctor` detects common problems
- Test edge cases: no running server, stale PIDs, missing files
