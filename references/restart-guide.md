# Restart & Lifecycle Guide

OpenWebGoggles manages two processes: the **MCP server** (talks to your editor via stdio) and the **webview server** (HTTP/WebSocket subprocess that serves the browser UI). Both have automatic recovery built in, but sometimes you need manual control.

## Quick Reference

```bash
openwebgoggles restart       # restart the MCP server (seamless, same PID)
openwebgoggles status        # check what's running
openwebgoggles doctor        # diagnose setup problems
```

All commands auto-discover running instances from `.opencode/webview/` in the current directory. Pass a directory argument to target a different project:

```bash
openwebgoggles status ~/my-project
```

## Automatic Recovery

The server handles these scenarios without any intervention:

### Webview subprocess crash

If the webview HTTP server dies mid-session, the MCP server detects it on the next tool call and restarts it automatically. The browser reconnects via WebSocket. No data is lost — state and actions live on disk.

### Package upgrade

A background monitor polls for version changes every 30 seconds. When it detects an upgrade (via `pipx upgrade openwebgoggles` or `pip install --upgrade`), it:

1. Sets a reload flag (new tool calls get a "please retry" response)
2. Waits up to 60 seconds for in-flight tool calls to finish
3. Gracefully closes the webview session
4. Calls `os.execv()` to replace the process in-place

On Unix, this is seamless — same PID, same stdin/stdout pipes. The editor never sees a disconnect. On Windows, the editor will need to restart the MCP server.

### Stale server cleanup

On startup, the MCP server checks `.opencode/webview/.server.pid`. If it finds a PID from a crashed previous session, it kills the orphan and reclaims the lock before starting fresh.

### Keep-alive pings

During long `webview()` calls (waiting for human input), the server sends MCP progress notifications every 10 seconds. This prevents the editor's MCP client from timing out with `-32001` errors.

## Manual Restart

### `openwebgoggles restart`

Sends `SIGUSR1` to the running MCP server, triggering the same `os.execv()` reload used by automatic upgrades. The process restarts in-place without breaking the stdio connection to your editor.

**When to use it:**
- After editing the server source code during development
- To clear accumulated state without restarting your editor
- When the server is in a degraded state but still responsive

**How it works:**

1. Reads the MCP server PID from `.opencode/webview/.mcp.pid`
2. Sends `SIGUSR1` to that process
3. The signal handler sets a flag, the event loop picks it up
4. In-flight tool calls drain (up to 60s), webview closes gracefully
5. `os.execv()` replaces the process — same PID, fresh code

On Windows (no `SIGUSR1`), the command sends `SIGTERM` instead. The editor detects the process exit and restarts the MCP server automatically.

### Editor-specific restart

You can also restart the MCP server from within your editor:

**Claude Code:**
- Type `/mcp` in the Claude Code chat to open the MCP management panel
- Find `openwebgoggles` in the server list and restart it

**OpenCode:**
- Use the MCP server management UI to restart `openwebgoggles`

## Diagnostics

### `openwebgoggles status`

Shows a snapshot of what's running:

```
OpenWebGoggles Status

  MCP server:    running (PID 12345)
  Webview:       running (PID 12346, port 8765)
  Uptime:        4m 32s
  WS clients:    2
  Session:       a1b2c3d4 (dynamic app)
```

If nothing is running:

```
OpenWebGoggles Status

  MCP server:    not running
  Webview:       not running

  To start: openwebgoggles init claude  (then restart your editor)
```

### `openwebgoggles doctor`

Validates your environment and configuration:

```
OpenWebGoggles Doctor

  [ok] Python 3.12.1
  [ok] websockets 13.1
  [ok] PyNaCl 1.5.0
  [ok] mcp 1.2.0
  [ok] Binary: /home/user/.local/bin/openwebgoggles
  [ok] .mcp.json: openwebgoggles configured
  [ok] Config binary path matches installed binary
  [ok] No stale PID files
  [ok] No lock file (clean state)

  All 9 checks passed!
```

Common issues it catches:
- Python version too old (needs 3.11+)
- Missing dependencies (`websockets`, `PyNaCl`, `mcp`)
- Binary not on PATH
- Config file missing or malformed
- Config pointing to a stale binary path (e.g., after reinstall)
- Orphaned PID files from crashed sessions

## Troubleshooting

**"No running MCP server found"** — The server isn't running, or it's running from a different directory. Make sure you're in the project where you ran `openwebgoggles init`. Try `openwebgoggles status` to confirm.

**"Lock held by another process"** — Another MCP server instance holds the webview lock. This usually means your editor spawned a duplicate. Run `openwebgoggles doctor` to diagnose, or restart your editor.

**Browser shows "disconnected"** — The webview subprocess may have crashed. The MCP server will restart it on the next tool call. You can also run `openwebgoggles restart` to force a full reload.

**"Server is reloading after a package update"** — A reload is in progress. Wait a few seconds and retry your tool call.
