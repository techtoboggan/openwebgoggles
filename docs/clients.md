# OpenWebGoggles — Client Compatibility Matrix

OpenWebGoggles operates in one of two modes depending on the MCP client (host) it connects to:

- **MCP Apps mode** — UI renders in a native pane/iframe inside the host. State flows via `structuredContent` in tool results. Non-blocking.
- **Browser mode** — UI opens in a browser tab. State flows via WebSocket to `localhost:18420/18421`. Non-blocking — `openwebgoggles()` returns immediately, agent polls `openwebgoggles_read()` until the user responds.

Mode is detected automatically at connection time — no configuration needed.

---

## Supported Clients

| Client | Mode | Detection Signal | Notes |
|--------|------|-----------------|-------|
| **Claude Code** (v1.x+) | MCP Apps | `clientInfo.name` starts with `"local-agent-mode-"` | Renders `structuredContent` as an inline preview pane. Non-blocking. |
| **Claude Desktop** | MCP Apps | `capabilities.extensions["io.modelcontextprotocol/ui"]` | Native iframe pane. Some versions use `capabilities.experimental` instead. |
| **OpenCode** | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Cursor** | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Zed** | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Cline** (VS Code) | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Continue** (VS Code) | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Sourcegraph Cody** | Browser | No UI extension | Browser tab opens automatically. Non-blocking — agent polls `openwebgoggles_read()`. |
| **Any other client** | Browser | No UI extension | Browser fallback is always available. Non-blocking. |

---

## Detection Flow

```
initialize handshake
        │
        ▼
clientInfo.name starts with "local-agent-mode-"? ──YES──► MCP Apps mode
        │ NO
        ▼
capabilities.extensions has "io.modelcontextprotocol/ui"? ──YES──► MCP Apps mode
        │ NO
        ▼
capabilities.experimental has "io.modelcontextprotocol/ui"? ──YES──► MCP Apps mode
        │ NO
        ▼
Host fetches ui://openwebgoggles/dynamic resource? ──YES──► MCP Apps mode
        │ NO
        ▼
Browser mode (subprocess + localhost WebSocket)
```

The detected mode is **cached for the session lifetime**. Calling `openwebgoggles_close()` resets the cache so the next call re-evaluates.

---

## Feature Availability by Mode

| Feature | MCP Apps | Browser |
|---------|----------|---------|
| All section types | ✓ | ✓ |
| Forms + actions | ✓ | ✓ |
| `openwebgoggles_update()` live push | ✓ | ✓ |
| Multi-page navigation | ✓ | ✓ |
| Non-blocking (poll `openwebgoggles_read()`) | ✓ | ✓ |
| No browser window needed | ✓ | — |
| Works without GUI | ✓ | — |
| HMAC/Ed25519 transport auth | Host | ✓ |

---

## Mode Diagnostics

If you're unsure which mode is active, call `openwebgoggles_status()`. It returns:

```json
{
  "mode": "app",
  "status": "idle",
  "version": "0.15.0"
}
```

A diagnostic log is also written to `.openwebgoggles/owg-diag.log` each time mode is resolved. Example entries:

```
check_ui: client=local-agent-mode-abc123 extra={} -> MATCH:local-agent-bridge
resolve: ctx=yes mode=app
```

---

## Configuration

No mode-specific configuration is needed — detection is fully automatic.

To install OpenWebGoggles for a specific client:

```bash
# Claude Code
openwebgoggles init claude

# Claude Code (global — available in all projects)
openwebgoggles init claude --global

# Claude Desktop
openwebgoggles init claude-desktop

# OpenCode
openwebgoggles init opencode

# Cursor
openwebgoggles init cursor

# Windsurf
openwebgoggles init windsurf
```

---

## Adding Support for a New Client

If your MCP client is not listed above and you want MCP Apps mode:

1. **Advertise the UI extension** in your `initialize` response:
   ```json
   {
     "capabilities": {
       "extensions": {
         "io.modelcontextprotocol/ui": {}
       }
     }
   }
   ```

2. **Fetch the HTML bundle** when you see `_meta.ui.resourceUri = "ui://openwebgoggles/dynamic"` in a tool result:
   ```
   resources/read("ui://openwebgoggles/dynamic")
   → returns self-contained ~168KB HTML (MIME: text/html;profile=mcp-app)
   ```

3. **Render** the HTML in a sandboxed iframe. The renderer communicates via PostMessage JSON-RPC.

4. **Proxy tool calls** from the iframe (`_owg_action`) back to the MCP server.

Browser mode requires no changes — it works with any compliant MCP client.
