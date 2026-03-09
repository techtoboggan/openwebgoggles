# OpenWebGoggles — Architecture

This document covers the internal architecture of OpenWebGoggles using Mermaid diagrams.
GitHub renders Mermaid natively — no build step required.

---

## 1. Browser Mode — Data Flow

The standard flow when running in a terminal/CLI environment (Claude Code, OpenCode, etc.)
that doesn't support MCP Apps native panes.

```mermaid
sequenceDiagram
    participant Agent as 🤖 Agent
    participant MCP as mcp_server.py<br/>(MCP Tools)
    participant FS as state.json<br/>(DataContract)
    participant HTTP as WebviewServer<br/>(HTTP :18420)
    participant WS as WebviewServer<br/>(WS :18421)
    participant Browser as 🌐 Browser

    Agent->>MCP: openwebgoggles(state)
    MCP->>FS: write state.json (SecurityGate validated)
    MCP->>Browser: open URL in browser
    Browser->>HTTP: GET /manifest.json (bearer token)
    HTTP-->>Browser: ports, session token
    Browser->>WS: WebSocket upgrade + HMAC auth
    WS-->>Browser: connected + current state
    Browser->>Browser: render UI sections

    loop Every 0.5s (file watcher)
        MCP->>FS: state change detected
        WS->>Browser: {"type":"state_updated", data}
        Browser->>Browser: re-render
    end

    Browser->>WS: {"type":"action", data:{id, type, formData}}
    WS->>MCP: session.wait_for_action() resolves
    MCP-->>Agent: ActionResult (dict)
```

---

## 2. MCP Apps Mode — Native Pane Flow

Used when the MCP host (Claude Code, Claude Desktop) supports the
`io.modelcontextprotocol/ui` extension. The UI renders inside a native iframe pane
rather than a browser window.

```mermaid
sequenceDiagram
    participant Agent as 🤖 Agent
    participant MCP as mcp_server.py<br/>(MCP Tools)
    participant Host as MCP Host<br/>(Claude Code/Desktop)
    participant Iframe as 📦 Iframe<br/>(dynamic renderer)

    Note over Agent,Host: Host advertises ui extension in initialize capabilities

    Agent->>MCP: openwebgoggles(state)
    MCP-->>Host: CallToolResult<br/>structuredContent=state<br/>_meta.ui.resourceUri="ui://..."

    Host->>MCP: resources/read("ui://openwebgoggles/dynamic")
    MCP-->>Host: HTML bundle (~168KB, inline JS/CSS)
    Host->>Iframe: render in native pane

    Host->>Iframe: ui/notifications/tool-result (structuredContent)
    Iframe->>Iframe: render UI sections (same renderer as browser mode)

    Iframe->>Host: tools/call("_owg_action", {id, type, formData})
    Host->>MCP: _owg_action tool invocation
    MCP-->>Agent: ActionResult (dict)

    Note over Agent,Iframe: openwebgoggles_update() pushes new state without round-trip
    Agent->>MCP: openwebgoggles_update(newState)
    MCP-->>Host: structuredContent=newState
    Host->>Iframe: ui/notifications/tool-result
    Iframe->>Iframe: re-render
```

---

## 3. Security Layers (9-Layer Defense)

```mermaid
graph TD
    subgraph Input["Untrusted Input"]
        LLM["🤖 LLM-generated state"]
        Browser["🌐 Browser actions"]
    end

    subgraph Layers["Defense Layers (applied in order)"]
        L1["① Localhost binding<br/>127.0.0.1 only, no 0.0.0.0"]
        L2["② Bearer token auth<br/>Per-session random token"]
        L3["③ WebSocket HMAC auth<br/>HMAC-SHA256 + nonce"]
        L4["④ Ed25519 signing<br/>Server signs all WS messages"]
        L5["⑤ HMAC verification<br/>Client verifies all messages"]
        L6["⑥ Nonce tracking<br/>Replay attack prevention"]
        L7["⑦ SecurityGate<br/>XSS scan, schema allowlist,<br/>size limits, depth limits,<br/>CSS isolation, ReDoS gate"]
        L8["⑧ CSP headers<br/>script-src nonce, no unsafe-inline"]
        L9["⑨ Rate limiting<br/>30 actions/min per IP"]
    end

    subgraph Output["Trusted Output"]
        Renderer["✅ Browser renderer<br/>(sanitized DOM)"]
        AgentResult["✅ Agent callback<br/>(validated action)"]
    end

    LLM --> L7
    Browser --> L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
    L7 --> L8 --> L9 --> Renderer
    L7 --> AgentResult

    style L7 fill:#2d333b,stroke:#58a6ff,color:#e6edf3
    style L1 fill:#1c2128,stroke:#30363d,color:#8b949e
    style L8 fill:#1c2128,stroke:#30363d,color:#8b949e
    style L9 fill:#1c2128,stroke:#30363d,color:#8b949e
```

---

## 4. Browser Mode vs MCP Apps Mode — Side-by-Side

```mermaid
graph LR
    subgraph BrowserMode["🌐 Browser Mode"]
        direction TB
        B1["Agent calls openwebgoggles()"]
        B2["MCP server writes state.json"]
        B3["Subprocess: webview_server.py<br/>(HTTP :18420, WS :18421)"]
        B4["Browser opened via webbrowser.open()"]
        B5["SDK connects over WebSocket"]
        B6["Sections rendered in full browser tab"]
        B7["Actions sent over WebSocket"]
        B8["wait_for_action() blocks agent"]

        B1 --> B2 --> B3 --> B4 --> B5 --> B6
        B6 --> B7 --> B8
    end

    subgraph AppMode["📦 MCP Apps Mode"]
        direction TB
        A1["Agent calls openwebgoggles()"]
        A2["AppModeState stored in memory<br/>(no subprocess, no filesystem)"]
        A3["Host fetches ui:// resource<br/>(168KB HTML bundle)"]
        A4["Host renders iframe natively"]
        A5["mcp-transport.js via PostMessage"]
        A6["Same sections.js renderer"]
        A7["_owg_action tool via host proxy"]
        A8["Returns structuredContent immediately<br/>(non-blocking)"]

        A1 --> A2 --> A3 --> A4 --> A5 --> A6
        A6 --> A7 --> A8
    end

    subgraph Detection["Mode Detection"]
        D1{"Host capabilities<br/>include ui extension?"}
        D1 -->|"Yes"| AppMode
        D1 -->|"No"| BrowserMode
    end
```

---

## 5. Section Type Inventory

All section types supported by the dynamic renderer:

```mermaid
mindmap
  root((OWG Sections))
    Input
      form
      actions
    Display
      text
      items
      static field
    Data Viz
      table
      metric
      chart
      heatmap
      timeline
    Structure
      tabs
      tree
      network
    Live
      progress
      log
      diff
```

---

## 6. File Structure

```
openwebgoggles/
├── scripts/                    Python source (NOT src/)
│   ├── mcp_server.py           MCP tools, AppModeState, presets, lifespan
│   ├── session.py              WebviewSession (subprocess lifecycle)
│   ├── webview_server.py       HTTP + WebSocket server (raw asyncio)
│   ├── security_gate.py        SecurityGate — validates all state payloads
│   ├── crypto_utils.py         Ed25519, HMAC-SHA256, NonceTracker
│   ├── bundler.py              Runtime HTML bundler for MCP Apps
│   ├── monitor.py              Version monitor + hot-reload manager
│   ├── cli.py                  CLI subcommands (init, status, doctor, dev, scaffold)
│   ├── log_config.py           Structured logging (text/JSON, rotating file)
│   ├── exceptions.py           Typed exception hierarchy (OWGError subtypes)
│   └── tests/                  2194+ tests (unit + BDD + E2E Playwright)
├── assets/
│   ├── sdk/
│   │   ├── openwebgoggles-sdk.js   Browser SDK (WS + HTTP polling)
│   │   └── openwebgoggles.d.ts     TypeScript definitions
│   ├── apps/
│   │   └── dynamic/            Built-in renderer (no build step)
│   │       ├── index.html      Entry point, CSS variables, all section styles
│   │       ├── app.js          Orchestrator — transport, render, pages, actions
│   │       ├── utils.js        Escaping, sanitizeHTML, markdown, CSS validation
│   │       ├── sections.js     All section renderers + event binding
│   │       ├── charts.js       SVG chart renderer (6 chart types)
│   │       ├── validation.js   Client-side field validation engine
│   │       ├── behaviors.js    Conditional show/hide/enable/disable
│   │       └── mcp-transport.js PostMessage JSON-RPC adapter
│   └── template/               Scaffold template for custom apps
└── .github/workflows/
    ├── ci.yml                  Unit + E2E + lint on push/PR
    ├── release.yml             Auto-create GitHub Release on v* tag
    ├── publish.yml             PyPI publish on GitHub Release
    └── security.yml            Weekly pip-audit + bandit SAST
```
