# OpenWebGoggles

AI coding agents are good at writing code. They are not good at showing you things. An agent can generate a 200-line diff, but it has no way to pull up a side-by-side review UI, highlight the parts that matter, and wait for you to say "approved" or "try again with fewer abstractions."

OpenWebGoggles fixes that. It gives any agent — Claude Code, a shell script, anything that can write JSON — the ability to open a browser-based UI and get structured decisions back from a human.

Not a chat interface. Not a terminal dump. A real interactive panel: forms, approval flows, dashboards, multi-step wizards. The kind of thing you'd build if you had a few days and a frontend team. Except the agent builds it on the fly from a JSON schema, and the whole round-trip takes seconds.

```
Agent ←→ OpenWebGoggles Server ←→ Browser UI ←→ Human
```

*"The goggles — they do everything."*

## What This Actually Looks Like

Here's a concrete example. Your agent finishes a security audit and has 12 findings to triage. Without OpenWebGoggles, it dumps them into the terminal and asks you to type `approve` or `reject` twelve times. With OpenWebGoggles, it opens a tabbed wizard in your browser — one finding per screen, editable severity dropdowns, analyst notes, a progress bar — and reads back your structured decisions when you're done.

The agent doesn't need to know HTML. It writes a JSON object describing what it wants to show, and the built-in dynamic renderer handles the rest:

```json
{
  "title": "Security Finding 1 of 12",
  "status": "waiting_input",
  "data": {
    "sections": [
      { "type": "text", "content": "**SQL Injection** in `/api/users` endpoint" },
      { "type": "form", "fields": [
        { "key": "severity", "label": "Severity", "type": "select",
          "options": ["critical", "high", "medium", "low"], "value": "high" },
        { "key": "notes", "label": "Analyst Notes", "type": "textarea" }
      ]}
    ]
  },
  "actions_requested": [
    { "id": "confirm", "type": "approve", "label": "Confirmed" },
    { "id": "fp", "type": "reject", "label": "False Positive" }
  ]
}
```

The agent gets back:

```json
{
  "actions": [{
    "action_id": "confirm",
    "type": "approve",
    "value": { "severity": "critical", "notes": "Escalated — no parameterized queries anywhere in this module." }
  }]
}
```

Structured data in, structured data out. The browser is just the rendering layer in between.

## Getting Started

### MCP (the easy path)

If your agent supports the [Model Context Protocol](https://modelcontextprotocol.io), this is a three-minute setup.

Install:

```bash
pip install openwebgoggles
```

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "openwebgoggles": {
      "command": "openwebgoggles"
    }
  }
}
```

Restart your editor. Four tools appear:

| Tool | What it does |
|------|-------------|
| `webview_ask(state)` | Show a UI and block until the human responds |
| `webview_show(state)` | Show a UI without blocking (dashboards, progress) |
| `webview_read()` | Poll for actions without blocking |
| `webview_close()` | Close the session |

That's the entire API surface. Tell your agent something like:

> *"Show me a review UI for these changes and wait for my approval."*

The agent figures out the schema, calls `webview_ask`, and you see a panel in your browser. You click approve. The agent continues.

### Bash Scripts (for shell-based agents)

If your agent orchestrates via shell scripts — or if you just want to understand the mechanics — the bash interface exposes the same capabilities:

```bash
# Start a session
bash scripts/start_webview.sh --app dynamic

# Push state to the browser
bash scripts/write_state.sh '{"version":1, "status":"pending_review", "title":"Review Changes", ...}'

# Block until the human responds (up to 5 minutes)
ACTIONS=$(bash scripts/wait_for_action.sh --timeout 300)

# Clean up
bash scripts/stop_webview.sh
```

| Script | Purpose |
|--------|---------|
| `start_webview.sh --app <name> [--port N]` | Launch server and open browser |
| `write_state.sh '<json>'` | Atomic state write |
| `wait_for_action.sh [--timeout N]` | Block until human acts |
| `read_actions.sh [--clear]` | Read actions, optionally clear |
| `stop_webview.sh` | Graceful shutdown |
| `init_webview_app.sh <name>` | Scaffold a custom app |

## How It Works Under the Hood

The architecture is deliberately simple. Three JSON files in a `.openwebgoggles/` directory are the entire interface between the agent and the browser.

| File | Direction | Purpose |
|------|-----------|---------|
| `state.json` | Agent → Browser | What to show: data, UI schema, requested actions |
| `actions.json` | Browser → Agent | What the human decided |
| `manifest.json` | Shared | Session config: ports, app name, auth token |

The Python server watches these files and pushes updates to the browser over WebSocket in real time. The browser renders the UI and writes responses back. The agent reads the response file and continues.

This means you can debug the entire system by looking at three JSON files. No hidden state, no message queues, no databases. If something looks wrong in the browser, `cat .openwebgoggles/state.json` and you'll see exactly what the agent sent.

## The Dynamic Renderer

Most use cases don't require custom HTML. The built-in `dynamic` app takes a JSON schema and renders a complete, styled interface.

**Section types:** `text`, `items`, `form`, `actions`

**Form field types:** `text`, `textarea`, `number`, `select`, `checkbox`, `email`, `url`, `static`

**Action styles:** `primary`, `success`, `danger`, `warning`, `ghost`, `approve`, `reject`, `submit`, `delete`

You can combine these to build approval flows, configuration wizards, data entry forms, triage interfaces — really any structured interaction that runs on fields, selections, and decisions. For 80% of use cases, you never touch HTML.

## Custom Apps

When the dynamic renderer isn't enough — complex visualizations, custom layouts, domain-specific interactions — you can build a custom app:

```bash
bash scripts/init_webview_app.sh my-dashboard
```

This scaffolds `index.html`, `app.js`, and `style.css` with the SDK already wired up. The client SDK is vanilla JavaScript with zero dependencies:

```javascript
const wv = new OpenWebGoggles();
await wv.connect();

// Listen for state updates from the agent
wv.onStateUpdate((state) => {
  // Render however you want
});

// Send structured responses back
await wv.approve("action-id", { comment: "Looks good" });
await wv.reject("action-id");
await wv.submitInput("field-id", "user input");
await wv.sendAction("custom-id", "custom", { any: "data" });
```

Two working examples are included in `examples/`:

- **approval-review** — Code review UI with unified diffs, per-file toggles, approve/reject with comments
- **security-qa** — Step-by-step security findings triage with editable fields, severity dropdowns, and a progress bar

These aren't toy demos. They're functional interfaces that handle real workflows. Start by reading their source if you're building something custom.

## Patterns That Work Well

**Single approval.** Agent shows a summary, human clicks approve or reject. The simplest case, and probably the most common.

**Multi-step wizard.** For N items that need review, show one at a time. The agent calls `webview_ask` in a loop, advancing to the next item after each response. This avoids overwhelming the user with a wall of decisions.

**Live dashboard.** Agent calls `webview_show` (non-blocking) to display progress, then updates state periodically. Useful for long-running operations where the human wants visibility but doesn't need to act.

**Batch triage.** Show all items at once with per-item actions — tabs, cards, or a list with inline controls. Works well when the total count is under 10 or so.

## Security

The trust model is straightforward: the agent and the browser are on the same machine, and nobody else should be able to read or tamper with the communication between them.

Nine defense layers enforce this, all enabled by default:

- **Localhost-only binding** — the server only listens on 127.0.0.1
- **Bearer token auth** — 32-byte session token, constant-time comparison
- **WebSocket first-message auth** — token verified before any data flows
- **Ed25519 signatures** — server signs every state update (cryptographic proof of origin)
- **HMAC-SHA256** — browser signs every action (tamper detection)
- **Nonce replay prevention** — each action can only be submitted once
- **Content Security Policy** — per-request nonce blocks inline script injection
- **SecurityGate** — 22 XSS patterns, zero-width character detection, schema validation
- **Rate limiting** — 30 actions per minute per session

All cryptographic keys are ephemeral — generated in memory at session start, zeroed on shutdown, never written to disk in plaintext. The test suite covers OWASP Top 10, MITRE ATT&CK techniques, and LLM-specific attack vectors across 471 tests.

The tradeoff is real, though. This level of defense adds complexity to the codebase. If you're running in a fully trusted local environment and want to understand what each layer does, the [security tests](scripts/tests/) are the best documentation.

## Development

```bash
# Run the full test suite
python -m pytest -v

# Lint
ruff check scripts/
```

Python 3.11+ required. Core dependencies: `websockets`, `PyNaCl`, `mcp`.

## Reference Documentation

For the full details:

- [Data Contract](references/data-contract.md) — JSON file formats, state lifecycle, status values
- [SDK API](references/sdk-api.md) — Complete client SDK reference
- [Integration Guide](references/integration-guide.md) — Step-by-step patterns for connecting from other tools

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

Built by [Techtoboggan](https://techtoboggan.com).
