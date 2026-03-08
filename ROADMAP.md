# OpenWebGoggles — Next-Level Roadmap

This is the authoritative plan for everything we're building. Every phase is ordered by
impact and dependency. Phases 1–4 are committed; Phases 5–6 are scheduled; Phase 7 is
backlog (parked, not forgotten).

**Priority input**: MCP Apps resilience first. Enterprise features (RBAC, multi-user,
audit logging) are explicitly deferred to v0.16+.

---

## Phase 1 — Resilience & Hardening (`v0.15.x`) ✅ COMPLETE

*Make what exists bulletproof before adding new surface area.*

### 1.1 MCP Apps: Request Timeout in `_sendRequest()` ✅

**What**: Add a 30-second timeout to the `_sendRequest()` PostMessage bridge in
`assets/apps/dynamic/mcp-transport.js`. If the host doesn't respond to a `tools/call`
request within the timeout window, reject the promise with a typed `TimeoutError`.

**Why**: Currently, if the host never responds (crash, bug, network issue), the iframe
shows a loading spinner indefinitely. Users have no way to know something went wrong or
to retry.

**Approach**:
- Wrap the pending-request promise in `Promise.race([responsePromise, timeoutPromise])`
- On timeout, call the registered `error` event handler with `{code: "TIMEOUT", message: "Host did not respond within 30s"}`
- Add `requestTimeout` option to `OWGTransport` constructor (default: 30000ms)
- Clean up the pending-request entry from the map on timeout

**Acceptance criteria**:
- Unit test: mock host that never responds → `error` event fires within 30s + ε
- Unit test: mock host that responds at t=25s → resolves normally
- No regression on normal action submission
- Configurable via `OWGTransport({requestTimeout: N})`

**Effort**: 0.5 days

---

### 1.2 MCP Apps: Error Banner on Action Failure ✅

**What**: When a PostMessage action fails (timeout, host rejection, network error), show
a visible error banner inside the iframe panel rather than silently failing.

**Why**: Silent failures are the worst user experience. Users submit a form, nothing
happens, they don't know if it worked or not.

**Approach**:
- In `app.js`, subscribe to the `error` event from the transport
- Render an error banner at the top of `#content` using existing `owg-callout-error` CSS class
- Banner includes: error message, a "Retry" button that re-submits the last action, a dismiss (×) button
- Auto-dismiss after 10 seconds for non-fatal errors; persist for fatal ones
- SecurityGate validation: error message from host is untrusted — escape it via `escHtml()`

**Acceptance criteria**:
- E2E test: trigger a transport error → error banner appears with correct message
- E2E test: dismiss button removes banner
- E2E test: retry button re-submits last action
- Error text is HTML-escaped (no XSS via crafted error message from host)
- Banner uses existing CSS classes (no new styles needed)

**Effort**: 0.5 days

---

### 1.3 MCP Apps: Host Disconnect Detection ✅

**What**: Detect when the MCP host disconnects (iframe unloaded, tab closed, host
crash) and emit a `disconnected` event on the transport so the app can show appropriate UI.

**Why**: Currently, if the host closes the iframe, all subsequent `postMessage` calls
silently fail. The app stays in its last state with no indication it's orphaned.

**Approach**:
- Listen for `window.addEventListener('pagehide')` and `'beforeunload'` to detect unload
- In the PostMessage handler, detect `MessageEvent` delivery failures (source window closed)
- On disconnect detected: emit `disconnected` event, show "Session ended" overlay (non-dismissable)
- In `mcp-transport.js`: send a heartbeat `ping` message to host every 15s; if no `pong`
  within 5s, emit `disconnected`

**Acceptance criteria**:
- Unit test: simulate host window close → `disconnected` event fires within 20s
- Unit test: heartbeat round-trip succeeds → no `disconnected` event
- UI test: "Session ended" overlay renders correctly
- Does not fire false positives during normal operation

**Effort**: 1 day

---

### 1.4 WebSocket Heartbeat / Keep-Alive ✅

**What**: Add a ping/pong heartbeat to the WebSocket connection in browser mode.
Server sends a `ping` frame every 30 seconds; if no pong within 10 seconds, close
and reconnect.

**Why**: Idle WebSocket connections are silently dropped by proxies, load balancers,
and OS network stacks after ~5 minutes of inactivity. This causes agents waiting for
user input to silently lose the connection.

**Approach**:
- Server side (`webview_server.py`): in `_handle_ws`, start a heartbeat task that sends
  `websockets.ping()` every 30s and awaits the pong with a 10s timeout
- Client side (`openwebgoggles-sdk.js`): handle `ping` frames (websockets library handles
  this automatically at the protocol level — verify it's not disabled)
- On timeout, close the connection with code 4002 and let the existing reconnect logic handle it

**Acceptance criteria**:
- Unit test: heartbeat task sends ping at correct interval
- Unit test: no pong within timeout → connection closed with 4002
- Unit test: pong received → connection stays open
- Existing reconnect logic picks up after heartbeat-triggered close
- No regression on normal message flow

**Effort**: 0.5 days

---

### 1.5 HTTP Server: Connection Limit ✅

**What**: Cap simultaneous HTTP connections to the webview server at 50. Reject
connections above the limit with HTTP 429.

**Why**: The server is localhost-only and single-session; there's no reason to accept
unlimited connections. An agent bug or malicious input could open thousands of connections
and exhaust file descriptors.

**Approach**:
- Wrap `asyncio.start_server` callback in a connection semaphore
  (`asyncio.Semaphore(MAX_CONNECTIONS=50)`)
- When semaphore is exhausted, write a minimal HTTP 429 response and close the connection
  without acquiring the semaphore
- Make `MAX_CONNECTIONS` a constant in `webview_server.py` (not configurable — hardcoded
  safe default)

**Acceptance criteria**:
- Unit test: 51st concurrent connection receives 429
- Unit test: connections under the limit are served normally
- Semaphore is released on connection close (no leak)
- Constant documented in source

**Effort**: 0.5 days

---

### 1.6 Security: ReDoS Gate on Behavior `matches` Condition ✅

**What**: User-supplied regex strings in `behaviors[].when.matches` conditions are
currently passed to `new RegExp()` without a safety check. Apply `_is_redos_safe()`
validation server-side before the state is accepted.

**Why**: A crafted regex like `(a+)+` can cause catastrophic backtracking and freeze the
browser tab. This is a user-supplied input path that bypasses the existing ReDoS gate.

**Approach**:
- In `SecurityGate.validate_state()`, walk all `behaviors[].when` objects
- If `matches` key is present, call `_is_redos_safe()` on the value
- Reject state with a descriptive error if the pattern is unsafe
- Add the same check in the JS renderer (`behaviors.js`) before `new RegExp()` — defensive
  belt-and-suspenders, even though SecurityGate is the authority

**Acceptance criteria**:
- Unit test: catastrophic regex → state rejected with clear error message
- Unit test: normal safe regex → state accepted
- Unit test: missing `matches` key → no error
- Existing BDD behavior scenarios still pass

**Effort**: 0.5 days

---

### 1.7 Rate Limiter: Bounded Timestamp List ✅

**What**: The sliding-window rate limiter in `webview_server.py` stores all action
timestamps in a growing list. Cap the list at 1000 entries.

**Why**: Minor memory leak. If an agent somehow submits actions rapidly for hours
(bug, loop), the list grows without bound.

**Approach**:
- In `RateLimiter.check()`, after the sliding window prune, also check
  `len(self._timestamps) > 1000` and truncate to the oldest 1000
- This is defence-in-depth; the rate limit itself prevents more than 30/min

**Acceptance criteria**:
- Unit test: add 1001 timestamps → list stays at ≤1000
- Existing rate limiter tests pass

**Effort**: 0.25 days

---

## Phase 2 — Feature Expansion (`v0.15.x` continued)

*Unblock real-world workflows that are currently impossible.*

### 2.1 New Field Type: `slider` / `range`

**What**: A range input field with min, max, step, and current value display.

**Schema**:
```json
{
  "key": "threshold",
  "label": "Confidence Threshold",
  "type": "slider",
  "min": 0,
  "max": 100,
  "step": 1,
  "value": 75,
  "unit": "%"
}
```

**Approach**:
- Renderer: HTML `<input type="range">` + sibling `<span>` showing live value (updated via `input` event)
- `unit` displayed after the value (e.g., "75%")
- Value submitted as number, not string
- SecurityGate: validate `min`/`max`/`step`/`value` are numbers; `min < max`; `value` in range
- Validation.js: `required` constraint checks value is not `min` (or explicit `requiredNotMin`)

**Acceptance criteria**:
- E2E test: slider renders, dragging updates displayed value, form submission includes correct value
- Unit test: SecurityGate validates schema correctly
- Unit test: out-of-range value in submitted action is rejected

**Effort**: 1 day

---

### 2.2 New Field Type: `date` / `datetime`

**What**: Native date and datetime-local pickers.

**Schema**:
```json
{
  "key": "deploy_at",
  "label": "Deploy Window",
  "type": "datetime",
  "value": "2026-03-10T14:00",
  "min": "2026-03-08T00:00",
  "max": "2026-12-31T23:59"
}
```

**Approach**:
- Renderer: HTML `<input type="date">` or `<input type="datetime-local">`
- Value output is ISO 8601 string
- `min`/`max` map to HTML `min`/`max` attributes
- SecurityGate: validate value matches ISO 8601 pattern; `min`/`max` are valid dates if provided

**Acceptance criteria**:
- E2E test: picker renders, selected value submitted as ISO string
- Unit test: SecurityGate rejects non-ISO values
- Unit test: value before `min` or after `max` fails required validation

**Effort**: 0.5 days

---

### 2.3 New Field Type: `autocomplete`

**What**: Text input with a dropdown list of suggestions. Supports both static
option lists and filtering as-you-type.

**Schema**:
```json
{
  "key": "assignee",
  "label": "Assignee",
  "type": "autocomplete",
  "options": ["alice", "bob", "carol"],
  "placeholder": "Search users...",
  "allowCustom": true
}
```

**Approach**:
- Renderer: `<input>` + `<datalist>` (native, no JS lib needed) for static options
- `allowCustom: true` (default): accepts values not in the list
- `allowCustom: false`: validation fails if submitted value not in options list
- Filter happens client-side in the datalist (browser handles it natively)
- SecurityGate: options list validated same as `select` field

**Acceptance criteria**:
- E2E test: typing filters suggestions, selecting submits value
- E2E test: `allowCustom: false` + unlisted value → form validation error
- Unit test: SecurityGate validates options array

**Effort**: 0.5 days

---

### 2.4 New Field Type: `file`

**What**: File upload field. Agent receives file content as base64 or file path.

**Schema**:
```json
{
  "key": "config_file",
  "label": "Upload Config",
  "type": "file",
  "accept": ".json,.yaml,.yml",
  "maxSizeMb": 5,
  "encoding": "base64"
}
```

**Approach**:
- Renderer: `<input type="file">` with `accept` and size validation before submission
- On file select: read with `FileReader.readAsDataURL()` (base64) or `readAsText()` (text)
- Submitted value: `{name: "foo.json", size: 1024, type: "application/json", content: "base64..."}`
- `maxSizeMb` enforced client-side before submission (show error if exceeded)
- SecurityGate: validate submitted object has expected keys; `content` is valid base64;
  `name` passes filename sanitization (no path traversal, no null bytes)
- `encoding: "text"` alternative for text files (skip base64 round-trip)

**Acceptance criteria**:
- E2E test: select file → submitted action includes file content
- E2E test: file exceeds `maxSizeMb` → validation error, no submission
- Unit test: SecurityGate rejects crafted `name` with path traversal
- Unit test: SecurityGate rejects invalid base64 content

**Effort**: 2 days

---

### 2.5 Collapsible Sections

**What**: Any section can be collapsed/expanded by the user. Agents can set initial
collapsed state.

**Schema addition**:
```json
{
  "type": "text",
  "title": "Debug Info",
  "collapsible": true,
  "collapsed": true,
  "content": "..."
}
```

**Approach**:
- Renderer: add `▶`/`▼` toggle button to section header when `collapsible: true`
- CSS: slide transition using `max-height` + `overflow: hidden` (no JS animation lib)
- State is client-local (not round-tripped to agent)
- `collapsed: true` renders initially collapsed; header still visible

**Acceptance criteria**:
- E2E test: collapsed section renders with header only, click expands
- E2E test: `collapsed: false` renders expanded
- No regression on non-collapsible sections

**Effort**: 0.5 days

---

### 2.6 Client-Side Table Filter

**What**: Search box above a table that filters rows client-side without an agent round-trip.

**Schema addition**:
```json
{
  "type": "table",
  "title": "Issues",
  "filterable": true,
  "filterPlaceholder": "Search issues...",
  "columns": [...],
  "rows": [...]
}
```

**Approach**:
- Renderer: inject `<input type="search">` above table when `filterable: true`
- On input: hide rows where no column value contains the search string (case-insensitive)
- Show "N of M rows" counter below table
- Filter is client-local; submitted actions still reference original row indices

**Acceptance criteria**:
- E2E test: typing in filter hides non-matching rows
- E2E test: clearing filter restores all rows
- E2E test: row click on filtered results sends correct row data
- Performance: 500-row table filters without noticeable lag

**Effort**: 0.5 days

---

### 2.7 Copy-to-Clipboard Buttons

**What**: `copyable: true` on `text` sections or `static` fields adds a copy icon button.
Clicking it copies the content to the clipboard.

**Schema addition**:
```json
{"type": "text", "title": "API Key", "content": "sk-abc123...", "copyable": true}
{"key": "token", "type": "static", "value": "eyJ...", "copyable": true}
```

**Approach**:
- Renderer: add `<button class="owg-copy-btn">⎘</button>` to section/field header
- On click: `navigator.clipboard.writeText(content)` → button briefly shows "✓"
- Fallback for no clipboard API: `document.execCommand('copy')` on a hidden textarea
- SecurityGate: no changes needed (button is UI-only, no new data paths)

**Acceptance criteria**:
- E2E test: click copy button → clipboard contains correct text
- E2E test: button shows confirmation feedback
- Accessible: button has `aria-label="Copy to clipboard"`

**Effort**: 0.5 days

---

## Phase 3 — Developer Experience (`v0.15.x` continued)

*Make building with OWG feel modern from day one.*

### 3.1 TypeScript Definitions

**What**: Publish a `openwebgoggles.d.ts` file alongside the SDK that provides full
type definitions for all state schemas, field types, section types, action payloads,
and SDK events.

**Approach**:
- Hand-write `assets/sdk/openwebgoggles.d.ts` (generated would require a build step we don't have)
- Types cover: `OWGState`, `Section` (discriminated union by `type`), `Field` (discriminated
  union by `type`), `Action`, `ActionResult`, `OWGTransport`, `OWGTransportOptions`
- Include in `pyproject.toml` package data so it ships with the wheel
- Document in README: "TypeScript users can `import type` or reference via `/// <reference>`"

**Acceptance criteria**:
- `tsc --noEmit` passes on a TypeScript file that imports from the definitions
- All section types are covered (11 types)
- All field types are covered (10 types post Phase 2)
- `OWGTransport` events are typed
- Structural test: check that `.d.ts` file exists in the installed package

**Effort**: 1.5 days

---

### 3.2 JSDoc Comments on SDK

**What**: Add JSDoc comments to all public methods and events in
`assets/sdk/openwebgoggles-sdk.js`.

**Approach**:
- `/** @param {string} event @param {Function} handler */` on `on()`, `off()`, `emit()`
- `/** @returns {Promise<ActionResult>} */` on `waitForAction()`
- `/** @type {OWGState} */` on state properties
- This enables VS Code hover documentation without TypeScript

**Acceptance criteria**:
- All public methods have `@param`, `@returns` JSDoc
- All events have `@event` tags
- Existing tests still pass

**Effort**: 0.5 days

---

### 3.3 Five New Presets

**What**: Expand `_expand_preset()` in `mcp_server.py` with 5 new shorthand patterns.

| Preset | State shape | Use case |
|--------|-------------|----------|
| `form-wizard` | `{steps, currentStep, fields}` | Multi-step guided form |
| `triage` | `{items, actions}` | Batch approve/reject/skip list |
| `dashboard` | `{metrics, charts}` | Live metrics + charts overview |
| `table-actions` | `{columns, rows, rowActions}` | Table with per-row action buttons |
| `stepper` | `{steps, currentStep}` | Visual step progress (no form) |

**Approach**:
- Each preset maps to a fully-specified `data.sections` array
- All expanded states must pass existing SecurityGate validation
- Add tests: one test per preset validating expansion + SecurityGate pass-through
- Document in README preset table

**Acceptance criteria**:
- Unit tests: 5 new preset tests pass
- SecurityGate passes all expanded preset states
- README updated with preset examples

**Effort**: 1.5 days

---

### 3.4 `openwebgoggles logs` CLI Subcommand

**What**: `openwebgoggles logs [--tail] [--lines N]` tails the server stderr output.

**Approach**:
- The webview server process writes stderr to a log file:
  `~/.openwebgoggles/server.log` (redirect stderr in `subprocess.Popen`)
- `logs` command reads that file and prints to stdout
- `--tail` keeps following (like `tail -f`) until Ctrl+C
- `--lines N` (default: 50) controls how many lines to show

**Acceptance criteria**:
- Unit test: `logs` with existing log file prints last N lines
- Unit test: `logs` with no log file prints helpful message
- Integration: server actually writes to the log file
- `--tail` follows new writes

**Effort**: 0.5 days

---

### 3.5 Enhanced Custom App Scaffold

**What**: `openwebgoggles init app <name>` generates a complete, documented starter
template with best-practice patterns.

**Current**: Minimal `index.html` + empty `app.js`.

**New template includes**:
- `index.html` — proper CSP nonce slot, correct script load order, viewport meta
- `app.js` — full lifecycle: connect → render → handle actions → disconnect
- `styles.css` — OWG CSS variables pre-imported, component examples
- `README.md` — how to run locally, how to add to Claude Code, how to test
- `example-state.json` — sample state payload to paste into `openwebgoggles` call
- `.vscode/settings.json` — auto-format on save, path mappings

**Approach**:
- Bundle templates as package data (alongside existing `apps/dynamic/`)
- `_init_app()` function in `mcp_server.py` copies templates and substitutes `{{APP_NAME}}`
- Add `app` sub-command to CLI dispatch table

**Acceptance criteria**:
- Unit test: `init app myapp` creates all 6 expected files in target dir
- Unit test: idempotent — running twice doesn't overwrite existing files
- Generated `app.js` is valid JavaScript (parse check)
- Generated `README.md` contains correct app name

**Effort**: 1 day

---

### 3.6 Hot-Reload Dev Server

**What**: When running in dev mode (`webview_server.py --dev`), watch app JS/CSS/HTML
files and trigger a browser reload when they change.

**Why**: Currently developers must restart the server to see JS changes, which is slow.

**Approach**:
- Extend `_file_watcher` in `webview_server.py` to also watch `*.js`, `*.css`, `*.html`
  in `apps_dir` when `--dev` flag is set
- On change: broadcast `{"type": "reload"}` over WebSocket
- In SDK/mcp-transport.js: handle `reload` message with `window.location.reload()`
- Only active in dev mode (not in production — security boundary)
- Launch config (`launch.json`) already passes `--apps-dir assets/apps` — add `--dev` flag

**Acceptance criteria**:
- E2E test (slow): modify `app.js` while server running → browser reloads within 1.5s
- Unit test: file watcher detects `.js` change and broadcasts reload
- `reload` message NOT sent in production mode (flag guard)
- Does not reload on `state.json` changes (only source files)

**Effort**: 1 day

---

## Phase 4 — Code Quality & Refactor (`v0.15.x` / `v0.16.x`)

*Pay down structural debt. Based on `plan.md`.*

### 4.1 Split `mcp_server.py` into Modules

`mcp_server.py` is 3,100+ lines mixing CLI, session management, MCP tools, version
monitoring, and process lifecycle. Split into focused modules:

| New file | Contents | Lines (est.) |
|----------|----------|--------------|
| `scripts/cli.py` | `_cmd_restart/status/doctor`, `_init_claude/opencode`, `_resolve_binary`, `main()` | ~400 |
| `scripts/session.py` | `WebviewSession` + port utils + browser detection | ~600 |
| `scripts/monitor.py` | `_version_monitor`, `ReloadManager`, `_sigusr1_handler` | ~200 |
| `scripts/mcp_server.py` | MCP tool definitions + `AppModeState` + thin glue only | ~800 |

**Approach**:
- Refactor only — no behavior changes. External interface unchanged.
- Move in strict dependency order: `cli.py` first (no deps on others), then `monitor.py`,
  then `session.py`, then slim down `mcp_server.py`
- Update all `import` statements in test files
- `pyproject.toml` entry point stays `scripts.mcp_server:main` (re-exported from `cli.py`)

**Acceptance criteria**:
- All 1,976+ tests still pass after each step
- No new test failures
- `mcp_server.py` < 1000 lines after refactor
- Each new module has its own test file

**Effort**: 3 days

---

### 4.2 Split `webview_server.py` into Modules

Similar treatment for `webview_server.py` (1,070 lines):

| New file | Contents |
|----------|----------|
| `scripts/server/handlers.py` | HTTP route handlers (Request/Response pattern) |
| `scripts/server/websocket.py` | WebSocket handler, auth, message dispatch |
| `scripts/server/auth.py` | Token validation, HMAC verification, nonce gate |
| `scripts/server/state.py` | `DataContract`, `RateLimiter` |
| `scripts/webview_server.py` | `WebviewServer` orchestration + `main()` only |

**Approach**:
- Introduce `Request`/`Response` dataclasses (from `plan.md`) to decouple HTTP from asyncio
- This enables unit tests on handlers without starting a real server
- WS handler split into `authenticate_ws()` + `handle_ws_message()` pure functions

**Acceptance criteria**:
- All existing server tests pass
- New unit tests cover previously untestable HTTP handlers (~200 new stmts covered)
- `webview_server.py` < 300 lines after refactor

**Effort**: 3 days

---

### 4.3 Structured Logging

**What**: Replace `logging.basicConfig(stderr)` with structured, contextual logging.

**Features**:
- `--log-format json` flag: emit `{"ts": ..., "level": ..., "msg": ..., "session_id": ...,
  "tool": ..., "mode": ...}` JSON lines — machine-parseable by log aggregators
- Log rotation: when log file exceeds 10MB, rotate to `.log.1` (keep 3 rotations)
- `--log-level DEBUG` enables field-level tracing (state diffs, action payloads)
- Default (no flag): human-readable format unchanged (no breaking change)

**Approach**:
- `logging.handlers.RotatingFileHandler` in `start()` when `--log-file` provided
- Custom `logging.Formatter` subclass for JSON format
- Add `session_id` to `LogRecord` via `logging.LoggerAdapter`

**Acceptance criteria**:
- Unit test: JSON formatter output is valid JSON with required fields
- Unit test: log rotation happens at 10MB
- `--log-format json` + `--log-level debug` shows state changes
- Default behavior unchanged (no new files created without explicit flags)

**Effort**: 1 day

---

### 4.4 Custom Exception Hierarchy

**What**: Replace bare `Exception` raises and `except Exception` catches with typed
exceptions that tests can assert on precisely.

```python
class OWGError(Exception): ...
class SecurityGateError(OWGError): ...
class CryptoError(OWGError): ...
class AuthError(OWGError): ...
class SessionError(OWGError): ...
class StateValidationError(SecurityGateError): ...
class ActionValidationError(SecurityGateError): ...
```

**Approach**:
- Define hierarchy in `scripts/exceptions.py`
- Update `SecurityGate` to raise `StateValidationError`/`ActionValidationError`
- Update `WebviewSession` to raise `SessionError` on lifecycle failures
- Update all `except Exception` catches to catch specific subclasses where intent is clear
- Keep broad catches only at the outermost MCP tool boundary

**Acceptance criteria**:
- Unit tests: assert on specific exception types (not bare `Exception`)
- All existing tests pass
- No new broad `except Exception` catches introduced

**Effort**: 1 day

---

### 4.5 Increase Test Coverage to 85%+

Building on `plan.md`, these test additions complete the coverage goal:

| Test file | New statements covered | Focus |
|-----------|----------------------|-------|
| `test_cli.py` (expanded) | ~250 | All CLI subcommands post-refactor |
| `test_monitor.py` | ~100 | `ReloadManager`, version detection |
| `test_session_expanded.py` | ~150 | Port utils, browser detection, lock mgmt |
| `test_webview_handlers.py` | ~200 | Request/Response handler unit tests |
| `test_exceptions.py` | ~20 | Exception hierarchy |

**Projected result**: ~720 newly covered stmts → ~85%+ source coverage

**Acceptance criteria**:
- `pytest --cov=scripts --cov-fail-under=85` passes in CI
- No test uses `time.sleep()` (use `wait_for_function` in E2E, mocks in unit)
- Coverage report shows no untested critical paths

**Effort**: 3 days

---

## Phase 5 — Distribution & Ecosystem (`v0.16.x`)

*Make installation a non-event on any platform.*

### 5.1 Homebrew Formula

**What**: `brew install openwebgoggles` for macOS users.

**Approach**:
- Create `techtoboggan/homebrew-tap` repository
- Write formula: downloads wheel from PyPI, installs with bundled Python
- Add to README installation section
- Add CI check: verify formula installs correctly on macOS runner

**Effort**: 1 day

---

### 5.2 Docker Image

**What**: Official Docker image at `ghcr.io/techtoboggan/openwebgoggles`.

**Use cases**:
- `docker run openwebgoggles init claude` — zero-dependency onboarding
- Container-based agent environments (no host Python needed)

**Approach**:
- `Dockerfile`: `python:3.12-slim` base, `pip install openwebgoggles`, `ENTRYPOINT ["openwebgoggles"]`
- GitHub Actions: build + push to GHCR on release
- Multi-arch: `linux/amd64` + `linux/arm64`

**Effort**: 1 day

---

### 5.3 Automated Release Pipeline

**What**: Fully automate the release — tag push triggers everything.

**Current flow**: Manual `gh release create` → publish workflow runs.

**New flow**: Push `v0.X.Y` tag → GitHub Action creates release → publish workflow triggers.

**Approach**:
- Add `release.yml` workflow: triggers on `v*` tag push
- Creates GitHub Release with auto-generated notes (from `CHANGELOG.md` section for that version)
- Chains into existing `publish.yml` via `workflow_run`
- Keep `gh release create` as an override for manual use

**Acceptance criteria**:
- Test run: push a pre-release tag → release created, publish triggers, PyPI updated
- CHANGELOG section for the version is extracted correctly
- Rollback: manual `gh release delete` still works

**Effort**: 1 day

---

### 5.4 Cross-Client Compatibility Matrix

**What**: Formal testing + documentation for all supported clients.

**Clients to certify**:

| Client | Status | Action |
|--------|--------|--------|
| Claude Code | ✅ Certified | Maintain E2E tests |
| Claude Desktop | ⚠️ Unverified CI | Add explicit E2E test |
| OpenCode | ❓ Claimed | Test + document or remove claim |
| Cursor | ❓ Unknown | Test when MCP support lands |
| Zed | ❓ Unknown | Test when MCP support lands |
| Generic MCP CLI | ⚠️ Untested | Add smoke test |

**Approach**:
- Add `test_client_compat.py` with client-specific smoke tests
- For clients without CI access (Desktop, OpenCode): document manual test procedure
- Add compatibility matrix table to README + dedicated `docs/clients.md` page

**Effort**: 2 days

---

### 5.5 ESM/npm SDK Export

**What**: Publish `openwebgoggles-sdk` as an npm package for JS-native integrations.

**Why**: Enables embedding in web frameworks (React, Svelte, etc.), other MCP clients
built in Node.js, and JS agent runtimes.

**Approach**:
- Wrap `openwebgoggles-sdk.js` as an ESM module with named exports
- Add `package.json` to `assets/sdk/`
- CI: publish to npm on GitHub Release (alongside PyPI)
- TypeScript definitions (from Phase 3.1) included in the npm package

**Effort**: 1.5 days

---

### 5.6 Architecture Diagrams

**What**: Mermaid diagrams in `docs/` covering:
1. Data flow: agent → state.json → HTTP server → WebSocket → browser
2. MCP Apps: tool call → structuredContent → iframe → postMessage → `_owg_action`
3. Security layers: 9-layer model visualized
4. Browser vs MCP Apps mode: side-by-side comparison

**Approach**:
- Write `docs/architecture.md` with embedded Mermaid code blocks
- GitHub renders Mermaid natively — no build step needed
- Link from README "How it works" section

**Effort**: 1 day

---

## Phase 6 — Advanced Visualizations (`v0.16.x`)

*Expand the UI vocabulary for complex agent workflows.*

### 6.1 Tree / Hierarchy Section Type

```json
{
  "type": "tree",
  "title": "File Changes",
  "nodes": [
    {"id": "src", "label": "src/", "children": [
      {"id": "auth.py", "label": "auth.py", "badge": "modified"},
      {"id": "utils.py", "label": "utils.py", "badge": "added"}
    ]}
  ],
  "expandAll": false
}
```

**Approach**: Recursive DOM rendering with CSS indent + toggle triangles.

**Effort**: 2 days

---

### 6.2 Timeline / Gantt Section Type

```json
{
  "type": "timeline",
  "title": "Sprint Plan",
  "items": [
    {"label": "Phase 1", "start": "2026-03-08", "end": "2026-03-15", "color": "blue"},
    {"label": "Phase 2", "start": "2026-03-10", "end": "2026-03-25", "color": "green"}
  ]
}
```

**Approach**: SVG-based timeline; scale determined from min/max dates in data.

**Effort**: 3 days

---

### 6.3 Heatmap / Matrix Section Type

```json
{
  "type": "heatmap",
  "title": "Error Rate by Hour/Day",
  "xLabels": ["Mon", "Tue", "Wed", "Thu", "Fri"],
  "yLabels": ["0h", "6h", "12h", "18h"],
  "values": [[0.1, 0.4, 0.2], ...],
  "colorScale": ["#eaffea", "#ff4444"]
}
```

**Effort**: 2 days

---

### 6.4 Network Diagram Section Type

```json
{
  "type": "network",
  "title": "Service Dependencies",
  "nodes": [{"id": "api", "label": "API"}, {"id": "db", "label": "DB"}],
  "edges": [{"from": "api", "to": "db", "label": "reads"}]
}
```

**Approach**: Force-directed layout using d3-force or hand-rolled physics (no build step).

**Effort**: 4 days

---

## Explicitly Deferred (v0.17+)

These are real needs but not before the core is proven in production:

- **Multi-user sessions** — multiple agents/users sharing a single panel
- **RBAC / permissions** — who can submit which actions
- **Audit logging** — structured log of all HITL interactions
- **Session persistence / recovery** — resume a closed session
- **Serverless deployment** — Vercel, Netlify, AWS Lambda templates
- **Conda-forge package** — pending `brew` validation first
- **Signed releases / SLSA provenance** — after automated pipeline is stable
- **Third-party security audit** — schedule for v0.16 milestone

---

## Execution Order

```
Phase 1 (Resilience)     ████████ 2 weeks
Phase 2 (Features)       ████████████ 3 weeks
Phase 3 (DX)             ████████████ 3 weeks  ← parallel with Phase 4
Phase 4 (Refactor)       ████████████ 3 weeks  ← parallel with Phase 3
Phase 5 (Distribution)   ████████ 2 weeks
Phase 6 (Visualizations) ████████████████ 4 weeks
```

Phases 3 and 4 can run in parallel because they touch different files.
Phase 5 depends on Phase 4 (split files make packaging cleaner).
Phase 6 is independent and can start any time after Phase 2.

---

## Version Mapping

| Version | Phase | Key deliverable |
|---------|-------|-----------------|
| v0.15.0 | 1 | MCP Apps resilience, WS heartbeat, ReDoS fix |
| v0.15.1 | 2a | slider, date, autocomplete fields |
| v0.15.2 | 2b | file upload, collapsible sections, table filter |
| v0.15.3 | 3 | TypeScript defs, 5 presets, logs CLI, hot-reload |
| v0.15.4 | 4a | mcp_server.py split, monitor.py, cli.py |
| v0.15.5 | 4b | webview_server.py split, structured logging |
| v0.16.0 | 5 | Homebrew, Docker, automated releases, compat matrix |
| v0.16.1 | 6a | Tree + timeline sections |
| v0.16.2 | 6b | Heatmap + network sections |

---

## How to Use This Document

- **Starting a new task**: find the task here, read the Approach and Acceptance Criteria
  before touching code.
- **Done with a task**: update the version in `pyproject.toml`, add an entry to
  `CHANGELOG.md`, follow the Release Process in `AGENTS.md`.
- **New idea surfaces**: add it to the correct phase or Deferred section — don't start
  building without documenting it here first.
- **Phase complete**: mark it with `✅ DONE — v0.X.Y` and the completion date.
