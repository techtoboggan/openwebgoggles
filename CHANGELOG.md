# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-03-01

### Security

- **H1: Unsigned WebSocket broadcast from HTTP handler** — `WebviewHTTPHandler._broadcast` sent plain JSON to WebSocket clients, bypassing the Ed25519/HMAC signing layer. Close messages from `/_api/close` were delivered unsigned, which browsers with crypto enabled would reject. Fixed by injecting the server's signed `_broadcast` function into the HTTP handler.
- **H2: SecurityGate parameter shadowed in HTTP handler** — `WebviewHTTPHandler.__init__` accepted a `security_gate` parameter but immediately overwrote it on the next line, creating a redundant second SecurityGate instance and silently discarding the one passed by `WebviewServer`. Fixed by removing the shadowing reassignment.
- **M1: CSP nonce stored as shared instance state** — The per-request CSP nonce was stored as `self._csp_nonce` on the handler, meaning concurrent or sequential HTML requests could leak nonces across responses. Refactored to pass the nonce as a parameter to `_send_raw`, never stored as instance state.
- **L1: Dockerfile runs as root** — Added non-root `owg` user (CIS Docker Benchmark 4.1).

### Fixed

- **Stale `__version__`** — `webview_server.py` hardcoded `__version__ = "0.1.0"`. Now reads version dynamically from package metadata via `importlib.metadata`.
- **Inline imports** — Moved `import re`, `import secrets`, `import copy` from inside methods to module-level in `webview_server.py`.

### Changed

- Test count: 772 → 988 (96% coverage, up from 82%)

## [0.9.0] - 2026-03-01

### Added

- **CLI commands: `restart`, `status`, `doctor`** — new subcommands for managing the MCP server lifecycle:
  - `openwebgoggles restart` — sends SIGUSR1 for seamless in-place restart via `os.execv` (same PID, no client disconnect)
  - `openwebgoggles status` — shows MCP server and webview server status, health endpoint, uptime, session info
  - `openwebgoggles doctor` — diagnoses setup: Python version, dependencies, binary resolution, config files, stale PIDs, lock state
- **SIGUSR1 signal handling** — MCP server registers a SIGUSR1 handler that sets a flag for the event loop to trigger a graceful restart (drains active tool calls, closes webview session, then exec)
- **Auto-reload version monitor** — background task polls package dist-info mtime every 30s; on version change, drains active calls and exec-reloads
- **PID file management** — `.mcp.pid` written on startup for `restart`/`status` to find the running MCP server
- **Code coverage tooling** — `pytest-cov` with `fail_under=80` in pyproject.toml; coverage report shows missing lines
- Test count: 772 → 988 (96% coverage)

## [0.8.1] - 2026-02-27

### Security

- **`_deep_merge` recursion depth limit** — added `MAX_MERGE_DEPTH=20` to prevent stack overflow from deeply nested merge payloads (defense-in-depth alongside SecurityGate's `MAX_NESTING_DEPTH=10`)
- **Pre-write validation for merged state** — `merge_state()` now validates the merged result via a validator callback *before* writing to disk, preventing invalid composite states from being persisted and broadcast
- **Broadened broadcast exception handling** — WebSocket broadcast now catches all exceptions (not just `ConnectionClosed`) to prevent one failing client from blocking delivery to remaining clients
- **Client-side ReDoS length guards** — `validation.js` and `behaviors.js` now skip regex evaluation when pattern length exceeds 500 chars or value length exceeds 10,000 chars (defense-in-depth alongside server-side `_is_redos_safe()`)
- **`Array.isArray` guards in behaviors engine** — behavior rule effects (`show`/`hide`/`enable`/`disable`) are now type-checked before iteration, preventing crashes from malformed state

### Changed

- Test count: 748 → 772

## [0.8.0] - 2026-02-27

### Added

- **`webview_update()` tool** — non-blocking state updates for live progress tracking, streaming logs, and real-time status changes. Supports `merge=True` for incremental updates without replacing the full state
- **`webview_status()` tool** — check whether a webview session is currently active and alive
- **5 new section types** for rich content rendering:
  - `progress` — task progress tracker with status icons and percentage bar (pair with `webview_update` for live updates)
  - `log` — scrolling terminal output with ANSI color support (red, green, yellow, blue, bold, dim)
  - `diff` — unified diff viewer with line numbers, color-coded additions/deletions, and hunk headers
  - `table` — sortable data table with optional row selection via checkboxes
  - `tabs` — client-side tabbed content with nested sections (no server round-trip)
- **Field validation** — `required`, `pattern` (regex), `minLength`, `maxLength`, and custom `errorMessage` for client-side form validation that blocks submission until resolved
- **Conditional behaviors** — show/hide fields and enable/disable buttons based on other field values. Conditions: `equals`, `notEquals`, `in`, `notIn`, `checked`, `unchecked`, `empty`, `notEmpty`, `matches` (regex)
- **Layout system** — multi-panel layouts via `layout` + `panels`. Types: `sidebar` (configurable width), `split` (equal columns). Responsive with mobile breakpoint
- **State presets** — shorthand patterns for common UIs: `progress` (task list), `confirm` (approve/cancel dialog), `log` (terminal output)
- **Action context** — per-item action buttons include `item_index`, `item_id`, `section_index`, `section_id` in the response so agents can identify exactly which item was acted on
- **Deep merge** — `webview_update(state, merge=True)` recursively merges dicts, replaces lists, preserving existing state
- 748 tests (up from 541)

### Changed

- **Modular JS architecture** — `app.js` refactored from monolith into 4 focused modules: `utils.js` (escaping, sanitization), `sections.js` (renderers), `validation.js` (field validation engine), `behaviors.js` (conditional logic). All share the `window.OWG` namespace
- `OWG` namespace frozen via `Object.freeze()` after initialization to prevent prototype pollution
- Form values use `Object.create(null)` to avoid prototype chain interference

### Security

- **H1**: Blocked ALL `url()` in custom CSS (prevents data exfiltration via attribute selectors + external requests)
- **H2**: Merged state re-validated through SecurityGate after `webview_update(merge=True)` — prevents post-merge injection
- **H3**: ReDoS detection for field `pattern` values — rejects nested quantifiers like `(a+)+` that cause catastrophic backtracking
- **H4**: ReDoS detection for behavior `matches` conditions
- **M1**: Thread-safe `merge_state()` with lock around read-merge-write cycle (TOCTOU prevention)
- **M2**: Top-level state key allowlist — rejects unknown keys to prevent LLM-injected payloads
- **M3**: Custom CSS scoped to `#content` — prevents defacing security-critical UI elements (header, session badge, connection indicator)
- **M5**: Client-side CSS filter synced with server (unicode/hex escape detection, `@font-face` blocking)
- **M6**: Log section line type enforcement — each line must be a string (rejects object/number/null injection)
- **M7**: ANSI span balancing — tracks open/close count to prevent unclosed `<span>` tag accumulation
- **M8**: Section nesting depth limit (`MAX_SECTION_DEPTH=3`) prevents deeply nested tabs-within-tabs DoS
- **M9**: `message_className` validated against safe pattern
- **M10**: Field `rows` (1-50 int) and `placeholder` (string, max 500 chars) validation
- **M11**: Close message XSS-scanned before WebSocket broadcast
- **M12**: Session token stripped from WebSocket manifest broadcast (matching HTTP endpoint behavior)
- **L1**: Narrowed SecurityGate import exception handling (`ImportError` + logged fallback)
- **L3**: `Object.freeze(window.OWG)` prevents post-init namespace tampering
- **L4**: URL protocol allowlist in HTML sanitizer (only `https?:`, `mailto:`, `#`, `/`)
- **L5**: Null-prototype objects for form values and field validators
- **L6**: Client-side CSS length validation for `sidebarWidth` with regex + fallback to `300px`

## [0.7.1] - 2026-02-27

### Added

- **Singleton webview server enforcement** — flock-based locking prevents duplicate webview servers from accumulating when the editor spawns multiple MCP processes
- Stale PID detection: on startup, checks `.server.pid` and kills orphaned servers from crashed/restarted MCP sessions
- Shared `_detect_python.sh` helper for consistent Python interpreter detection across all shell scripts

### Fixed

- **MCP -32001 timeout** — `webview()` now sends progress pings every 10s via `ctx.report_progress()` to keep the MCP connection alive during long waits for user input
- Shell scripts no longer hardcode `python3` — all scripts source `_detect_python.sh` and use `$PYTHON` (prefers venv, falls back to system)
- `start_webview.sh`: session credential generation moved after venv setup so it uses the venv Python, not system Python
- README: fixed stale `webview_ask`/`webview_show` references, updated test count to 541
- CHANGELOG: added missing entries for v0.4.2 through v0.7.0

## [0.7.0] - 2026-02-27

### Added

- **MCP keep-alive progress notifications** — `webview()` now sends progress pings every 10 seconds during the blocking wait, preventing MCP client -32001 timeout errors
- Pre-commit change review use case documented in README as the headline workflow pattern
- 541 tests (up from 471), covering all new security hardening

### Fixed

- **H1**: Removed all inline event handlers from example apps (CSP compliance) — full DOM API rewrite of approval-review and security-qa apps
- **H2**: SDK fail-closed — unsigned WS messages are dropped instead of sent in plaintext
- **H3**: Server rejects unsigned WS envelopes when crypto is enabled
- **H4**: HMAC fallback returns empty verify key instead of leaking the symmetric secret as a "public key"
- **H5**: `start_webview.sh` copies all SDK files, not just the primary one
- **H6**: CI workflows use least-privilege permissions (`contents: read`)
- **M1**: SDK enforces state version monotonicity (rejects downgrades)
- **M2**: Nonce tracker aggressive prune at capacity before hard-rejecting all messages
- **M3**: SecurityGate singleton per handler instead of per-request instantiation
- **M4**: App directory name validation blocks path traversal in manifest entries
- **M5**: XSS patterns extended for `srcdoc` and `xlink:href` injection vectors
- **L1**: Template app uses DOM API instead of `innerHTML`
- **L2**: SDK periodic nonce pruning timer on WS connect/disconnect
- **L3**: Close message length limited to 500 characters

### Changed

- README updated: stale `webview_ask`/`webview_show` references replaced with current `webview` API
- `actions/upload-artifact` bumped from 6.0.0 to 7.0.0
- `actions/download-artifact` bumped from 6.0.0 to 8.0.0

## [0.6.0] - 2026-02-26

### Added

- Opt-in markdown rendering via DOMPurify sanitization for message and text section content
- `message_format` and section-level `format` fields — set to `"markdown"` to enable rich rendering

## [0.5.0] - 2026-02-26

### Changed

- **Breaking:** Removed `webview_show` — use `webview` + `webview_read` for non-blocking patterns
- **Breaking:** Renamed `webview_ask` → `webview` — single blocking tool for all interactive UIs
- Added auto-reload: server watches `state.json` for changes and pushes updates to the browser in real time

## [0.4.3] - 2026-02-26

### Fixed

- Stripped action buttons from `webview_show` responses to prevent orphaned interactions that could never be read

## [0.4.2] - 2026-02-26

### Fixed

- 53 code review findings across security, correctness, and cross-platform compatibility

## [0.4.1] - 2026-02-25

### Fixed

- `openwebgoggles init opencode` now defaults to `~/.config/opencode/` (global config) instead of the current directory — MCP server available in all projects without per-project setup
- Handle `opencode.jsonc` files (JSON with Comments) — state machine parser strips `//` and `/* */` comments while preserving URLs like `https://...`
- Standardized installation docs across README, CONTRIBUTING, integration guide, and mcp_server.py docstring/error messages

## [0.4.0] - 2026-02-25

### Added

- Init commands now embed the **absolute path** to the `openwebgoggles` binary in generated configs, so editors don't depend on PATH at runtime
- `_resolve_binary()` — resolves via `shutil.which()`, then `sys.argv[0]`, with bare name as last resort

### Changed

- Recommended install method changed from `pip` to `pipx` (isolates dependencies, keeps binary on PATH)
- README and CONTRIBUTING.md updated to lead with `pipx install openwebgoggles`
- Init output now prints the resolved binary path for transparency

## [0.3.1] - 2026-02-26

### Fixed

- Remove `from __future__ import annotations` that caused `issubclass()` crash on Python 3.12 when `@mcp.tool()` decorator inspected string-ified type annotations

## [0.3.0] - 2026-02-26

### Added

- Dependabot monitoring for pip dependencies and GitHub Actions (weekly)
- Dedicated security workflow (`security.yml`) with pip-audit (SCA) and bandit (SAST)
- pip-audit dependency vulnerability scanning in CI test matrix
- Pre-commit hooks for pip-audit (SCA) and detect-secrets (secret scanning)
- `.secrets.baseline` for detect-secrets false positive tracking

### Changed

- GitHub Actions updated to v6 (checkout, setup-python, upload-artifact, download-artifact)
- Added `# nosec B310` markers to localhost-only urlopen calls for bandit compatibility

## [0.2.0] - 2026-02-26

### Added

- `openwebgoggles init claude` — bootstrap MCP config + permissions for Claude Code
- `openwebgoggles init opencode` — bootstrap MCP config for OpenCode
- Pre-commit hooks with ruff lint + format
- Release flow documentation in CONTRIBUTING.md

### Fixed

- Init commands no longer crash when mcp library has version conflicts (`issubclass()` error)
- Init commands create target directory if it doesn't exist
- Ruff formatting applied across all Python files (fixes CI lint failure)

## [0.1.0] - 2026-02-25

### Added

- MCP server with 4 tools: `webview_ask`, `webview_show`, `webview_read`, `webview_close`
- HTTP + WebSocket server for browser-based HITL UIs
- File-based JSON data contract (state.json, actions.json, manifest.json)
- Client-side JavaScript SDK with WS connection, state caching, HTTP fallback
- Dynamic app renderer — declarative UI from JSON schemas (forms, items, text, actions)
- Shell script helpers: start, stop, write state, read actions, wait for action, scaffold
- 9-layer security architecture:
  - Localhost-only binding
  - Bearer token authentication
  - WebSocket first-message auth
  - Ed25519 message signatures (server → browser)
  - HMAC-SHA256 message signatures (browser → server)
  - Nonce replay prevention
  - Content Security Policy with per-request nonce
  - SecurityGate content validation (22 XSS patterns, zero-width character detection)
  - Rate limiting (30 actions per minute per session)
- 471 tests with OWASP Top 10, MITRE ATT&CK, and OWASP LLM Top 10 traceability markers
- Example apps: approval-review, security-qa
- App scaffold template via init_webview_app.sh
- Benchmark demos exercising full framework capability range
- PyPI package: `pip install openwebgoggles`
