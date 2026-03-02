# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.3] - 2026-03-02

### Added

- **32 BDD test scenarios (pytest-bdd)** — Gherkin feature files covering hot-reload lifecycle, import fallback, MCP lifespan, stale server behavior, CLI lifecycle, and installation version detection. Step definitions in `scripts/tests/steps/`.
- **5 new E2E browser tests** — Long text overflow wrapping, whitespace preservation in plain text, markdown code block rendering, item row overflow, all verified with headless Chromium.
- **Host notification on staleness** — `_notify_host_stale()` proactively sends a `send_log_message(level="error")` to the MCP host when the server detects a version change, instead of silently waiting for the next tool call.
- **Task done-callbacks** — All background asyncio tasks now attach `_task_done_callback()` which logs unhandled exceptions so crashes don't vanish silently.

### Fixed

- **Hot-reload not detecting upgrades** — `importlib.invalidate_caches()` doesn't flush `importlib.metadata` distribution caches in pipx/venv installs. Rewrote `_read_version_fresh()` to read the `METADATA` file directly from disk, bypassing importlib entirely.
- **dist-info path permanently lost after upgrade** — When the package was temporarily missing during upgrade, setting `dist_info_path = None` lost the reference forever. Now the path is preserved and re-discovered via `_get_installed_version_info()` when it reappears.
- **mtime=None recovery stuck** — After a "version unknown" state set `last_mtime = None`, the next successful stat didn't force a version recheck because `last_mtime is not None` was false. Changed to `last_mtime is None or current_mtime != last_mtime` so recovery always triggers a version read.
- **MCP -32001 timeout on startup** — `_version_monitor()` called `_get_installed_version_info()` synchronously during lifespan startup. Deferred to `loop.run_in_executor()` so the MCP `initialize` response returns immediately.
- **Version monitor infinite error loop** — If `stat()` failed every iteration, the monitor logged an exception every 30s forever. Added consecutive error counter with exponential backoff; gives up after 10 consecutive errors.
- **SIGUSR1 handler not in lifespan** — Signal was registered only in `main()`. Now also registered in `lifespan()` for test and restart scenarios.
- **Long text overflowing containers** — Text without spaces (URLs, base64, long paths) overflowed `.message-box`, `.item-content`, and table cells. Added `overflow-wrap: break-word; word-break: break-word` to all text containers.
- **Plain text whitespace not preserved** — Plain text sections (no `format: "markdown"`) now use `white-space: pre-wrap` via `.message-box-plain` class, preserving newlines and indentation for code-like content.

### Changed

- Test count: 1627 → 1664 (1577 unit + 32 BDD + 55 E2E, 0 failures, 16 skipped)
- CI workflow: Added `pytest-bdd` to test job dependencies.
- Updated AGENTS.md: BDD testing section, hot-reload architecture docs, text overflow protection docs.

## [0.12.2] - 2026-03-02

### Fixed

- **MCP SDK version floor raised to >=1.8.1** — The previous `mcp>=1.0.0` constraint allowed installing MCP SDK versions that lack `FastMCP` (pre-1.2.0) or have known `JSONRPCMessage` import breakage (1.4.0, 1.8.0). Raised to `>=1.8.1` to guarantee a working MCP SDK on all systems.
- **Import errors on pipx/isolated installs** — `from security_gate import SecurityGate` and `from crypto_utils import ...` used bare absolute imports that only work when `scripts/` is directly on `sys.path`. On pipx or isolated venv installs, these fail with `ModuleNotFoundError`. Switched to relative imports (`from .security_gate`, `from .crypto_utils`) which resolve correctly in all installation contexts.

## [0.12.1] - 2026-03-02

### Added

- **`showNav` top-level boolean** — Hide the auto-generated page tab bar (`showNav: false`) when navigation is handled entirely through `navigateTo` buttons, items, and tables.
- **Per-page `hidden` boolean** — Exclude individual pages from the nav bar while keeping them reachable via `navigateTo`. Enables master-detail drill-down patterns.
- **Chart `columns/rows` data format** — Charts now accept the same `columns`/`rows` tabular format used by table sections as an alternative to `data.labels/datasets`. The first column becomes labels; remaining columns become datasets.
- **50 Playwright E2E browser tests** — Comprehensive end-to-end tests using headless Chromium validate all 10+ section types, SPA navigation, form submission round-trips, client-side validation, conditional behaviors, layouts, and chart rendering against a real browser. Marked `@pytest.mark.slow` with dedicated CI job.
- **`pytest-timeout` dev dependency** — Added to pyproject.toml for CI E2E test timeout enforcement.

### Fixed

- **SPA page visibility stripped by sanitizer** — `sanitizeHTML()` strips all inline `style` attributes from non-SVG elements (security hardening), which silently removed `style="display:none"` from inactive SPA pages, making all pages visible simultaneously. Replaced with class-based visibility (`.owg-page-hidden`) that survives sanitization.
- **Tab panel visibility stripped by sanitizer** — Same bug class as above. Inactive tab panels used `style="display:none"` which was stripped. Replaced with `.owg-tabs-hidden` CSS class.
- **`validateAllRequired()` crash on `Object.create(null)`** — `fieldValidators.hasOwnProperty(key)` threw `TypeError` because `Object.create(null)` objects have no prototype chain. Fixed with `Object.prototype.hasOwnProperty.call()`.
- **`renderLegend` crash on empty datasets** — Charts using `columns/rows` format (which produces empty `datasets` at parse time) would crash with `TypeError: Cannot read properties of undefined (reading 'label')`. Added guard for empty arrays.
- **Silent page switching** — `navigateToPage()` no longer emits `_page_switch` actions. Page navigation is now purely client-side with no agent round-trip. The server-side `wait_for_action` also filters internal `_`-prefixed actions as defense-in-depth.

### Changed

- Test count: 1569 → 1627 (1577 unit + 50 E2E, 0 failures, 16 skipped)
- E2E tests use deterministic waits (`wait_for_function`, `wait_for_selector`) instead of hardcoded timeouts for CI reliability.
- Updated AGENTS.md: E2E testing section, inline style warning, `Object.create(null)` prototype safety docs.
- Updated reference documentation: data-contract.md (major expansion with all section types), integration-guide.md (new metric/SPA/table examples), sdk-api.md (client-side navigation section), README (metric/chart section types, SPA navigation subsection).

## [0.12.0] - 2026-03-01

### Added

- **Metric cards section** (`type: "metric"`) — KPI widgets with label, value, unit, change indicator (up/down/neutral), optional inline sparkline, and responsive grid layout (1-6 columns).
- **Chart section** (`type: "chart"`) — Data-driven SVG charts rendered client-side from validated numeric arrays. Supports bar, line, area, pie, donut, and sparkline chart types. Colors via hex codes or named theme aliases (blue, green, red, yellow, purple, orange, cyan, pink). Options for legend, grid lines, stacked bars, and custom dimensions.
- **Clickable table rows** — Extended `table` section with `clickable: true` and optional `clickActionId`. Row clicks emit an action with row data and context (section_index, row_index). Coexists with `selectable` checkboxes.
- **SPA-style pages / navigation** — New top-level `pages` dict and `activePage` key. Renders an auto-generated navigation bar with instant client-side page switching. Each page has its own sections and actions.
- **New file: `charts.js`** — Vanilla JS IIFE module for safe SVG chart generation. All SVG built from data (no raw SVG injection). Text through `esc()`, attributes through `escAttr()`, colors pre-validated by SecurityGate.
- **`OWG.emitAction()`** — Exposed action dispatch function for sub-modules (used by clickable table rows and page navigation).
- **360+ new tests** — End-to-end MCP integration tests, SecurityGate validation, client-side escaping, SVG safety, and security audit regression tests.
- Test count: 1025 → 1529 (0 failures, 16 skipped, 95.97% coverage)

### Security

- **SG-1: `math.isfinite()` on float fields** — Progress percentage, metric card values, sparkline points, chart data values, and field min/max now reject `NaN` and `Infinity`.
- **SG-2: COLOR_PATTERN strict hex lengths** — Color validation now only accepts 3, 6, or 8 hex digit colors. Previously accepted invalid lengths like 4, 5, or 7 digits.
- **SG-3: String length limits** — Metric card labels, chart data labels, dataset labels, and page labels are now capped at 500 characters.
- **SG-4: KEY_PATTERN leading alpha** — Form field keys must now start with a letter (not a digit), preventing CSS selector edge cases.
- **SG-5: Chart label length validation** — Per-label length check added for chart data labels (500 char max).
- **TR-1: WebSocket auth token length** — Token length capped at 1024 bytes to prevent memory allocation DoS.
- **TR-2: Prototype pollution in `_deep_merge()`** — Keys `__proto__`, `constructor`, and `prototype` are now rejected with a `ValueError`.
- **TR-3: Rate limiting on manifest endpoint** — Unauthenticated `/_api/manifest` endpoint now rate-limited to 60 requests per minute.
- **TR-4: Nonce tracker thread safety** — `NonceTracker.check_and_record()` now uses `threading.Lock` to prevent TOCTOU races.
- **CS-0: `sanitizeHTML()` no longer strips buttons/inputs** — The v0.11.0 security hardening inadvertently added `button`, `input`, `select`, `textarea` to `DANGEROUS_TAGS`, breaking all UI interactivity. Removed form elements from the blocklist.
- **SVG sanitization strategy** — Replaced blanket SVG stripping with context-aware sanitization: `DANGEROUS_SVG_TAGS` strips `script`, `foreignObject`, `use`, `set`, `animate*`, and `handler`/`listener` inside SVG; `SAFE_SVG_TAGS` allowlists structural SVG elements (`svg`, `g`, `rect`, `circle`, `line`, `polyline`, `polygon`, `path`, `text`, etc.).

## [0.11.0] - 2026-03-01

### Security

- **PY-F1: Undefined `_exec_reload()` in signal handler** — SIGUSR1 handler called `_exec_reload()` which no longer existed after refactor, causing a NameError on restart signal. Replaced with `_mark_stale("current", "reload-requested")`.
- **PY-F4: XSS scanning missing from `validate_action()`** — Actions received from WebSocket clients were validated for schema compliance but not scanned for XSS payloads. Added `_scan_xss()` call to `validate_action()` for defense-in-depth.
- **PY-F3: PID reuse attack on stale server kill** — Stale PID file cleanup would `os.kill(pid, 0)` without verifying the process identity, risking killing an unrelated process after PID wraparound. Added `ps` command identity check before termination.
- **PY-F5: Internal error leakage in MCP tool responses** — Three MCP tool error handlers included exception details (`{e}`) in user-facing error messages, potentially leaking internal paths and stack info. Replaced with generic messages; details logged server-side only.
- **PY-F8: Bootstrap state bypassed SecurityGate** — Initial state loaded from `state.json` during `_initial_bootstrap()` was served to the browser without SecurityGate validation. Added validation gate with fallback to empty state on failure.
- **PY-F2: `delay_ms` crash on non-numeric input** — `int(opts.get("delay_ms", ...))` would raise `ValueError` on non-numeric strings. Wrapped in try/except with safe default.
- **JS-F1: CSS selector injection in `validation.js`** — Four `querySelector()` calls concatenated unescaped field keys directly into CSS selector strings. Added `CSS.escape()` via `_safeQuery()` helper.
- **JS-F2: Unescaped data attributes in `sections.js`** — `_item_index` and `_section_index` were inserted into `data-*` attributes without escaping. Applied `escAttr()`.
- **JS-F10: Prototype pollution via `Object.assign`** — Item action context objects used `Object.assign({}, a, ...)` which copies `__proto__` keys. Replaced with `Object.create(null)` and filtered property copy.
- **JS-F17: Protocol-relative URL bypass** — `SAFE_URL_PROTOCOL_RE` matched `//evil.com` as a valid URL starting with `/`. Fixed regex from `/^(https?:|mailto:|#|\/)/i` to `/^(https?:|mailto:|#|\/[^\/])/i`.
- **JS-F4+F5: Form elements and DOM clobbering in sanitizer** — `DANGEROUS_TAGS` did not include `input`, `button`, `select`, `textarea` (form injection). `cleanNode()` did not strip `id` or `name` attributes (DOM clobbering). Both fixed.
- **JS-F13: Single quote unescaped in `esc()`** — `esc()` encoded `& < > "` but not `'`, allowing attribute injection in single-quoted HTML contexts. Added `&#39;` encoding.

### Changed

- **Renamed `security-qa` example to `item-triage`** — The custom app example is now a generic item triage interface (dependency updates, config reviews, PR triage) instead of a security-specific findings reviewer.
- **Expanded README examples** — Added four new JSON examples covering dependency update review (table + form), live build dashboard (progress + log), configuration wizard (tabs + behaviors + validation), and sidebar layout (items + diff + multi-panel).
- Test count: 988 → 1025 (0 failures, 16 skipped)

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

## [0.8.2] - 2026-02-28

### Fixed

- **Auto-reload no longer breaks MCP connection** — `os.execv()` self-restart was incompatible with MCP's stateful stdio protocol (the new process sent a fresh handshake mid-session, breaking the client connection). Replaced with graceful stale-version detection: the server marks itself as stale and returns a clear "please restart" error in subsequent tool calls instead of crashing the connection

### Changed

- Test count: 772 → 773

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

- **H1**: Removed all inline event handlers from example apps (CSP compliance) — full DOM API rewrite of approval-review and item-triage apps
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
- Example apps: approval-review, item-triage
- App scaffold template via init_webview_app.sh
- Benchmark demos exercising full framework capability range
- PyPI package: `pip install openwebgoggles`
