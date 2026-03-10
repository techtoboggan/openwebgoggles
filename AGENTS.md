# AGENTS.md — Development Standards for OpenWebGoggles

Read this before making changes to avoid retreading solved problems.

## Project Layout

```
scripts/              Python source (NOT src/)
  mcp_server.py       MCP server — tools, session management, presets, hot-reload
  webview_server.py   HTTP + WebSocket server (raw asyncio, no framework)
  security_gate.py    SecurityGate — validates all state payloads before browser
  crypto_utils.py     Ed25519 + HMAC signing, NonceTracker
  bundler.py          Runtime HTML bundler for MCP Apps (inlines all JS into single HTML)
  tests/              pytest suite (1899+ tests: unit + 36 BDD + 54 E2E)
    conftest.py       Shared fixtures (gate, session_keys, nonce_tracker, E2E Playwright)
    features/         BDD feature files (Gherkin scenarios)
    steps/            BDD step definitions (pytest-bdd)
assets/
  sdk/                Client JS SDK (openwebgoggles-sdk.js)
  apps/dynamic/       Built-in dynamic renderer
    index.html        Entry point — CSS variables, section styles, CSP nonce injection
    app.js            Orchestrator — transport detection, state rendering, action dispatch, pages
    utils.js          Escaping, sanitization, CSS validation, markdown rendering
    sections.js       Section type renderers (progress, log, diff, table, tabs, metric)
    charts.js         Data-driven SVG chart renderer (bar, line, area, pie, donut, sparkline)
    validation.js     Field validation engine (required, pattern, minLength, maxLength)
    behaviors.js      Conditional show/hide/enable/disable logic
    mcp-transport.js  PostMessage JSON-RPC adapter for MCP Apps (origin pinning)
```

## JavaScript Architecture

### IIFE + OWG Namespace (No Build Step)

All JS uses vanilla IIFE modules sharing `window.OWG`. **Load order matters** in `index.html`: `utils.js` → `sections.js` → `charts.js` → `validation.js` → `behaviors.js` → `mcp-transport.js` → `app.js`. All script tags require the CSP nonce: `<script nonce="{{NONCE}}" src="...">`.

### Key Safety Rules

- **No innerHTML** — use `document.createTextNode()`, `OWG.sanitizeHTML()`, or DOM API
- **Prototype-safe iteration** — `formValues`/`fieldValidators` use `Object.create(null)`; always use `Object.prototype.hasOwnProperty.call(obj, key)` instead of `obj.hasOwnProperty(key)`
- **Namespace frozen** — `Object.freeze(window.OWG)` at end of `app.js` prevents post-init tampering
- **`sanitizeHTML()` strips** — event handler attrs (`on*`), `id`/`name` attrs, and dangerous URLs; preserves `data-*` and `style` (needed by renderer)
- **CSS classes for visibility** — `.owg-page-hidden`, `.owg-tabs-hidden`, `.hidden` (not inline styles)

## MCP Apps — Dual-Mode Architecture

OpenWebGoggles supports two transport modes, selected automatically at runtime:

| Mode | When | Transport | State Flow |
|------|------|-----------|------------|
| **MCP Apps** | Host fetches `ui://openwebgoggles/dynamic` resource | postMessage JSON-RPC via host iframe | `structuredContent` in tool results |
| **Browser fallback** | Host does not fetch UI resource | WebSocket + HTTP to localhost subprocess | `state.json` / `actions.json` on disk |

### Mode Detection

1. Host calls `resources/read("ui://openwebgoggles/dynamic")` → server sets `_host_fetched_ui_resource = True`
2. All subsequent tool calls check `_is_app_mode()` and branch accordingly
3. In app mode: `AppModeState` holds state in memory (no subprocess, no filesystem)
4. In browser mode: `WebviewSession` manages subprocess lifecycle (unchanged)

### MCP Apps Key Components

- **`bundler.py`** — Runtime HTML bundler producing ~168KB self-contained HTML with all JS inlined. Sets `window.__OWG_MCP_APPS__ = true` flag. Cached for process lifetime.
- **`mcp-transport.js`** — PostMessage JSON-RPC adapter implementing same interface as SDK (`connect`, `on`, `sendAction`, `getState`). Uses **origin pinning**: first handshake uses `"*"`, then locks to host's `event.origin` for all subsequent messages. Validates `event.source === window.parent`.
- **`app.js` transport detection** — `isMCPApps = !!(window.__OWG_MCP_APPS__ && window.parent !== window)`. Picks `MCPAppsTransport` or `OpenWebGoggles` SDK accordingly.
- **`_owg_action` tool** — Hidden tool called by iframe to submit user actions. Actions stored in `AppModeState` memory queue, read by agent via `webview_read()`.
- **Tool `meta`** — All 5 tools declare `meta={"ui": {"resourceUri": "ui://openwebgoggles/dynamic"}}` linking them to the UI resource.

### MCP Apps Security Model

App mode delegates transport security to the host. SecurityGate validation still applies to all state and actions. The trust boundary comparison:

| Protection | Browser Mode | App Mode |
|-----------|-------------|----------|
| State validation (SecurityGate) | ✓ | ✓ |
| Ed25519 signatures | ✓ | Host responsibility |
| HMAC action signing | ✓ | Host responsibility |
| Nonce replay protection | ✓ | Host responsibility |
| Origin validation | Localhost-only | Origin pinning (postMessage) |
| Process isolation | Subprocess | Iframe sandbox |

**Key rule**: In app mode, the host is part of the trusted computing base. For untrusted embedding contexts, use browser fallback mode.



### SecurityGate — Rejection, Not Mutation

SecurityGate **rejects** invalid payloads entirely — it never sanitizes or modifies data. This is intentional: mutation-based sanitization is bypass-prone.

### Key Validation Rules

| What | Constraint | Where |
|------|-----------|-------|
| Payload size | 512KB max | `MAX_PAYLOAD_SIZE` |
| String values | 50KB each | `MAX_STRING_LENGTH` |
| JSON nesting | 10 levels | `MAX_NESTING_DEPTH` |
| Tab nesting | 3 levels (sections) | `MAX_SECTION_DEPTH` |
| Sections | 50 max | `MAX_SECTIONS` |
| Custom CSS | 50KB, no `url()`, no `@import`/`@font-face`/`@media`/`@keyframes`/`@supports`/`@layer`, no backslashes, no CSS comments | `DANGEROUS_CSS_PATTERNS` |
| Field patterns | No nested quantifiers (ReDoS) | `_is_redos_safe()` |
| Class names | `^[a-zA-Z][a-zA-Z0-9_ -]*$` | `CLASS_NAME_PATTERN` |
| Top-level keys | Allowlisted only | `ALLOWED_TOP_KEYS` |
| Pages | 20 max, keys match `KEY_PATTERN` | `MAX_PAGES` |
| Charts | 500 labels, 20 datasets, 500 points each | `MAX_CHART_*` |
| WS messages | 1 MB max | `MAX_WS_MESSAGE_SIZE` |

### Thread Safety

`merge_state()` wraps read-merge-write in `threading.Lock()`. Post-merge results must be re-validated through SecurityGate (two valid payloads can merge into an invalid one).

## Security Architecture

### Defense Layers

1. Localhost-only binding (127.0.0.1)
2. Bearer token auth (constant-time comparison) + trivial token guard
3. WebSocket first-message auth + 1 MB message size limit
4. Ed25519 signatures (server → browser) with `\x00` domain separator
5. HMAC-SHA256 (browser → server) with `\x00` domain separator
6. Nonce replay prevention (monotonic clock)
7. CSP via HTTP header with per-request nonce
8. SecurityGate validation (server) + client-side XSS scanner
9. Rate limiting (30 actions/min, monotonic clock)

### CSS Security

**Server-side** (`DANGEROUS_CSS_PATTERNS`) blocks all dangerous CSS constructs:
- `url()` — data exfiltration via attribute selectors
- All `@`-rules — resource loading, scoping bypass, animation hijacking
- ALL backslash escapes — non-hex escapes like `\m` bypass keyword patterns (`@\media` → `@media`)
- CSS comments `/*` — keyword splitting (`ur/**/l()` → `url()`)
- Zero-width/bidi Unicode chars — keyword splitting in XSS patterns

**Client-side** (`DANGEROUS_CSS_RE` in `utils.js`) must stay synced with server patterns. `_scopeCSS()` prepends `#content` to all selectors (prevents defacing security UI).

### Cryptographic Protocol

- Domain separator: `nonce + "\x00" + payload` prevents concatenation ambiguity
- Empty tokens and trivial tokens (`"REDACTED"`, `"test"`, etc.) auto-replaced with `secrets.token_hex(32)`
- NonceTracker uses `time.monotonic()` (immune to wall-clock adjustments)
- Empty/non-string nonces rejected
- Temp files written with `umask(0o077)` (restrictive perms on shared systems)

### Client-Side Hardening

- `sanitizeHTML()` strips event handlers, `id`/`name` attrs, and dangerous URLs; preserves `data-*` and `style`
- `escAnsi()` caps nesting at 20 (`MAX_ANSI_NESTING`) — prevents DoS via crafted ANSI sequences
- `safeCopy()` uses `Object.create(null)` — no prototype chain pollution
- SDK caps listeners at 100/event (`MAX_LISTENERS_PER_EVENT`) with deduplication

## Testing

### Running Tests

```bash
# Unit tests (fast)
python -m pytest scripts/tests/ -m "not slow" -v

# E2E browser tests (requires playwright install chromium)
python -m pytest scripts/tests/test_browser_e2e.py -v -m slow

# BDD tests
python -m pytest scripts/tests/steps/ -v -m bdd
```

### Conventions

- Use `gate` fixture from `conftest.py` — don't instantiate `SecurityGate()` inline
- Tag security tests: `@pytest.mark.owasp_a03`, `@pytest.mark.mitre_t1059`, etc.
- E2E: use `wait_for_function()`/`wait_for_selector()`, never `wait_for_timeout()`
- E2E: use CSS class selectors (`.owg-page-hidden`), not inline style selectors
- Top-level state keys are allowlisted — nest test data under `"data"`
- Two tabs nesting levels exceed `MAX_NESTING_DEPTH=10` by design

### BDD Tests (36 scenarios)

Feature files in `scripts/tests/features/`, step definitions in `scripts/tests/steps/`:
- `hot_reload.feature` (9) — version monitor, mtime, error backoff, path recovery
- `import_fallback.feature` (5) — relative/absolute import resolution
- `mcp_lifecycle.feature` (5) — lifespan startup/cleanup, background tasks
- `stale_server.feature` (5) — tool rejection, host notification
- `mcp_apps.feature` (4) — structured content, browser fallback, action round-trip, close cleanup
- `cli_lifecycle.feature` (4) — SIGUSR1, status, PID files
- `installation.feature` (4) — version detection, METADATA reading

### Structural Testing Gates

Seven automated gate test classes prevent regression categories, not just individual bugs:

| Gate | Class | File | What It Catches |
|------|-------|------|-----------------|
| CSS Bypass Fuzzer | `TestCSSBypassFuzzer` | `test_security_gate.py` | Obfuscated CSS variants (backslash, comment-split, invisible chars) |
| Client-Server Sync | `TestClientServerPatternSync` | `test_security_gate.py` | Pattern count mismatch between `DANGEROUS_CSS_PATTERNS` (Python) and `DANGEROUS_CSS_RE` (JS) |
| Crypto Invariants | `TestCryptoSecurityInvariants` | `test_crypto_utils.py` | Domain separation, token rejection, HMAC round-trip, tamper detection |
| Stale Crypto Lint | `TestStaleCryptoPatternLint` | `test_crypto_utils.py` | Test files with `(var + var).encode("utf-8")` missing `\x00` delimiter |
| Input Channel Registry | `TestInputChannelRegistry` | `test_webview_server.py` | Missing or changed limit constants across all 27 input channels + auto-detect new ones |
| Deployment Security | `TestDeploymentSecurity` | `test_webview_server.py` | Umask patterns, trivial token guard, wall-clock usage in security code |
| Sanitizer Preservation | `TestSanitizerPreservesRendererAttributes` | `test_client_escaping.py` | Ensures `cleanNode` does NOT strip `data-*` or `style` attributes needed by renderers |

When adding new CSS patterns, crypto constructs, or input limits, the corresponding gate test will fail if the change isn't propagated everywhere.

### Hot-Reload Architecture

Version monitor uses two-tier detection: cheap mtime poll (30s) → full METADATA file read (only when mtime changes). Bypasses `importlib.metadata` cache. Exponential backoff on errors (gives up after 10). Async startup via `run_in_executor()` to avoid MCP -32001 timeout.

## Release Process

**Automated flow (preferred):**

1. Bump version in `pyproject.toml` **and** `assets/sdk/package.json` (keep in sync)
2. Update `CHANGELOG.md` — add a `## [X.Y.Z] - YYYY-MM-DD` section
3. Commit and push to main
4. `git tag v0.X.Y && git push origin v0.X.Y`
   - `.github/workflows/release.yml` fires automatically
   - Extracts the `## [X.Y.Z]` section from `CHANGELOG.md` as release notes
   - Creates the GitHub Release
   - `publish.yml` triggers on the new release → PyPI updated
   - `npm-publish.yml` triggers on the new release → npm updated
   - `docker-publish.yml` triggers on the new release → GHCR updated
   - `homebrew-update.yml` triggers on the new release → opens PR on techtoboggan/homebrew-tap

**Manual override** (still works):

4. `git tag v0.X.Y && git push origin v0.X.Y`
5. `gh release create v0.X.Y --title "v0.X.Y" --notes "..."`
   - `release.yml` will attempt to create a release but fail if one already exists — that's fine

**Verify**: `pip index versions openwebgoggles` after the publish workflow completes.

The publish workflow verifies `pyproject.toml` version matches the git tag before building.

## QA Protocol

Follow this protocol exactly when doing code review. A past agent flagged 4 "critical bugs" that were all false positives caused by partial file reads and threading reasoning applied to asyncio code.

### Phase 1 — Automated tools first

Run these before opening any file. Do not manually re-report what these already catch.

```bash
python -m pytest scripts/tests/ -m "not slow" --cov=scripts --cov-fail-under=90
ruff check scripts/ && ruff format --check scripts/
bandit -r scripts/ --exclude scripts/.venv,scripts/tests/ -ll
pip-audit
npx eslint@8 assets/apps/dynamic/ --ext .js assets/sdk/openwebgoggles-sdk.js
```

### Phase 2 — Before reading any code

State the precise question you are answering. "Is the WebSocket client removed from `_ws_clients` when an exception occurs?" is a question. "Review ws_handler.py for bugs" is not. No question = no finding.

### Phase 3 — Full execution path tracing (mandatory)

**3a. Read the entire function.** `finally` blocks appear 60–100 lines after the `return` that triggered the concern. Reading lines 114–165 of a 246-line function is not reading the function.

**3b. Find every `try/finally` before flagging a resource leak.** A `finally` runs on every exit — `return`, `raise`, normal fall-through. If the resource is closed in `finally`, it is closed on all paths, including the bare `return` you just saw.

**3c. Distinguish asyncio from threading before flagging a race.** In asyncio, context switches only happen at `await`. A synchronous function with no `await` runs atomically — no interleaving, no race. Applying mutex/lock reasoning to such code is wrong.

**3d. Check explanatory comments.** This codebase leaves comments at non-obvious decisions (e.g. `# Close stderr pipe to prevent buffer deadlock`). If a comment explains why the pattern is correct, your finding must explain why the comment is wrong.

**3e. Search the test suite.** `grep -rn "keyword" scripts/tests/`. If passing tests cover the behavior, explain why they are insufficient — don't just restate the concern.

### Phase 4 — Verification pass (every finding)

Answer all five before writing up a finding. Missing any = not ready to report.

| # | Question |
|---|----------|
| V1 | What is the exact line and mechanism? ("The writer may not close" is not sufficient.) |
| V2 | What is the complete call path from entry to the buggy exit? |
| V3 | What exact input/condition triggers it? |
| V4 | Does a `finally`, context manager, or documented cleanup path handle this? (State the lines you read.) |
| V5 | What is the concrete observable consequence? (fd exhaustion, deadlock, corrupted state — not "a leak might occur") |

### Phase 5 — Severity

| Severity | Requires |
|----------|----------|
| Critical | RCE, auth bypass, data exfiltration |
| High | DoS, privilege escalation, server crash |
| Medium | Functional breakage under specific conditions |
| Low | Code quality, minor edge cases |
| **False Positive** | **Handled by code the reviewer did not fully read** |

### Required finding format

```
## Finding #N: [title]
Severity: [Critical/High/Medium/Low]
File+lines: scripts/foo.py:114–203 (full function confirmed read)
Trigger: [exact condition]
Path: entry → line X → line Y → [exit]
Cleanup checked: [Yes — finally at lines 180–186 / No — none found after reading full function]
Tests checked: [Yes — no coverage / Yes — tests pass but wrong because ...]
Consequence: [concrete description]
Why existing code does not handle this: [specific explanation]
```

### Anti-patterns

- Reading a partial line range and concluding "no cleanup exists"
- Applying race-condition reasoning to `async def` functions without `await` at the concern point
- Flagging patterns that have an explanatory comment answering the concern
- Re-reporting what ruff/bandit/pytest already catch
- High-confidence language for findings based on <50% of the relevant function

## Common Pitfalls

- **Ruff UP038**: `isinstance(x, int | float)` not `(int, float)` — Python 3.10+ union syntax
- **Ruff S105**: Suppress with `# noqa: S105` (not `# nosec`)
- **Ruff reformats**: May need to re-stage after first pre-commit hook failure
- **Deep merge**: `list + list` → replace (NOT append). Send full updated lists.
- **File data contract**: Three JSON files in `.openwebgoggles/` — `state.json`, `actions.json`, `manifest.json`
- **ANSI rendering**: `escAnsi()` tracks open/close count; `</span>` only emits when `openCount > 0`; reset (`\033[0m`) closes all open spans
- **Presets expand before validation**: `_expand_preset()` output must also be valid
- **JS file references**: When functions move between files, update test path references in `test_client_escaping.py`
- **Context overflow**: Use size-limited sub-agent results, not raw file dumps
