# AGENTS.md — Development Standards for OpenWebGoggles

Read this before making changes to avoid retreading solved problems.

## Project Layout

```
scripts/              Python source (NOT src/)
  mcp_server.py       MCP server — tools, session management, presets, hot-reload
  webview_server.py   HTTP + WebSocket server (raw asyncio, no framework)
  security_gate.py    SecurityGate — validates all state payloads before browser
  crypto_utils.py     Ed25519 + HMAC signing, NonceTracker
  tests/              pytest suite (1700+ tests: 1665 unit + 32 BDD + 55 E2E)
    conftest.py       Shared fixtures (gate, session_keys, nonce_tracker, E2E Playwright)
    features/         BDD feature files (Gherkin scenarios)
    steps/            BDD step definitions (pytest-bdd)
assets/
  sdk/                Client JS SDK (openwebgoggles-sdk.js)
  apps/dynamic/       Built-in dynamic renderer
    index.html        Entry point — CSS variables, section styles, CSP nonce injection
    app.js            Orchestrator — WebSocket, state rendering, action dispatch, pages
    utils.js          Escaping, sanitization, CSS validation, markdown rendering
    sections.js       Section type renderers (progress, log, diff, table, tabs, metric)
    charts.js         Data-driven SVG chart renderer (bar, line, area, pie, donut, sparkline)
    validation.js     Field validation engine (required, pattern, minLength, maxLength)
    behaviors.js      Conditional show/hide/enable/disable logic
```

## JavaScript Architecture

### IIFE + OWG Namespace (No Build Step)

All JS uses vanilla IIFE modules sharing `window.OWG`. **Load order matters** in `index.html`: `utils.js` → `sections.js` → `charts.js` → `validation.js` → `behaviors.js` → `app.js`. All script tags require the CSP nonce: `<script nonce="{{NONCE}}" src="...">`.

### Key Safety Rules

- **No innerHTML** — use `document.createTextNode()`, `OWG.sanitizeHTML()`, or DOM API
- **Prototype-safe iteration** — `formValues`/`fieldValidators` use `Object.create(null)`; always use `Object.prototype.hasOwnProperty.call(obj, key)` instead of `obj.hasOwnProperty(key)`
- **Namespace frozen** — `Object.freeze(window.OWG)` at end of `app.js` prevents post-init tampering
- **`sanitizeHTML()` strips** — inline `style` attrs (use CSS classes instead) and all `data-*` attrs (prevents phantom action injection)
- **CSS classes for visibility** — `.owg-page-hidden`, `.owg-tabs-hidden`, `.hidden` (not inline styles)

## Python Architecture

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

- `sanitizeHTML()` strips `data-*` attrs and inline `style` attrs
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

### BDD Tests (32 scenarios)

Feature files in `scripts/tests/features/`, step definitions in `scripts/tests/steps/`:
- `hot_reload.feature` (9) — version monitor, mtime, error backoff, path recovery
- `import_fallback.feature` (5) — relative/absolute import resolution
- `mcp_lifecycle.feature` (5) — lifespan startup/cleanup, background tasks
- `stale_server.feature` (5) — tool rejection, host notification
- `cli_lifecycle.feature` (4) — SIGUSR1, status, PID files
- `installation.feature` (4) — version detection, METADATA reading

### Hot-Reload Architecture

Version monitor uses two-tier detection: cheap mtime poll (30s) → full METADATA file read (only when mtime changes). Bypasses `importlib.metadata` cache. Exponential backoff on errors (gives up after 10). Async startup via `run_in_executor()` to avoid MCP -32001 timeout.

## Release Process

1. Bump version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit and push
4. `git tag v0.X.Y && git push --tags`
5. `gh release create v0.X.Y --title "..." --notes "..."` ← triggers PyPI publish

The publish workflow verifies `pyproject.toml` version matches the git tag.

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
