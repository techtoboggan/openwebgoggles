# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
