# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
