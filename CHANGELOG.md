# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
