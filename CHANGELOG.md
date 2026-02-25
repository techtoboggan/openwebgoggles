# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-24

### Added

- HTTP + WebSocket server for browser-based HITL UIs
- File-based JSON data contract (state.json, actions.json, manifest.json)
- Client-side JavaScript SDK with WS connection, state caching, HTTP fallback
- Dynamic app renderer — declarative UI from JSON schemas (forms, items, text, actions)
- Shell script helpers: start, stop, write state, read actions, wait for action, scaffold
- 8-layer security architecture:
  - Localhost-only binding
  - Bearer token authentication
  - WebSocket first-message auth
  - Ed25519 message signatures (server→browser)
  - HMAC-SHA256 message signatures (browser→server)
  - Nonce replay prevention
  - Content Security Policy with per-request nonce
  - SecurityGate content validation (16 XSS patterns)
- Comprehensive test suite (378 tests) with OWASP/MITRE ATT&CK traceability markers
- Example apps: approval-review, security-qa
- App scaffold template via init_webview_app.sh
- Benchmark demos exercising full framework capability range
