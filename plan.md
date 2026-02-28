# Plan: Restructure for Testability + Coverage to 80%

## Current Coverage (source files only)

| File | Stmts | Missed | Coverage |
|------|-------|--------|----------|
| crypto_utils.py | 95 | 15 | **84.2%** |
| security_gate.py | 493 | 40 | **91.9%** |
| mcp_server.py | 1100 | 694 | **36.9%** |
| webview_server.py | 556 | 268 | **51.8%** |
| **TOTAL** | **2244** | **1017** | **54.7%** |

Target: **80%+ source coverage** (need to cover ~570 more statements).

## Why Coverage Is Low

Both low-coverage files are **monoliths** that mix pure logic with I/O-heavy runtime:

### `mcp_server.py` (2202 lines, 37% covered)
- **WebviewSession** (L184-856): One 670-line class mixing subprocess management, file I/O, port scanning, browser detection, Chrome launching, lock files, PID files, health checks, and data contract operations
- **MCP tools** (L1347-1620): Functions that require a live MCP server context + running WebviewSession
- **Auto-reload** (L875-1084): Version monitor + signal handler tightly coupled to `os.execv()` and global state
- **Init commands** (L1624-1828): Pure file I/O functions that are easily testable but untested
- **CLI commands** (L1831-2118): New restart/status/doctor — pure logic + file reads, untested

### `webview_server.py` (883 lines, 52% covered)
- **WebviewHTTPServer** (L67-870): One massive class handling HTTP routing, static files, API endpoints, WebSocket, file watching, CSP injection, and bootstrap — all tightly coupled to `asyncio.start_server()`
- Tests use a fixture that starts a real server subprocess → slow, fragile, and many code paths unreachable

## Root Cause: Tight Coupling

The testability problem comes from three patterns:

1. **God classes**: `WebviewSession` and `WebviewHTTPServer` do too many things. You can't test "does port scanning work?" without also dealing with subprocess launches, file I/O, and browser detection.

2. **Global mutable state**: `_session`, `_reload_pending`, `_signal_reload_requested`, `_active_tool_calls` are module-level globals. MCP tools mutate them directly. Tests can't isolate behavior.

3. **I/O in constructors/methods**: `ensure_started()` does port scanning, file writes, subprocess launches, and health checks in one call. Each is independently testable but currently inseparable.

## Restructuring Plan

### Phase 1: Extract Pure Logic from `mcp_server.py`

**Goal**: Pull testable logic out of WebviewSession without changing external behavior.

#### 1a. Extract `scripts/cli.py` — CLI subcommands (~250 lines)

Move out of `mcp_server.py`:
- `_find_data_dir()`, `_read_pid_file()`
- `_cmd_restart()`, `_cmd_status()`, `_cmd_doctor()`
- `_print_usage()`, `_init_usage()`
- `_init_claude()`, `_init_opencode()`, `_strip_jsonc_comments()`
- `_resolve_binary()`, `_EDITOR_DEFAULT_DIRS`, `_INIT_DISPATCH`
- The `main()` entry point

**Why testable**: These are all synchronous functions doing file reads, PID checks, and `os.kill()` calls — easy to mock/stub. Zero dependency on MCP or WebviewSession runtime.

**Impact**: ~350 statements moved to a file that's trivially testable. `mcp_server.py` shrinks by ~400 lines.

#### 1b. Extract `scripts/reload.py` — Auto-reload logic (~120 lines)

Move out of `mcp_server.py`:
- `_get_installed_version_info()`, `_read_version_fresh()`
- `_exec_reload()`
- `_version_monitor()` (refactored to accept a callback for "what to do on reload" instead of directly calling `_exec_reload()` and manipulating globals)
- `_signal_reload_monitor()` (same refactor)
- `_sigusr1_handler()`
- `_active_tool_calls`, `_reload_pending` state → encapsulated in a `ReloadManager` class

**Why testable**: Version detection is pure (mock `importlib.metadata`). The monitor loops can be tested by injecting fake version info. `ReloadManager` makes state explicit instead of global.

#### 1c. Extract `scripts/session.py` — WebviewSession refactored (~500 lines)

Keep `WebviewSession` but split its concerns:

- **Port utilities**: `_find_free_ports()`, `_port_available()` → standalone functions (testable without a session)
- **Browser detection**: `_find_chrome()`, `_get_cursor_screen_position()` → standalone functions
- **Process management**: `_cleanup_process()`, `_cleanup_chrome()`, `_atexit_cleanup()` → extract into a `ProcessManager` that takes a `Popen` object
- **Lock management**: `_acquire_lock()`, `_release_lock()`, `_kill_stale_server()` → extract into a `ServerLock` class
- **Data contract**: `write_state()`, `read_state()`, `merge_state()`, `read_actions()`, `clear_actions()`, `wait_for_action()` → stay on `WebviewSession` but with injected data_dir (already partially the case)

**Why testable**: Each extracted piece is a pure function or small class with a clear interface. `_find_chrome()` doesn't need a session — it just scans the filesystem. Lock management can be tested with temp directories.

### Phase 2: Decouple `webview_server.py`

#### 2a. Extract request handling into testable functions

The HTTP handler (`handle_request`) is a 50-line method dispatching to sub-handlers. The sub-handlers (`_handle_api`, `_handle_static`, `_send_index_with_bootstrap`) do the real work but are bound to `self` and need socket writers.

**Refactor**: Make request handling operate on **parsed request objects** and return **response objects**, instead of directly writing to `asyncio.StreamWriter`. This lets tests call handlers without starting a real server.

```python
@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
```

The server layer converts raw stream I/O to/from these objects. Tests construct `Request` directly.

#### 2b. Extract WebSocket handler

`_handle_ws()` (65 lines, 1.5% covered) mixes protocol-level WebSocket framing with application logic (auth, broadcasting, signing). Split into:
- Protocol layer (websocket library handles this)
- Application handler: `handle_ws_message(msg, session_token) -> Response`

#### 2c. Extract file watcher

`_file_watcher()` (35 lines, 3% covered) polls `state.json` for changes and broadcasts. Make it a standalone async generator or callback-based watcher that tests can drive with fake files.

### Phase 3: Write Tests for Extracted Modules

With the restructuring done, writing tests becomes straightforward:

#### `test_cli.py` (~200 lines, targets ~250 new stmts covered)
- `_cmd_restart()`: mock `_read_pid_file` + `os.kill`, test signal sending, error paths, Windows fallback
- `_cmd_status()`: create temp data dirs with manifest/PID files, test output formatting
- `_cmd_doctor()`: create temp dirs with various configs, test all check paths
- `_init_claude()` / `_init_opencode()`: temp dirs, test file creation, merge behavior, idempotency
- `_strip_jsonc_comments()`: pure function, test edge cases
- `_resolve_binary()`: mock `shutil.which`
- `main()`: mock `sys.argv`, test dispatch

#### `test_reload.py` (~100 lines, targets ~100 new stmts covered)
- `ReloadManager.check_version()`: mock `importlib.metadata`, test version comparison
- `_get_installed_version_info()`: mock distribution lookup
- `_read_version_fresh()`: mock cache invalidation
- Signal handler: set flag, verify it's picked up

#### `test_session.py` — expanded (~150 lines, targets ~150 new stmts covered)
- `_find_free_ports()`: test with occupied/free ports
- `_find_chrome()`: mock filesystem, test all platforms
- `ServerLock`: temp dir, test acquire/release/stale cleanup
- `ensure_started()`: mock subprocess.Popen + health check
- `wait_for_action()`: mock actions.json polling with progress callbacks

#### `test_webview_handlers.py` (~200 lines, targets ~200 new stmts covered)
- Request/Response-based handler tests (no real server needed)
- API endpoint tests: actions POST/DELETE, state GET, close POST
- Static file serving: content types, path traversal (these exist but fail without server)
- Bootstrap injection: CSP nonce, script escaping
- WebSocket auth: token validation, signed messages

### Phase 4: Coverage Infrastructure

#### Add pytest-cov to dev dependencies
```toml
[project.optional-dependencies]
dev = [
    "pytest>=9.0,<10",
    "pytest-asyncio>=1.0,<2",
    "pytest-cov>=6.0",
    "ruff>=0.9",
    "pre-commit>=4.0",
]
```

#### Add coverage config to `pyproject.toml`
```toml
[tool.coverage.run]
source = ["scripts"]
omit = ["scripts/tests/*"]

[tool.coverage.report]
show_missing = true
fail_under = 80
exclude_lines = [
    "pragma: no cover",
    "if __name__",
    "if platform.system\\(\\) == .Windows.",
    "except ImportError",
]
```

#### Update CI to report coverage
```yaml
- name: Run tests with coverage
  run: python -m pytest scripts/tests/ --cov=scripts --cov-report=term --cov-report=xml --cov-fail-under=80
```

#### Auto-update release notes
Add a `scripts/coverage_badge.py` or Makefile target that:
1. Runs `pytest --cov --cov-report=json`
2. Extracts source-only coverage percentage
3. Writes it to a known location (e.g., `coverage.txt`)

The release process reads this file when generating CHANGELOG entries.

## Execution Order

| Step | What | Files Changed | Stmts Newly Covered | Risk |
|------|------|--------------|-------------------|------|
| 1 | Extract `cli.py` from mcp_server.py | mcp_server.py, new cli.py, pyproject.toml | 0 (refactor only) | Low — just moving code |
| 2 | Write `test_cli.py` | new test_cli.py | ~250 | Low — pure functions |
| 3 | Extract `reload.py` + `ReloadManager` | mcp_server.py, new reload.py | 0 (refactor only) | Medium — async + signals |
| 4 | Write `test_reload.py` | new test_reload.py | ~100 | Low — mockable |
| 5 | Refactor WebviewSession internals | mcp_server.py / session.py | 0 (refactor only) | Medium — class surgery |
| 6 | Expand `test_session.py` (test_mcp_server.py) | existing test file | ~100 | Low |
| 7 | Add Request/Response layer to webview_server.py | webview_server.py | 0 (refactor only) | Medium — HTTP plumbing |
| 8 | Write `test_webview_handlers.py` | new test file | ~200 | Low — unit tests |
| 9 | Add coverage config + CI | pyproject.toml, ci.yml | 0 | Low |

**Projected result**: ~650 newly covered statements → ~(1017 - 650) = ~367 remaining misses → **~83.6% source coverage**

## What NOT to Restructure

- **security_gate.py** (92%) — already well-tested, leave it alone
- **crypto_utils.py** (84%) — mostly covered, just add a few edge case tests for the 15 missing lines
- **The MCP tool registration** (`@mcp.tool()` decorators) — these are thin wrappers; testing them requires a running MCP context which is better left to integration tests
- **Platform-specific code** (macOS CoreGraphics, Windows paths) — mark with `# pragma: no cover`
