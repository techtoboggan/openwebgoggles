#!/usr/bin/env python3
"""
OpenWebGoggles Server — HTTP + WebSocket server for browser-based HITL UIs.

Serves static files from the active webview app directory, provides a REST API
for the JSON data contract, and a WebSocket channel for real-time push updates.

Usage:
    python webview_server.py --data-dir .openwebgoggles --http-port 18420 --ws-port 18421
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import logging
import os
import secrets
import signal
import time
from pathlib import Path

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("openwebgoggles")
except Exception:
    __version__ = "dev"

logger = logging.getLogger("openwebgoggles")

# WebSocket support is optional — graceful degradation if not installed
try:
    import websockets
    import websockets.server

    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

# Cryptographic utilities (Ed25519 signing, HMAC verification, nonce tracking)
try:
    try:
        from .crypto_utils import (
            NonceTracker,
            generate_nonce,
            generate_session_keys,
            sign_message,
            verify_hmac,
            zero_key,
        )
    except ImportError:
        from crypto_utils import (  # noqa: I001
            NonceTracker,
            generate_nonce,
            generate_session_keys,
            sign_message,
            verify_hmac,
            zero_key,
        )

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Security gate for validating agent-generated content
try:
    try:
        from .security_gate import SecurityGate
    except ImportError:
        from security_gate import SecurityGate  # noqa: I001

    HAS_GATE = True
except ImportError:
    HAS_GATE = False

# Sub-module imports
try:
    try:
        from .rate_limiter import RateLimiter
    except ImportError:
        from rate_limiter import RateLimiter  # noqa: I001
except ImportError:
    from rate_limiter import RateLimiter  # noqa: I001,F811

try:
    try:
        from .data_contract import DataContract, _strip_token
    except ImportError:
        from data_contract import DataContract, _strip_token  # noqa: I001
except ImportError:
    from data_contract import DataContract, _strip_token  # noqa: I001,F811

try:
    try:
        from .http_handler import WebviewHTTPHandler
    except ImportError:
        from http_handler import WebviewHTTPHandler  # noqa: I001
except ImportError:
    from http_handler import WebviewHTTPHandler  # noqa: I001,F811


_SRC_EXTENSIONS: frozenset[str] = frozenset({".js", ".css", ".html"})


class WebviewServer:
    """Main server orchestrating HTTP, WebSocket, and file watching."""

    def __init__(
        self,
        data_dir: str,
        http_port: int,
        ws_port: int,
        sdk_path: str,
        apps_dir: str | None = None,
        dev_mode: bool = False,
        watch_dirs: list[str] | None = None,
    ):
        self.data_dir = Path(data_dir)
        self.apps_dir = Path(apps_dir) if apps_dir else self.data_dir / "apps"
        self.http_port = http_port
        self.ws_port = ws_port
        self.sdk_path = Path(sdk_path)
        self._dev_mode: bool = dev_mode
        self._watch_dirs: list[Path] = [Path(d) for d in (watch_dirs or [])]
        self._src_mtimes: dict[Path, float] = {}
        self.contract = DataContract(data_dir)
        self._running = True
        self._ws_clients: set = set()
        self._ws_server = None

        # Read session token — prefer environment variable (secure), fall back to manifest (legacy)
        env_token = os.environ.get("OCV_SESSION_TOKEN", "").strip()
        if env_token:
            # Validate token format: reject control characters, null bytes, and excessive length
            if len(env_token) > 1024 or any(c < " " and c not in "\t" for c in env_token):
                logger.error("OCV_SESSION_TOKEN contains invalid characters or exceeds 1024 bytes — rejected")
                env_token = ""
        if env_token:
            self.session_token = env_token
        else:
            manifest = self.contract.get_manifest()
            self.session_token = manifest.get("session", {}).get("token", "") if manifest else ""
        # Guard against trivial/placeholder tokens that provide no security
        _TRIVIAL_TOKENS = frozenset({"", "REDACTED", "test", "token", "secret"})
        if self.session_token in _TRIVIAL_TOKENS:
            logger.error(
                "Session token is empty or trivial (%r) — generating a random token. "
                "Set OCV_SESSION_TOKEN for persistent sessions.",
                self.session_token[:8] if self.session_token else "(empty)",
            )
            self.session_token = secrets.token_hex(32)

        # Ephemeral cryptographic identity (keys live in memory only, never on disk)
        self._private_key: bytes | None = None
        self._public_key_hex: str = ""
        self._nonce_tracker: NonceTracker | None = None

        if HAS_CRYPTO:
            self._private_key, self._public_key_hex, _ = generate_session_keys()
            self._nonce_tracker = NonceTracker(window_seconds=300)
            if self._public_key_hex:
                logger.info("Crypto: Ed25519 ephemeral keypair generated (pub: %s...)", self._public_key_hex[:16])
            else:
                logger.warning(
                    "Crypto: HMAC-only mode (PyNaCl import failed). "
                    "Server→browser messages use HMAC signatures; browser cannot verify with Ed25519."
                )
        else:
            logger.warning("Crypto: PyNaCl not available. Running without message signing.")

        # Security gate for content validation
        self._security_gate: SecurityGate | None = None
        if HAS_GATE:
            self._security_gate = SecurityGate()
            logger.info("Security gate: Active (XSS scanning, schema validation, payload limits)")
        else:
            logger.warning("Security gate: Not available. Running without content validation.")

        self.http_handler = WebviewHTTPHandler(
            self.contract,
            self.apps_dir,
            self.sdk_path,
            self.session_token,
            http_port=self.http_port,
            ws_port=self.ws_port,
            security_gate=self._security_gate,
        )
        self.http_handler.ws_clients = self._ws_clients
        self.http_handler._public_key_hex = self._public_key_hex
        self.http_handler._broadcast_fn = self._broadcast

    async def start(self):  # pragma: no cover
        # Start HTTP server
        http_server = await asyncio.start_server(
            self.http_handler.handle_request,
            "127.0.0.1",
            self.http_port,
        )
        logger.info("HTTP server listening on http://127.0.0.1:%d", self.http_port)

        tasks = [http_server.serve_forever()]

        # Start WebSocket server if available
        if HAS_WEBSOCKETS:
            self._ws_server = await websockets.serve(
                self._handle_ws,
                "127.0.0.1",
                self.ws_port,
                # Server-initiated keep-alive pings — closes dead connections (ROADMAP 1.4)
                ping_interval=self.WS_PING_INTERVAL,
                ping_timeout=self.WS_PING_TIMEOUT,
            )
            logger.info("WebSocket server listening on ws://127.0.0.1:%d", self.ws_port)
            tasks.append(self._file_watcher())
        else:
            logger.warning("WebSocket not available (pip install websockets). Running HTTP-only mode.")

        # Write PID file with explicit permissions (thread-safe, no process-wide umask)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        pid_path = self.data_dir / ".server.pid"
        fd = os.open(str(pid_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, str(os.getpid()).encode())
        finally:
            os.close(fd)

        logger.info("Server ready. PID: %d", os.getpid())

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            # Broadcast close to all connected clients so windows self-close
            if self._ws_clients:
                try:
                    await self._broadcast(
                        {"type": "close", "data": {"message": "Server shutting down.", "delay_ms": 0}}
                    )
                except Exception:
                    logger.debug("Failed to broadcast shutdown message", exc_info=True)
            # Close WebSocket server
            if self._ws_server:
                self._ws_server.close()
                await self._ws_server.wait_closed()
            # Zero out cryptographic key material
            if HAS_CRYPTO and self._private_key:
                zero_key(self._private_key)
                self._private_key = None
                if self._nonce_tracker:
                    self._nonce_tracker.clear()
                logger.info("Crypto: Ephemeral keys zeroed.")
            pid_path.unlink(missing_ok=True)  # noqa: S110

    async def _send_ws_signed(self, websocket, message: dict):  # pragma: no cover
        """Send a signed WebSocket message (envelope with nonce + signature).

        Compact separators ensure the payload string (ps) is deterministic so
        the browser can verify the Ed25519 signature without re-serializing raw.p
        (JS JSON key ordering is implementation-defined and may differ from Python).
        """
        # Compact separators: deterministic byte string the browser can verify against
        payload_str = json.dumps(message, separators=(",", ":"))
        if HAS_CRYPTO and self._private_key:
            nonce = generate_nonce()
            sig = sign_message(self._private_key, payload_str, nonce)
            # ps (payload string) is included so the SDK can reconstruct the exact
            # signed bytes without re-serializing p (which may differ across engines).
            envelope = json.dumps({"nonce": nonce, "sig": sig, "p": message, "ps": payload_str})
        else:
            envelope = payload_str
        await websocket.send(envelope)

    MAX_WEBSOCKET_CLIENTS = 50  # Prevent connection exhaustion DoS
    MAX_WS_MESSAGE_SIZE = 1_048_576  # 1MB max per WS message (matches SDK limit)
    WS_PING_INTERVAL = 30  # seconds between server-initiated WS pings (ROADMAP 1.4)
    WS_PING_TIMEOUT = 10  # seconds to wait for pong before closing connection

    async def _handle_ws(self, websocket):  # noqa: C901 — TODO: extract message handlers  # pragma: no cover
        # Reject if at capacity (defense against connection exhaustion)
        if len(self._ws_clients) >= self.MAX_WEBSOCKET_CLIENTS:
            await websocket.close(1008, "Server at capacity")
            logger.warning("WS: Rejected connection — at capacity (%d clients)", len(self._ws_clients))
            return

        # First-message authentication: client must send {type: "auth", token: "..."}
        authenticated = False

        try:
            first_msg_raw = await asyncio.wait_for(websocket.recv(), timeout=5)
            first_msg = json.loads(first_msg_raw)
            msg_token = first_msg.get("token", "")
            # Reject oversized tokens to prevent DoS via memory allocation
            if not isinstance(msg_token, str) or len(msg_token) > 1024:
                msg_token = ""
            if first_msg.get("type") == "auth" and msg_token and hmac.compare_digest(msg_token, self.session_token):
                authenticated = True
        except (TimeoutError, json.JSONDecodeError, websockets.exceptions.ConnectionClosed):
            pass

        if not authenticated:
            await websocket.close(4001, "Unauthorized")
            return

        self._ws_clients.add(websocket)
        logger.info("WebSocket client connected (%d total)", len(self._ws_clients))

        try:
            # Send initial state (signed) — only if present and valid
            state = self.contract.get_state() or {}
            if state and self._security_gate:
                ok, _err, _sanitized = self._security_gate.validate_state(json.dumps(state))
                if not ok:
                    logger.warning("WS connected: invalid state from disk, skipping: %s", _err)
                    state = {}
            # Always send the connected message so the SDK transitions out of
            # "connecting" state; include state only when present and valid.
            msg: dict = {"type": "connected"}
            if state:
                msg["state"] = state
            await self._send_ws_signed(websocket, msg)

            async for message in websocket:
                # Server-side message size guard (matches client-side 1MB limit)
                if isinstance(message, str | bytes) and len(message) > self.MAX_WS_MESSAGE_SIZE:
                    logger.warning(
                        "WS: Rejected oversized message (%d bytes, max %d)", len(message), self.MAX_WS_MESSAGE_SIZE
                    )
                    continue
                try:
                    msg = json.loads(message)
                except json.JSONDecodeError:
                    continue

                # Unwrap signed envelope from browser if present
                if "p" in msg and "nonce" in msg and "sig" in msg:
                    # Verify HMAC signature from browser
                    if HAS_CRYPTO and self._nonce_tracker:
                        # Must use compact separators to match JS JSON.stringify output
                        payload_str = json.dumps(msg["p"], separators=(",", ":"))
                        if not verify_hmac(self.session_token, payload_str, msg["nonce"], msg["sig"]):
                            logger.warning("WS: Rejected message with invalid signature")
                            continue
                        if not self._nonce_tracker.check_and_record(msg["nonce"]):
                            logger.warning("WS: Rejected replayed nonce: %s...", msg["nonce"][:16])
                            continue
                    msg = msg["p"]
                elif HAS_CRYPTO and self._nonce_tracker:
                    # Crypto is enabled but message has no signed envelope — reject
                    # This prevents security downgrade by sending unsigned messages
                    msg_type = msg.get("type", "")
                    if msg_type != "auth":
                        logger.warning("WS: Rejected unsigned message (type=%s) — signed envelope required", msg_type)
                        continue

                msg_type = msg.get("type")

                if msg_type == "auth":
                    # Already handled above, ignore subsequent auth messages
                    continue

                elif msg_type == "action":
                    # Rate limiting for WS actions (shared limiter with HTTP)
                    if not self.http_handler._rate_limiter.check():
                        await self._send_ws_signed(
                            websocket, {"type": "error", "data": {"message": "Rate limit exceeded"}}
                        )
                        continue
                    action_data = msg.get("data", {})
                    # Validate action through security gate (singleton, same validation as HTTP path)
                    if self._security_gate:
                        valid, err = self._security_gate.validate_action(action_data)
                        if not valid:
                            logger.warning("WS action rejected by SecurityGate: %s", err)
                            await self._send_ws_signed(
                                websocket, {"type": "error", "data": {"message": "Invalid action"}}
                            )
                            continue
                    self.contract.append_action(action_data)
                    # Notify other clients
                    actions = self.contract.get_actions()
                    await self._broadcast({"type": "actions_updated", "data": actions}, exclude=websocket)

                elif msg_type == "heartbeat":
                    await self._send_ws_signed(
                        websocket,
                        {
                            "type": "heartbeat_ack",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        },
                    )

                elif msg_type == "request_state":
                    state = self.contract.get_state()
                    if state:
                        await self._send_ws_signed(websocket, {"type": "state_updated", "data": state})

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._ws_clients.discard(websocket)
            logger.info("WebSocket client disconnected (%d total)", len(self._ws_clients))

    async def _broadcast(self, message: dict, exclude=None):  # pragma: no cover
        """Broadcast a signed message to all connected WebSocket clients."""
        payload_str = json.dumps(message, separators=(",", ":"))
        if HAS_CRYPTO and self._private_key:
            nonce = generate_nonce()
            sig = sign_message(self._private_key, payload_str, nonce)
            envelope = json.dumps({"nonce": nonce, "sig": sig, "p": message, "ps": payload_str})
        else:
            envelope = payload_str
        for client in list(self._ws_clients):
            if client == exclude:
                continue
            try:
                await client.send(envelope)
            except Exception:
                self._ws_clients.discard(client)

    def _init_src_mtimes(self) -> None:
        """Snapshot current mtimes for all watched source files."""
        for watch_dir in self._watch_dirs:
            try:
                for path in watch_dir.rglob("*"):
                    if path.is_file() and path.suffix in _SRC_EXTENSIONS:
                        self._src_mtimes[path] = path.stat().st_mtime
            except OSError:
                pass

    def _check_src_changes(self) -> list[Path]:
        """Return list of source files whose mtime has changed since last check."""
        changed: list[Path] = []
        for watch_dir in self._watch_dirs:
            try:
                for path in watch_dir.rglob("*"):
                    if not path.is_file() or path.suffix not in _SRC_EXTENSIONS:
                        continue
                    try:
                        mtime = path.stat().st_mtime
                    except OSError:
                        continue
                    prev = self._src_mtimes.get(path)
                    if prev is None:
                        # New file discovered — record but don't trigger reload
                        self._src_mtimes[path] = mtime
                    elif mtime != prev:
                        self._src_mtimes[path] = mtime
                        changed.append(path)
            except OSError:
                pass
        return changed

    async def _file_watcher(self):  # pragma: no cover
        """Poll data contract files for changes and broadcast over WebSocket."""
        # Initialize mtimes
        self.contract.check_changes()
        if self._dev_mode:
            self._init_src_mtimes()
        last_broadcast: dict[str, float] = {}
        debounce_ms = 100  # minimum ms between broadcasts for the same file
        last_reload: float = 0.0
        while self._running:
            await asyncio.sleep(0.5)
            changed = self.contract.check_changes()
            # Debounce: skip files that were broadcast too recently
            now = time.monotonic()
            changed = [c for c in changed if (now - last_broadcast.get(c, 0)) * 1000 >= debounce_ms]
            for name in changed:
                if name == "state":
                    data = self.contract.get_state()
                    if data:
                        # Run through security gate before broadcasting
                        if self._security_gate:
                            valid, err, _ = self._security_gate.validate_state(json.dumps(data))
                            if not valid:
                                logger.error("SECURITY GATE BLOCKED state update: %s", err)
                                await self._broadcast(
                                    {"type": "error", "data": {"message": "State update rejected by security gate"}}
                                )
                                last_broadcast["state"] = now
                                continue
                        await self._broadcast({"type": "state_updated", "data": data})
                        last_broadcast["state"] = time.monotonic()
                elif name == "manifest":
                    data = self.contract.get_manifest()
                    if data:
                        # Strip session token before broadcasting (same as HTTP endpoint)
                        safe_data = _strip_token(data)
                        await self._broadcast({"type": "manifest_updated", "data": safe_data})
                        last_broadcast["manifest"] = time.monotonic()
                elif name == "actions":
                    data = self.contract.get_actions()
                    if data:
                        await self._broadcast({"type": "actions_updated", "data": data})
                        last_broadcast["actions"] = time.monotonic()

            # Dev mode: watch source files and broadcast reload
            if self._dev_mode:
                src_changed = self._check_src_changes()
                if src_changed and (now - last_reload) >= 0.5:
                    logger.info("Dev: source changed (%s) — broadcasting reload", src_changed[0].name)
                    await self._broadcast({"type": "reload"})
                    last_reload = time.monotonic()


def main():  # pragma: no cover
    parser = argparse.ArgumentParser(description="OpenWebGoggles Server")
    parser.add_argument("--data-dir", required=True, help="Path to .openwebgoggles/ directory")
    parser.add_argument("--http-port", type=int, default=18420, help="HTTP server port (default: 18420)")
    parser.add_argument("--ws-port", type=int, default=18421, help="WebSocket server port (default: 18421)")
    parser.add_argument("--sdk-path", required=True, help="Path to openwebgoggles-sdk.js")
    parser.add_argument("--apps-dir", default=None, help="Override apps directory (default: data-dir/apps)")
    parser.add_argument("--app", default=None, help="Auto-create a dev manifest for this app name")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
    parser.add_argument("--log-file", default=None, help="Path to log file (enables rotating file output)")
    parser.add_argument(
        "--log-format", default="text", choices=["text", "json"], help="Log format: text (default) or json"
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        default=False,
        help="Enable dev mode: watch source files and broadcast reload on change",
    )
    parser.add_argument(
        "--watch-dir",
        action="append",
        dest="watch_dirs",
        default=None,
        metavar="DIR",
        help="Additional directory to watch for source changes (can be repeated)",
    )
    args = parser.parse_args()

    from log_config import configure_logging

    configure_logging(
        level=args.log_level,
        log_file=Path(args.log_file) if args.log_file else None,
        log_format=args.log_format,
    )

    # Auto-create a minimal dev manifest so the server serves without a prior MCP session
    if args.app:
        data_dir = Path(args.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = data_dir / "manifest.json"
        if not manifest_path.exists():
            import json as _json

            manifest_path.write_text(
                _json.dumps(
                    {
                        "version": "1.0",
                        "app": {"name": args.app, "entry": f"{args.app}/index.html", "title": args.app},
                        "session": {"id": "dev", "created_at": "dev", "token": "REDACTED"},
                        "server": {"http_port": args.http_port, "ws_port": args.ws_port, "host": "127.0.0.1"},
                    }
                )
            )

    server = WebviewServer(
        data_dir=args.data_dir,
        http_port=args.http_port,
        ws_port=args.ws_port,
        sdk_path=args.sdk_path,
        apps_dir=args.apps_dir,
        dev_mode=args.dev,
        watch_dirs=args.watch_dirs,
    )

    loop = asyncio.new_event_loop()

    def shutdown(sig, frame):
        server._running = False
        for task in asyncio.all_tasks(loop):
            task.cancel()
        logger.info("Shutting down...")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, shutdown)
        except (OSError, ValueError):
            pass  # Windows doesn't support SIGTERM

    try:
        loop.run_until_complete(server.start())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()
        logger.info("Server stopped.")


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Backward-compatibility re-exports
# Everything that tests import from webview_server is still available here.
# ---------------------------------------------------------------------------
__all__ = [
    "RateLimiter",
    "DataContract",
    "_strip_token",
    "WebviewHTTPHandler",
    "WebviewServer",
    "main",
]
