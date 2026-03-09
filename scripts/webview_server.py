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
import logging
import os
import secrets
import signal
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
            generate_session_keys,
            zero_key,
        )
    except ImportError:
        from crypto_utils import (  # noqa: I001
            NonceTracker,
            generate_session_keys,
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

try:
    try:
        from .ws_handler import WebSocketHandler
    except ImportError:
        from ws_handler import WebSocketHandler  # noqa: I001
except ImportError:
    from ws_handler import WebSocketHandler  # noqa: I001,F811

try:
    try:
        from .file_watcher import FileWatcher
    except ImportError:
        from file_watcher import FileWatcher  # noqa: I001
except ImportError:
    from file_watcher import FileWatcher  # noqa: I001,F811


class WebviewServer:
    """Orchestrate HTTP, WebSocket, and file watching for the HITL UI server."""

    # Re-export WS constants so existing tests continue to reference WebviewServer.*
    MAX_WEBSOCKET_CLIENTS = WebSocketHandler.MAX_WEBSOCKET_CLIENTS
    MAX_WS_MESSAGE_SIZE = WebSocketHandler.MAX_WS_MESSAGE_SIZE
    WS_PING_INTERVAL = 30  # seconds between server-initiated WS pings
    WS_PING_TIMEOUT = 10  # seconds to wait for pong before closing

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
        self._running = True
        self._ws_clients: set = set()
        self._ws_server = None

        # Read session token — prefer environment variable (secure), fall back to manifest (legacy)
        self.contract = DataContract(data_dir)
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

        # HTTP handler
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

        # WebSocket handler
        self._ws_handler = WebSocketHandler(
            ws_clients=self._ws_clients,
            session_token=self.session_token,
            security_gate=self._security_gate,
            private_key=self._private_key,
            nonce_tracker=self._nonce_tracker,
            contract=self.contract,
            rate_limiter=self.http_handler._rate_limiter,
            public_key_hex=self._public_key_hex,
        )

        # File watcher (data contract + optional dev-mode source files)
        self._file_watcher = FileWatcher(
            contract=self.contract,
            security_gate=self._security_gate,
            broadcast_fn=self._broadcast,
            dev_mode=dev_mode,
            watch_dirs=[Path(d) for d in (watch_dirs or [])],
        )

    # ---------------------------------------------------------------------------
    # Delegation methods — kept on WebviewServer so existing tests & callers work
    # ---------------------------------------------------------------------------

    async def _handle_ws(self, websocket) -> None:  # pragma: no cover
        """Delegate to WebSocketHandler.handle (kept for backward compat).

        Sync shared mutable references first so tests that replace _ws_clients
        or http_handler._rate_limiter after construction are respected.
        """
        self._ws_handler._ws_clients = self._ws_clients
        self._ws_handler._rate_limiter = self.http_handler._rate_limiter
        await self._ws_handler.handle(websocket)

    async def _send_ws_signed(self, websocket, message: dict) -> None:  # pragma: no cover
        """Delegate to WebSocketHandler.send_signed (kept for backward compat)."""
        await self._ws_handler.send_signed(websocket, message)

    async def _broadcast(self, message: dict, exclude=None) -> None:  # pragma: no cover
        """Delegate to WebSocketHandler.broadcast (kept for backward compat)."""
        await self._ws_handler.broadcast(message, exclude=exclude)

    # ---------------------------------------------------------------------------
    # File watcher delegation (legacy attribute access)
    # ---------------------------------------------------------------------------

    def _init_src_mtimes(self) -> None:
        self._file_watcher.init_src_mtimes()

    def _check_src_changes(self) -> list[Path]:
        return self._file_watcher.check_src_changes()

    # ---------------------------------------------------------------------------
    # Server lifecycle
    # ---------------------------------------------------------------------------

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
                ping_interval=self.WS_PING_INTERVAL,
                ping_timeout=self.WS_PING_TIMEOUT,
            )
            logger.info("WebSocket server listening on ws://127.0.0.1:%d", self.ws_port)
            _running_ref = [True]
            tasks.append(self._file_watcher.watch(_running_ref))
        else:
            logger.warning("WebSocket not available (pip install websockets). Running HTTP-only mode.")
            _running_ref = [True]

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
            _running_ref[0] = False
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
    "WebSocketHandler",
    "FileWatcher",
    "WebviewServer",
    "main",
]
