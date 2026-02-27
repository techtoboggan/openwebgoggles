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
import signal
import time
import uuid
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, urlparse

__version__ = "0.1.0"

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
    from crypto_utils import (
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
    from security_gate import SecurityGate

    HAS_GATE = True
except ImportError:
    HAS_GATE = False


class RateLimiter:
    """Simple sliding-window rate limiter for action submissions."""

    def __init__(self, max_actions: int = 30, window_seconds: float = 60.0):
        self.max_actions = max_actions
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def check(self) -> bool:
        """Return True if the action is allowed, False if rate-limited."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_actions:
            return False
        self._timestamps.append(now)
        return True


class DataContract:
    """Manages the file-based JSON data contract in .openwebgoggles/."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.manifest_path = self.data_dir / "manifest.json"
        self.state_path = self.data_dir / "state.json"
        self.actions_path = self.data_dir / "actions.json"

        # Track modification times for change detection
        self._mtimes: dict[str, float] = {}

    def read_json(self, path: Path) -> dict | None:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def write_json(self, path: Path, data: dict) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(path)

    def get_manifest(self) -> dict | None:
        return self.read_json(self.manifest_path)

    def get_state(self) -> dict | None:
        return self.read_json(self.state_path)

    def get_actions(self) -> dict | None:
        return self.read_json(self.actions_path)

    def append_action(self, action: dict) -> dict:
        actions = self.get_actions() or {"version": 0, "actions": []}
        action["id"] = str(uuid.uuid4())
        action["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        actions["actions"].append(action)
        actions["version"] = actions.get("version", 0) + 1
        self.write_json(self.actions_path, actions)
        return actions

    def clear_actions(self) -> int:
        actions = self.get_actions()
        count = len(actions["actions"]) if actions and "actions" in actions else 0
        self.write_json(self.actions_path, {"version": 0, "actions": []})
        return count

    def check_changes(self) -> list[str]:
        """Check for file modifications since last check. Returns list of changed file names."""
        changed = []
        for name, path in [
            ("state", self.state_path),
            ("actions", self.actions_path),
            ("manifest", self.manifest_path),
        ]:
            try:
                mtime = path.stat().st_mtime
            except FileNotFoundError:
                continue
            if name in self._mtimes and self._mtimes[name] != mtime:
                changed.append(name)
            self._mtimes[name] = mtime
        return changed


class WebviewHTTPHandler:
    """Async HTTP request handler for the webview server."""

    MAX_BODY_SIZE = 1_048_576  # 1MB

    def __init__(
        self,
        contract: DataContract,
        apps_dir: Path,
        sdk_path: Path,
        session_token: str,
        http_port: int = 18420,
        ws_port: int = 18421,
        security_gate: SecurityGate | None = None,
    ):
        self.contract = contract
        self.apps_dir = apps_dir
        self.sdk_path = sdk_path
        self.session_token = session_token
        self.http_port = http_port
        self.ws_port = ws_port
        self._security_gate = security_gate
        self.start_time = time.time()
        self.ws_clients: set = set()
        self._csp_nonce: str | None = None  # set per-HTML-response
        self._public_key_hex: str = ""
        self._rate_limiter = RateLimiter(max_actions=30, window_seconds=60.0)
        self._security_gate: SecurityGate | None = SecurityGate() if HAS_GATE else None

    async def _broadcast(self, message: dict, exclude=None):
        import json as _json

        payload = _json.dumps(message)
        for client in list(self.ws_clients):
            if client == exclude:
                continue
            try:
                await client.send(payload)
            except Exception:
                self.ws_clients.discard(client)

    def _check_token(self, headers: dict) -> bool:
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            # Constant-time comparison prevents timing-based token enumeration
            return hmac.compare_digest(auth[7:], self.session_token)
        return False

    def _content_type(self, path: str) -> str:
        ext = Path(path).suffix.lower()
        types = {
            ".html": "text/html",
            ".js": "application/javascript",
            ".css": "text/css",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
        }
        return types.get(ext, "application/octet-stream")

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                writer.close()
                return

            request_text = request_line.decode("utf-8", errors="replace").strip()
            parts = request_text.split(" ")
            if len(parts) < 2:
                writer.close()
                return

            method = parts[0]
            raw_path = parts[1]
            parsed = urlparse(raw_path)
            path = parsed.path
            query = parse_qs(parsed.query)

            # Read headers (cap at 100 to prevent memory exhaustion)
            headers = {}
            for _ in range(100):
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    key, val = line_str.split(":", 1)
                    headers[key.strip().lower()] = val.strip()
            else:
                # More than 100 headers — reject
                await self._send_response(writer, 431, {"error": "Too many headers"})
                return

            # Read body for POST/PUT/DELETE
            body = b""
            if method in ("POST", "PUT", "DELETE"):
                try:
                    content_length = int(headers.get("content-length", "0"))
                except (ValueError, TypeError):
                    await self._send_response(writer, 400, {"error": "Invalid Content-Length"})
                    return
                if content_length < 0:
                    await self._send_response(writer, 400, {"error": "Invalid Content-Length"})
                    return
                if content_length > self.MAX_BODY_SIZE:
                    await self._send_response(writer, 413, {"error": "Payload too large"})
                    return
                if content_length > 0:
                    body = await asyncio.wait_for(reader.readexactly(content_length), timeout=30)

            # CORS preflight
            if method == "OPTIONS":
                await self._send_cors_preflight(writer)
                return

            # Route the request
            await self._route(method, path, query, headers, body, writer)

        except (TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _route(self, method: str, path: str, query: dict, headers: dict, body: bytes, writer):
        # Health check — no auth required
        if path == "/_health":
            await self._send_response(
                writer,
                200,
                {
                    "status": "ok",
                    "uptime": int(time.time() - self.start_time),
                    "ws_clients": len(self.ws_clients),
                },
            )
            return

        # SDK — no auth required (served as static asset, token is fetched from manifest)
        if path == "/sdk/openwebgoggles-sdk.js":
            await self._send_file(writer, self.sdk_path)
            return

        # Manifest — no auth required (SDK needs it to bootstrap, but token is STRIPPED)
        if path == "/_api/manifest":
            data = self.contract.get_manifest()
            if data:
                safe_data = json.loads(json.dumps(data))  # deep copy
                if "session" in safe_data and "token" in safe_data["session"]:
                    del safe_data["session"]["token"]
                await self._send_response(writer, 200, safe_data)
            else:
                await self._send_response(writer, 404, {"error": "manifest.json not found"})
            return

        # API endpoints — require auth
        if path.startswith("/_api/"):
            if not self._check_token(headers):
                await self._send_response(writer, 401, {"error": "Unauthorized"})
                return
            await self._handle_api(method, path, query, body, writer)
            return

        # Static files — no auth (the app itself, loaded in browser)
        await self._handle_static(path, writer)

    async def _handle_api(self, method: str, path: str, query: dict, body: bytes, writer):
        if path == "/_api/manifest":
            data = self.contract.get_manifest()
            if data:
                await self._send_response(writer, 200, data)
            else:
                await self._send_response(writer, 404, {"error": "manifest.json not found"})

        elif path == "/_api/state":
            data = self.contract.get_state()
            if data:
                since_raw = query.get("since_version", [None])[0]
                if since_raw is not None:
                    try:
                        since_version = int(since_raw)
                    except (ValueError, TypeError):
                        await self._send_response(writer, 400, {"error": "Invalid since_version"})
                        return
                    if data.get("version", 0) <= since_version:
                        await self._send_raw(writer, 304, b"", "text/plain")
                        return
                await self._send_response(writer, 200, data)
            else:
                await self._send_response(writer, 404, {"error": "state.json not found"})

        elif path == "/_api/actions":
            if method == "GET":
                data = self.contract.get_actions()
                await self._send_response(writer, 200, data or {"version": 0, "actions": []})

            elif method == "POST":
                # Rate limiting
                if not self._rate_limiter.check():
                    await self._send_response(writer, 429, {"error": "Rate limit exceeded (max 30 actions/min)"})
                    return
                try:
                    action = json.loads(body)
                except json.JSONDecodeError:
                    await self._send_response(writer, 400, {"error": "Invalid JSON"})
                    return
                # Validate action through security gate (singleton)
                if self._security_gate:
                    valid, err = self._security_gate.validate_action(action)
                    if not valid:
                        await self._send_response(writer, 400, {"error": f"Action rejected: {err}"})
                        return
                actions = self.contract.append_action(action)
                await self._send_response(writer, 200, actions)

            elif method == "DELETE":
                count = self.contract.clear_actions()
                await self._send_response(writer, 200, {"cleared": count})

            else:
                await self._send_response(writer, 405, {"error": "Method not allowed"})

        elif path == "/_api/close":
            # Broadcast close message to all connected WebSocket clients, then optionally stop
            try:
                opts = json.loads(body) if body else {}
            except json.JSONDecodeError:
                opts = {}
            delay_ms = max(0, min(int(opts.get("delay_ms", 1500)), 10000))
            message = str(opts.get("message", "Session complete."))[:500]  # Limit close message length
            # XSS-scan close message before broadcasting to browser
            if self._security_gate:
                xss = self._security_gate._scan_xss(message, "close.message")
                if xss:
                    message = "Session complete."  # Fallback to safe default
            await self._broadcast({"type": "close", "data": {"message": message, "delay_ms": delay_ms}})
            await self._send_response(writer, 200, {"ok": True, "clients_notified": len(self.ws_clients)})

        else:
            await self._send_response(writer, 404, {"error": "Not found"})

    async def _handle_static(self, path: str, writer):
        # Resolve the manifest to find the active app
        manifest = self.contract.get_manifest()
        if not manifest:
            await self._send_response(writer, 503, {"error": "No manifest.json — server not initialized"})
            return

        app_entry = manifest.get("app", {}).get("entry", "")
        app_dir_name = app_entry.split("/")[0] if "/" in app_entry else app_entry

        # Defense-in-depth: validate app directory name to prevent injection
        import re as _re

        if not app_dir_name or not _re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", app_dir_name):
            await self._send_response(writer, 400, {"error": "Invalid app entry in manifest"})
            return

        if path == "/" or path == "":
            # Serve the app's index.html with bootstrap data injected
            index = self.apps_dir / app_dir_name / "index.html"
            if index.is_file():
                await self._send_index_with_bootstrap(writer, index, manifest)
            else:
                await self._send_response(writer, 404, {"error": "App entry not found"})
            return

        # Serve files relative to the app directory
        clean_path = path.lstrip("/")
        primary = self.apps_dir / app_dir_name / clean_path
        fallback = self.apps_dir / clean_path
        apps_dir_resolved = self.apps_dir.resolve()

        # Security: validate path containment BEFORE any filesystem access.
        # Checking file existence first could leak timing information about whether
        # a traversal target (e.g. ../../etc/passwd) exists outside the apps dir.
        for candidate in (primary, fallback):
            try:
                candidate.resolve().relative_to(apps_dir_resolved)
            except ValueError:
                await self._send_response(writer, 403, {"error": "Forbidden"})
                return

        # Both paths are confirmed within apps_dir — now check existence
        file_path = primary if primary.is_file() else fallback
        if not file_path.is_file():
            await self._send_response(writer, 404, {"error": "File not found"})
            return

        await self._send_file(writer, file_path)

    async def _send_index_with_bootstrap(self, writer, index: Path, manifest: dict):
        """Serve index.html with manifest + initial state injected as window.__OCV__ bootstrap."""
        import secrets as _secrets

        html = index.read_text(encoding="utf-8")
        state = self.contract.get_state() or {}

        # Inject real token into bootstrap manifest (sole delivery path — never in API response or on disk)
        safe_manifest = json.loads(json.dumps(manifest))
        if "session" in safe_manifest:
            safe_manifest["session"]["token"] = self.session_token

        bootstrap_data = {
            "manifest": safe_manifest,
            "state": state,
        }
        # Include public key for signature verification in the browser
        if self._public_key_hex:
            bootstrap_data["publicKey"] = self._public_key_hex
        bootstrap = json.dumps(bootstrap_data, ensure_ascii=True)
        # Comprehensive escaping for embedding in <script> context
        bootstrap = bootstrap.replace("</", "<\\/")
        bootstrap = bootstrap.replace("<!--", "<\\!--")
        bootstrap = bootstrap.replace("<!", "<\\!")

        # Generate per-request CSP nonce
        csp_nonce = _secrets.token_hex(16)
        self._csp_nonce = csp_nonce

        injection = f'<script nonce="{csp_nonce}">window.__OCV__ = {bootstrap};</script>\n'

        # Add nonce to existing script tags in the HTML (skip tags that already have a nonce)
        import re as _re

        html = _re.sub(r"<script(?![^>]*\bnonce=)", f'<script nonce="{csp_nonce}"', html)

        # Inject just before </head> — falls back to injecting at top of <body> or start of file
        if "</head>" in html:
            html = html.replace("</head>", injection + "</head>", 1)
        elif "<body" in html:
            html = html.replace("<body", injection + "<body", 1)
        else:
            html = injection + html
        body = html.encode("utf-8")
        await self._send_raw(writer, 200, body, "text/html")

    async def _send_response(self, writer, status: int, data: dict):
        body = json.dumps(data).encode()
        await self._send_raw(writer, status, body, "application/json")

    async def _send_file(self, writer, file_path: Path):
        if not file_path.is_file():
            await self._send_response(writer, 404, {"error": "Not found"})
            return
        body = file_path.read_bytes()
        content_type = self._content_type(str(file_path))
        await self._send_raw(writer, 200, body, content_type)

    async def _send_raw(self, writer, status: int, body: bytes, content_type: str):
        reason = HTTPStatus(status).phrase
        origin = f"http://127.0.0.1:{self.http_port}"
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
            f"Access-Control-Allow-Origin: {origin}",
            "Access-Control-Allow-Headers: Authorization, Content-Type",
            "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "Referrer-Policy: no-referrer",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ]
        # Add CSP for HTML responses
        if content_type == "text/html" and self._csp_nonce:
            csp = (
                f"default-src 'none'; "
                f"script-src 'nonce-{self._csp_nonce}'; "
                f"style-src 'unsafe-inline' 'self'; "
                f"connect-src 'self' ws://127.0.0.1:{self.ws_port}; "
                f"img-src 'self'; "
                f"font-src 'self'; "
                f"frame-ancestors 'none'; "
                f"base-uri 'none'; "
                f"form-action 'none'"
            )
            headers.append(f"Content-Security-Policy: {csp}")
        response = "\r\n".join(headers) + "\r\n\r\n"
        writer.write(response.encode() + body)
        await writer.drain()

    async def _send_cors_preflight(self, writer):
        await self._send_raw(writer, 204, b"", "text/plain")


class WebviewServer:
    """Main server orchestrating HTTP, WebSocket, and file watching."""

    def __init__(self, data_dir: str, http_port: int, ws_port: int, sdk_path: str):
        self.data_dir = Path(data_dir)
        self.apps_dir = self.data_dir / "apps"
        self.http_port = http_port
        self.ws_port = ws_port
        self.sdk_path = Path(sdk_path)
        self.contract = DataContract(data_dir)
        self._running = True
        self._ws_clients: set = set()
        self._ws_server = None

        # Read session token — prefer environment variable (secure), fall back to manifest (legacy)
        env_token = os.environ.get("OCV_SESSION_TOKEN", "")
        if env_token:
            self.session_token = env_token
        else:
            manifest = self.contract.get_manifest()
            self.session_token = manifest.get("session", {}).get("token", "") if manifest else ""

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

    async def start(self):
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
            )
            logger.info("WebSocket server listening on ws://127.0.0.1:%d", self.ws_port)
            tasks.append(self._file_watcher())
        else:
            logger.warning("WebSocket not available (pip install websockets). Running HTTP-only mode.")

        # Write PID file
        pid_path = self.data_dir / ".server.pid"
        pid_path.write_text(str(os.getpid()))

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
            pid_path.unlink(missing_ok=True)

    async def _send_ws_signed(self, websocket, message: dict):
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

    async def _handle_ws(self, websocket):
        # First-message authentication: client must send {type: "auth", token: "..."}
        authenticated = False

        try:
            first_msg_raw = await asyncio.wait_for(websocket.recv(), timeout=5)
            first_msg = json.loads(first_msg_raw)
            msg_token = first_msg.get("token", "")
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
            # Send initial state (signed)
            state = self.contract.get_state()
            if state:
                await self._send_ws_signed(websocket, {"type": "connected", "state": state})

            async for message in websocket:
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
                            await self._send_ws_signed(
                                websocket, {"type": "error", "data": {"message": f"Action rejected: {err}"}}
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

    async def _broadcast(self, message: dict, exclude=None):
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
            except websockets.exceptions.ConnectionClosed:
                self._ws_clients.discard(client)

    async def _file_watcher(self):
        """Poll data contract files for changes and broadcast over WebSocket."""
        # Initialize mtimes
        self.contract.check_changes()
        last_broadcast: dict[str, float] = {}
        debounce_ms = 100  # minimum ms between broadcasts for the same file
        while self._running:
            await asyncio.sleep(0.5)
            changed = self.contract.check_changes()
            # Debounce: skip files that were broadcast too recently
            now = time.time()
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
                                await self._broadcast({"type": "error", "data": {"message": f"State rejected: {err}"}})
                                continue
                        await self._broadcast({"type": "state_updated", "data": data})
                        last_broadcast["state"] = time.time()
                elif name == "manifest":
                    data = self.contract.get_manifest()
                    if data:
                        # Strip session token before broadcasting (same as HTTP endpoint)
                        import copy as _copy

                        safe_data = _copy.deepcopy(data)
                        if "session" in safe_data and "token" in safe_data["session"]:
                            safe_data["session"]["token"] = "REDACTED"  # noqa: S105 — redacting, not setting a password
                        await self._broadcast({"type": "manifest_updated", "data": safe_data})
                        last_broadcast["manifest"] = time.time()
                elif name == "actions":
                    data = self.contract.get_actions()
                    if data:
                        await self._broadcast({"type": "actions_updated", "data": data})
                        last_broadcast["actions"] = time.time()


def main():
    parser = argparse.ArgumentParser(description="OpenWebGoggles Server")
    parser.add_argument("--data-dir", required=True, help="Path to .openwebgoggles/ directory")
    parser.add_argument("--http-port", type=int, default=18420, help="HTTP server port (default: 18420)")
    parser.add_argument("--ws-port", type=int, default=18421, help="WebSocket server port (default: 18421)")
    parser.add_argument("--sdk-path", required=True, help="Path to openwebgoggles-sdk.js")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    server = WebviewServer(
        data_dir=args.data_dir,
        http_port=args.http_port,
        ws_port=args.ws_port,
        sdk_path=args.sdk_path,
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
