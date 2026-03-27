"""
HTTP request handler for the OpenWebGoggles webview server.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import secrets
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    from .data_contract import DataContract, _strip_token
    from .rate_limiter import RateLimiter
except ImportError:
    from data_contract import DataContract, _strip_token  # noqa: I001
    from rate_limiter import RateLimiter  # noqa: I001

try:
    try:
        from .security_gate import SecurityGate
    except ImportError:
        from security_gate import SecurityGate  # noqa: I001

    HAS_GATE = True
except ImportError:
    HAS_GATE = False

logger = logging.getLogger("openwebgoggles")


class WebviewHTTPHandler:
    MAX_HTTP_CONNECTIONS = 50  # Cap simultaneous HTTP connections (ROADMAP 1.5)
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
        bind_host: str = "127.0.0.1",
    ):
        self.contract = contract
        self.apps_dir = apps_dir
        self.sdk_path = sdk_path
        self.session_token = session_token
        self.http_port = http_port
        self.ws_port = ws_port
        self._security_gate = security_gate
        self.bind_host = bind_host
        # Remote mode: when bound to 0.0.0.0, accept any host header (bearer auth
        # already prevents unauthorized access). When localhost, restrict to
        # localhost variants only (DNS rebinding protection).
        self._remote = bind_host == "0.0.0.0"  # noqa: S104
        self.start_time = time.monotonic()
        self.ws_clients: set = set()
        self._public_key_hex: str = ""
        self._rate_limiter = RateLimiter(max_actions=30, window_seconds=60.0)
        self._manifest_rate_limiter = RateLimiter(max_actions=60, window_seconds=60.0)
        self._http_active_connections: int = 0
        # Injected by WebviewServer to send signed broadcasts; falls back to
        # unsigned plain-JSON if not set (e.g. in tests or standalone usage).
        self._broadcast_fn: Any | None = None

    async def _broadcast(self, message: dict, exclude=None):  # pragma: no cover
        if self._broadcast_fn is not None:
            await self._broadcast_fn(message, exclude=exclude)
            return
        # Fallback: unsigned broadcast (only when server hasn't injected its signed version)
        payload = json.dumps(message)
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

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):  # noqa: C901 — linear request parsing, not truly complex  # pragma: no cover
        # Connection limit: reject when at capacity (ROADMAP 1.5)
        if self._http_active_connections >= self.MAX_HTTP_CONNECTIONS:
            writer.write(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        self._http_active_connections += 1
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

            # Reject Transfer-Encoding to prevent HTTP request smuggling
            if "transfer-encoding" in headers:
                await self._send_response(writer, 400, {"error": "Transfer-Encoding not supported"})
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

        except TimeoutError:
            logger.warning("Request timed out for %s", locals().get("path", "(unknown)"))
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            self._http_active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: S110
                pass

    # Allowlisted Host header values — prevents DNS rebinding attacks.
    # Only localhost variants are accepted since the server binds to 127.0.0.1.
    _ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

    def _is_valid_host(self, host_header: str) -> bool:
        """Check if Host header is a localhost variant (with optional port).

        In remote mode (bind_host=0.0.0.0), any host header is accepted since
        the server is intentionally network-accessible and bearer auth is the
        access gate. DNS rebinding is not a concern when the server expects
        arbitrary origins.
        """
        if not host_header:
            return False
        if self._remote:
            return True  # Bearer auth is the access gate in remote mode
        # Strip port suffix (e.g. "localhost:18420" -> "localhost")
        host = host_header.rsplit(":", 1)[0] if ":" in host_header else host_header
        # Handle IPv6 with brackets (e.g. "[::1]:18420")
        if host.startswith("[") and "]" in host:
            host = host[: host.index("]") + 1]
        return host.lower() in self._ALLOWED_HOSTS

    async def _route(self, method: str, path: str, query: dict, headers: dict, body: bytes, writer):
        # Host header validation — prevents DNS rebinding attacks.
        # Missing Host is allowed for HTTP/1.0 clients but non-localhost is rejected.
        host = headers.get("host", "")
        if host and not self._is_valid_host(host):
            await self._send_response(writer, 403, {"error": "Forbidden: invalid Host header"})
            return

        # Health check — no auth required
        if path == "/_health":
            await self._send_response(
                writer,
                200,
                {
                    "status": "ok",
                    "uptime": int(time.monotonic() - self.start_time),
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
            if not self._manifest_rate_limiter.check():
                await self._send_response(writer, 429, {"error": "Rate limit exceeded"})
                return
            data = self.contract.get_manifest()
            if data:
                safe_data = _strip_token(data)
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

    async def _handle_api(self, method: str, path: str, query: dict, body: bytes, writer):  # noqa: C901 — TODO: extract route handlers
        if path == "/_api/state":
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
                # No state yet (server just started or cleared) — return empty loading state
                # rather than 404 so the SDK doesn't interpret it as a connection error.
                await self._send_response(writer, 200, {"version": 0, "status": "initializing"})

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
                        logger.warning("Action rejected by SecurityGate: %s", err)
                        await self._send_response(writer, 400, {"error": "Invalid action"})
                        return
                actions = self.contract.append_action(action)
                await self._send_response(writer, 200, actions)

            elif method == "DELETE":
                count = self.contract.clear_actions()
                await self._send_response(writer, 200, {"cleared": count})

            else:
                await self._send_response(writer, 405, {"error": "Method not allowed"})

        elif path == "/_api/patch":
            # Broadcast a state_patch delta to all WebSocket clients.
            # The MCP server uses this to deliver incremental updates (append mode)
            # without waiting for the file-watcher poll cycle.
            if method != "POST":
                await self._send_response(writer, 405, {"error": "Method not allowed"})
                return
            try:
                patch_msg = json.loads(body)
            except json.JSONDecodeError:
                await self._send_response(writer, 400, {"error": "Invalid JSON"})
                return
            # Validate patch structure
            if not isinstance(patch_msg, dict) or patch_msg.get("type") != "state_patch":
                await self._send_response(writer, 400, {"error": "Invalid patch message"})
                return
            ops = patch_msg.get("ops", [])
            if not isinstance(ops, list):
                await self._send_response(writer, 400, {"error": "ops must be a list"})
                return
            # Validate each op through security gate (check values for XSS/injection)
            if self._security_gate:
                for op in ops:
                    val = op.get("value")
                    if val is not None:
                        # Use validate_state for complex values, skip primitives
                        if isinstance(val, dict):
                            valid, err, _ = self._security_gate.validate_state(
                                json.dumps({"title": "x", "data": val}, separators=(",", ":"))
                            )
                            if not valid:
                                await self._send_response(writer, 400, {"error": f"Patch value rejected: {err}"})
                                return
                        elif isinstance(val, str):
                            xss = self._security_gate._scan_xss(val, f"patch.{op.get('path', '?')}")
                            if xss:
                                await self._send_response(writer, 400, {"error": "Patch value contains XSS"})
                                return
                        elif isinstance(val, list):
                            for item in val:
                                if isinstance(item, str):
                                    xss = self._security_gate._scan_xss(item, f"patch.{op.get('path', '?')}")
                                    if xss:
                                        await self._send_response(writer, 400, {"error": "Patch value contains XSS"})
                                        return
            await self._broadcast(patch_msg)
            await self._send_response(writer, 200, {"ok": True, "ops": len(ops)})

        elif path == "/_api/agent-status":
            # Returns whether the agent is currently in wait_for_action.
            # was_active=True means the agent wrote a liveness file at some point
            # this session (it was watching but stopped). was_active=False means
            # the liveness file never existed — agent never connected or already
            # completed cleanly. The browser uses was_active to decide whether to
            # show the "Remind Agent" button (only meaningful when was_active=True).
            if method != "GET":
                await self._send_response(writer, 405, {"error": "Method not allowed"})
                return
            liveness_path = self.contract.data_dir / "_agent_waiting"
            try:
                if liveness_path.exists():
                    age = time.time() - float(liveness_path.read_text())
                    if age < 10.0:
                        await self._send_response(
                            writer, 200, {"waiting": True, "was_active": True, "age": round(age, 1)}
                        )
                        return
                    # File exists but stale — agent was watching and has since stopped
                    await self._send_response(writer, 200, {"waiting": False, "was_active": True})
                    return
            except (OSError, ValueError):
                pass
            # No liveness file — agent never connected or exited cleanly
            await self._send_response(writer, 200, {"waiting": False, "was_active": False})

        elif path == "/_api/close":
            # Broadcast close message to all connected WebSocket clients, then optionally stop
            try:
                opts = json.loads(body) if body else {}
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON in close request body: %s", e)
                opts = {}
            try:
                delay_ms = max(0, min(int(opts.get("delay_ms", 1500)), 10000))
            except (ValueError, TypeError):
                delay_ms = 1500
            message = str(opts.get("message", "Session complete."))[:500]  # Limit close message length
            # XSS-scan close message before broadcasting to browser
            if self._security_gate:
                xss = self._security_gate._scan_xss(message, "close.message")
                if xss:
                    message = "Session complete."  # Fallback to safe default
            else:
                # Defense-in-depth: strip basic HTML when SecurityGate unavailable
                import html as _html

                message = _html.escape(message)
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
        if not app_dir_name or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", app_dir_name):
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
        # SDK fallback: when apps_dir != data_dir/apps (e.g. dev mode pointing to assets/apps),
        # SDK files won't be co-located with the app. Check sdk_path.parent as a third location.
        sdk_fallback = self.sdk_path.parent / clean_path
        apps_dir_resolved = self.apps_dir.resolve()
        sdk_dir_resolved = self.sdk_path.parent.resolve()

        # Security: validate path containment BEFORE any filesystem access.
        # Checking file existence first could leak timing information about whether
        # a traversal target (e.g. ../../etc/passwd) exists outside the apps dir.
        for candidate in (primary, fallback):
            try:
                candidate.resolve().relative_to(apps_dir_resolved)
            except ValueError:
                await self._send_response(writer, 403, {"error": "Forbidden"})
                return
        try:
            sdk_fallback.resolve().relative_to(sdk_dir_resolved)
        except ValueError:
            sdk_fallback = None  # traversal attempt — ignore this candidate

        # Confirmed-safe paths — now check existence
        file_path = primary if primary.is_file() else fallback
        if not file_path.is_file() and sdk_fallback and sdk_fallback.is_file():
            file_path = sdk_fallback
        if not file_path.is_file():
            await self._send_response(writer, 404, {"error": "File not found"})
            return

        await self._send_file(writer, file_path)

    async def _send_index_with_bootstrap(self, writer, index: Path, manifest: dict):
        """Serve index.html with manifest + initial state injected as window.__OCV__ bootstrap.

        SECURITY NOTE: The session token is intentionally embedded in the HTML bootstrap
        ``<script>`` tag. This is the sole delivery path for the token to the browser client.
        This is acceptable because:
        1. The server binds to localhost only — no cross-origin access is possible.
        2. The token is per-session and short-lived (destroyed on session close).
        3. CSP with per-request nonces prevents injection of rogue scripts.
        4. The token is never included in API responses or written to manifest.json on disk.
        """
        html = index.read_text(encoding="utf-8")
        state = self.contract.get_state() or {}

        # Validate bootstrap state through SecurityGate (defense-in-depth against disk tampering)
        if self._security_gate and state:
            ok, _err, _parsed = self._security_gate.validate_state(json.dumps(state))
            if not ok:
                logger.warning("Bootstrap state failed SecurityGate validation: %s", _err)
                state = {}  # Fall back to empty state

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

        # Generate per-request CSP nonce (passed as parameter, never stored as instance state)
        csp_nonce = secrets.token_hex(16)

        injection = f'<script nonce="{csp_nonce}">window.__OCV__ = {bootstrap};</script>\n'

        # Add nonce to existing script tags in the HTML (skip tags that already have a nonce)
        html = re.sub(r"<script(?![^>]*\bnonce=)", f'<script nonce="{csp_nonce}"', html)

        # Inject just before </head> — fallback chain:
        # 1. Before </head> (ideal — script loads before body)
        # 2. Before <body (if no </head> tag — e.g. minimal HTML)
        # 3. Prepend to file (last resort — e.g. HTML fragment with no structure)
        # Note: case-sensitive match is acceptable since we control the app HTML templates.
        if "</head>" in html:
            html = html.replace("</head>", injection + "</head>", 1)
        elif "<body" in html:
            html = html.replace("<body", injection + "<body", 1)
        else:
            html = injection + html
        body = html.encode("utf-8")
        await self._send_raw(writer, 200, body, "text/html", csp_nonce=csp_nonce)

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

    async def _send_raw(
        self,
        writer,
        status: int,
        body: bytes,
        content_type: str,
        *,
        csp_nonce: str | None = None,
        request_origin: str = "",
    ):
        reason = HTTPStatus(status).phrase
        # In remote mode, echo the request origin (standard CORS for authenticated APIs).
        # In localhost mode, use the known localhost origin.
        if self._remote and request_origin:
            origin = request_origin
        else:
            origin = f"http://127.0.0.1:{self.http_port}"
        headers = [
            f"HTTP/1.1 {status} {reason}",
        ]
        # RFC 7231: 204 No Content MUST NOT include a message body or Content-Type
        if status != 204:
            headers.append(f"Content-Type: {content_type}")
            headers.append(f"Content-Length: {len(body)}")
        headers.extend(
            [
                "Connection: close",
                f"Access-Control-Allow-Origin: {origin}",
                "Access-Control-Allow-Headers: Authorization, Content-Type",
                "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS",
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: DENY",
                "Referrer-Policy: no-referrer",
                "Permissions-Policy: camera=(), microphone=(), geolocation=()",
            ]
        )
        # Add CSP for HTML responses (nonce must be passed explicitly per-request)
        if content_type == "text/html" and csp_nonce:
            # In remote mode, use wildcard connect-src since the hostname can vary
            if self._remote:
                ws_connect = "ws: wss:"
            else:
                ws_connect = f"ws://127.0.0.1:{self.ws_port}"
            csp = (
                f"default-src 'none'; "
                f"script-src 'nonce-{csp_nonce}'; "
                f"style-src 'unsafe-inline' 'self'; "
                f"connect-src 'self' {ws_connect}; "
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
