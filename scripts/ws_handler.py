"""
WebSocket handler for OpenWebGoggles — authentication, message dispatch, and broadcast.

Extracted from webview_server.py (Phase 4.2) to keep WebviewServer focused on
orchestration (HTTP + WS startup, file watching) rather than protocol details.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger("openwebgoggles")

try:
    import websockets.exceptions  # noqa: F401

    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    try:
        from .crypto_utils import (
            NonceTracker,
            generate_nonce,
            sign_message,
            verify_hmac,
        )
    except ImportError:
        from crypto_utils import (  # noqa: I001
            NonceTracker,  # noqa: F401
            generate_nonce,
            sign_message,
            verify_hmac,
        )

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class WebSocketHandler:
    """WebSocket authentication, message dispatch, and broadcast logic.

    Instantiated by WebviewServer; holds no server-lifecycle state.
    WebviewServer._handle_ws, ._send_ws_signed, and ._broadcast all delegate here.
    """

    MAX_WEBSOCKET_CLIENTS = 50  # Prevent connection exhaustion DoS
    MAX_WS_MESSAGE_SIZE = 1_048_576  # 1MB max per WS message (matches SDK limit)

    def __init__(
        self,
        ws_clients: set,
        session_token: str,
        security_gate: Any | None,
        private_key: bytes | None,
        nonce_tracker: Any | None,
        contract: Any,
        rate_limiter: Any,
        public_key_hex: str = "",
    ) -> None:
        self._ws_clients = ws_clients
        self._session_token = session_token
        self._security_gate = security_gate
        self._private_key = private_key
        self._nonce_tracker = nonce_tracker
        self._contract = contract
        self._rate_limiter = rate_limiter
        self._public_key_hex = public_key_hex

    async def send_signed(self, websocket: Any, message: dict) -> None:  # pragma: no cover
        """Send a signed WebSocket message (envelope with nonce + signature).

        Compact separators ensure the payload string (ps) is deterministic so
        the browser can verify the Ed25519 signature without re-serializing raw.p
        (JS JSON key ordering is implementation-defined and may differ from Python).
        """
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

    async def broadcast(self, message: dict, exclude: Any = None) -> None:  # pragma: no cover
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

    async def handle(self, websocket: Any) -> None:  # noqa: C901  # pragma: no cover
        """Handle a WebSocket connection: authenticate, dispatch messages, clean up."""
        import websockets.exceptions

        # Reject if at capacity (defense against connection exhaustion)
        if len(self._ws_clients) >= self.MAX_WEBSOCKET_CLIENTS:
            await websocket.close(1008, "Server at capacity")
            logger.warning("WS: Rejected connection — at capacity (%d clients)", len(self._ws_clients))
            return

        # First-message authentication: client must send {type: "auth", token: "..."}
        authenticated = False

        try:
            first_msg_raw = await __import__("asyncio").wait_for(websocket.recv(), timeout=5)
            first_msg = json.loads(first_msg_raw)
            msg_token = first_msg.get("token", "")
            # Reject oversized tokens to prevent DoS via memory allocation
            if not isinstance(msg_token, str) or len(msg_token) > 1024:
                msg_token = ""
            if first_msg.get("type") == "auth" and msg_token and hmac.compare_digest(msg_token, self._session_token):
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
            state = self._contract.get_state() or {}
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
            await self.send_signed(websocket, msg)

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
                        if not verify_hmac(self._session_token, payload_str, msg["nonce"], msg["sig"]):
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

                try:
                    await self._dispatch(msg, websocket)
                except Exception:
                    logger.exception("WS: Unhandled error in _dispatch — keeping connection open")

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._ws_clients.discard(websocket)
            logger.info("WebSocket client disconnected (%d total)", len(self._ws_clients))

    async def _dispatch(self, msg: dict, websocket: Any) -> None:  # pragma: no cover
        """Dispatch a single (already-unwrapped) WS message."""
        msg_type = msg.get("type")

        if msg_type == "auth":
            # Already handled above, ignore subsequent auth messages
            return

        elif msg_type == "action":
            # Rate limiting for WS actions (shared limiter with HTTP)
            if not self._rate_limiter.check():
                await self.send_signed(websocket, {"type": "error", "data": {"message": "Rate limit exceeded"}})
                return
            action_data = msg.get("data", {})
            # Validate action through security gate (singleton, same validation as HTTP path)
            if self._security_gate:
                valid, err = self._security_gate.validate_action(action_data)
                if not valid:
                    logger.warning("WS action rejected by SecurityGate: %s", err)
                    await self.send_signed(websocket, {"type": "error", "data": {"message": "Invalid action"}})
                    return
            self._contract.append_action(action_data)
            # Notify other clients
            actions = self._contract.get_actions()
            await self.broadcast({"type": "actions_updated", "data": actions}, exclude=websocket)

        elif msg_type == "heartbeat":
            await self.send_signed(
                websocket,
                {
                    "type": "heartbeat_ack",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
            )

        elif msg_type == "request_state":
            state = self._contract.get_state()
            if state:
                await self.send_signed(websocket, {"type": "state_updated", "data": state})

        else:
            logger.warning("WS: Unknown message type %r — ignoring", msg_type)
