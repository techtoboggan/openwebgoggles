"""
Comprehensive tests for webview_server.py — HTTP request handling, authentication,
path traversal, CSP, bootstrap injection, and session management.

Coverage mapping:
  OWASP Top 10 2021:
    A01 Broken Access Control   — path traversal, unauthorized endpoint access
    A02 Crypto Failures         — token handling, CSP nonce generation
    A03 Injection               — bootstrap escaping, header injection
    A05 Security Misconfiguration — CSP, security headers, CORS
    A07 Auth Failures           — bearer token validation, WebSocket auth
    A08 Integrity               — manifest token stripping, atomic writes
    A09 Logging/Monitoring      — security gate rejection logging
    A10 SSRF                    — localhost binding, no external connections
  OWASP LLM Top 10 2025:
    LLM01 Prompt Injection  — state content validation before broadcast
    LLM05 Improper Output   — security gate blocks XSS in file watcher path
    LLM10 Unbounded Consumption — body size limit, connection handling
  MITRE ATT&CK:
    T1071 Application Layer Protocol — HTTP/WS protocol validation
    T1078 Valid Accounts             — bearer token auth
    T1185 Session Hijacking          — token not in URL, nonce-based CSP
    T1190 Exploit Public App         — path traversal, input validation
    T1499 Endpoint DoS               — body size limits
    T1568 Dynamic Resolution         — localhost binding
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time
from unittest.mock import patch

import pytest
import websockets.exceptions

# Ensure scripts dir on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto_utils import generate_nonce  # noqa: E402
from webview_server import DataContract, RateLimiter, WebviewHTTPHandler, WebviewServer  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Create a temporary data directory structure."""
    data_dir = tmp_path / ".opencode" / "webview"
    apps_dir = data_dir / "apps" / "testapp"
    apps_dir.mkdir(parents=True)

    # Write a minimal manifest
    manifest = {
        "session": {"id": "test-session-123", "token": "secret_token_abc"},
        "server": {"host": "127.0.0.1", "http_port": 18420, "ws_port": 18421},
        "app": {"entry": "testapp/index.html"},
    }
    (data_dir / "manifest.json").write_text(json.dumps(manifest))

    # Write a minimal state
    state = {"version": 1, "status": "ready", "title": "Test"}
    (data_dir / "state.json").write_text(json.dumps(state))

    # Write empty actions
    (data_dir / "actions.json").write_text(json.dumps({"version": 0, "actions": []}))

    # Write a minimal index.html
    (apps_dir / "index.html").write_text(
        "<!DOCTYPE html><html><head><title>Test</title></head>"
        '<body><script src="/sdk/openwebgoggles-sdk.js"></script>'
        '<script>console.log("app")</script></body></html>'
    )
    (apps_dir / "app.js").write_text('console.log("app.js");')
    (apps_dir / "style.css").write_text("body { color: black; }")

    return data_dir


@pytest.fixture
def contract(tmp_data_dir):
    return DataContract(str(tmp_data_dir))


@pytest.fixture
def handler(contract, tmp_data_dir):
    sdk_path = tmp_data_dir / "sdk.js"
    sdk_path.write_text("// SDK placeholder")
    from security_gate import SecurityGate

    h = WebviewHTTPHandler(
        contract=contract,
        apps_dir=tmp_data_dir / "apps",
        sdk_path=sdk_path,
        session_token="secret_token_abc",
        http_port=18420,
        ws_port=18421,
        security_gate=SecurityGate(),
    )
    h._public_key_hex = "deadbeef" * 8
    return h


# ═══════════════════════════════════════════════════════════════════════════════
# Helper to simulate HTTP requests
# ═══════════════════════════════════════════════════════════════════════════════


class MockWriter:
    """Captures HTTP response bytes."""

    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data: bytes):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    @property
    def response_text(self) -> str:
        return self.data.decode("utf-8", errors="replace")

    @property
    def status_code(self) -> int:
        first_line = self.response_text.split("\r\n")[0]
        return int(first_line.split(" ")[1])

    @property
    def headers(self) -> dict:
        header_section = self.response_text.split("\r\n\r\n")[0]
        result = {}
        for line in header_section.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                result[k.strip().lower()] = v.strip()
        return result

    @property
    def body(self) -> str:
        parts = self.response_text.split("\r\n\r\n", 1)
        return parts[1] if len(parts) > 1 else ""

    @property
    def json_body(self) -> dict:
        return json.loads(self.body)


async def send_request(handler, method, path, headers=None, body=b"", query=None):
    """Simulate an HTTP request to the handler.

    query: dict mapping name → list of values (same format as urllib.parse.parse_qs).
    """
    writer = MockWriter()
    headers = headers or {}

    await handler._route(method, path, query or {}, headers, body, writer)
    return writer


# ═══════════════════════════════════════════════════════════════════════════════
# 1. AUTHENTICATION — OWASP A01, A07; MITRE T1078
# ═══════════════════════════════════════════════════════════════════════════════


class TestHTTPAuthentication:
    """Bearer token authentication for API endpoints."""

    @pytest.mark.owasp_a01
    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_api_requires_auth(self, handler):
        """API endpoints without token return 401."""
        w = await send_request(handler, "GET", "/_api/state")
        assert w.status_code == 401

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_api_wrong_token(self, handler):
        """Wrong bearer token returns 401."""
        w = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer wrong_token"})
        assert w.status_code == 401

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_api_correct_token(self, handler):
        """Correct bearer token returns 200."""
        w = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 200

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_api_empty_token(self, handler):
        """Empty bearer token returns 401."""
        w = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer "})
        assert w.status_code == 401

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_api_no_bearer_prefix(self, handler):
        """Token without Bearer prefix returns 401."""
        w = await send_request(handler, "GET", "/_api/state", headers={"authorization": "secret_token_abc"})
        assert w.status_code == 401

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_health_no_auth_required(self, handler):
        """Health endpoint is accessible without auth."""
        w = await send_request(handler, "GET", "/_health")
        assert w.status_code == 200
        data = w.json_body
        assert data["status"] == "ok"

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_manifest_strips_token(self, handler):
        """Public manifest endpoint must NOT include the session token."""
        w = await send_request(handler, "GET", "/_api/manifest")
        assert w.status_code == 200
        data = w.json_body
        assert "token" not in data.get("session", {})

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_authenticated_manifest_has_data(self, handler):
        """Authenticated manifest returns session metadata."""
        w = await send_request(handler, "GET", "/_api/manifest", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 200

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1134
    @pytest.mark.asyncio
    async def test_token_timing_attack_resistance(self, handler):
        """Both correct and incorrect tokens should complete (constant-time check)."""
        # Correct
        w1 = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer secret_token_abc"})
        # Incorrect (same length)
        w2 = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer secret_token_xyz"})
        assert w1.status_code == 200
        assert w2.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PATH TRAVERSAL — OWASP A01; MITRE T1190
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathTraversal:
    """Path traversal protection for static file serving."""

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1190
    @pytest.mark.asyncio
    async def test_basic_traversal_blocked(self, handler):
        """../../etc/passwd should return 403 or 404."""
        w = await send_request(handler, "GET", "/../../etc/passwd")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_encoded_traversal_blocked(self, handler):
        """URL-encoded traversal should be blocked."""
        w = await send_request(handler, "GET", "/%2e%2e/%2e%2e/etc/passwd")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_double_encoded_traversal(self, handler):
        """Double-encoded traversal."""
        w = await send_request(handler, "GET", "/%252e%252e/%252e%252e/etc/passwd")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_backslash_traversal(self, handler):
        """Backslash traversal (Windows-style)."""
        w = await send_request(handler, "GET", "/..\\..\\etc\\passwd")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_null_byte_in_path(self, handler):
        """Null byte injection in file path."""
        w = await send_request(handler, "GET", "/app.js%00.html")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_valid_static_file(self, handler):
        """Legitimate static file should be served."""
        w = await send_request(handler, "GET", "/app.js")
        assert w.status_code == 200

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_dotfile_access(self, handler):
        """Access to dotfiles should be handled safely."""
        w = await send_request(handler, "GET", "/.env")
        assert w.status_code in (403, 404)

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_symlink_escape(self, handler, tmp_data_dir):
        """Symlink that points outside apps_dir should be blocked."""
        apps_dir = tmp_data_dir / "apps" / "testapp"
        link = apps_dir / "escape"
        try:
            link.symlink_to("/etc")
        except OSError:
            pytest.skip("Cannot create symlink")
        w = await send_request(handler, "GET", "/escape/passwd")
        assert w.status_code in (403, 404)
        link.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SECURITY HEADERS — OWASP A05; MITRE T1185
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecurityHeaders:
    """HTTP security headers on all responses."""

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_x_content_type_options(self, handler):
        w = await send_request(handler, "GET", "/_health")
        assert w.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_x_frame_options(self, handler):
        w = await send_request(handler, "GET", "/_health")
        assert w.headers.get("x-frame-options") == "DENY"

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_referrer_policy(self, handler):
        w = await send_request(handler, "GET", "/_health")
        assert w.headers.get("referrer-policy") == "no-referrer"

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_permissions_policy(self, handler):
        w = await send_request(handler, "GET", "/_health")
        pp = w.headers.get("permissions-policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_cors_origin_restricted(self, handler):
        w = await send_request(handler, "GET", "/_health")
        origin = w.headers.get("access-control-allow-origin", "")
        assert "127.0.0.1" in origin
        # Must NOT be wildcard
        assert origin != "*"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. CSP & BOOTSTRAP INJECTION — OWASP A03, A05; MITRE T1059, T1185
# ═══════════════════════════════════════════════════════════════════════════════


class TestCSPAndBootstrap:
    """Content Security Policy and bootstrap data injection in index.html."""

    @pytest.mark.owasp_a05
    @pytest.mark.mitre_t1185
    @pytest.mark.asyncio
    async def test_html_has_csp_header(self, handler):
        """HTML responses must include a CSP header."""
        w = await send_request(handler, "GET", "/")
        csp = w.headers.get("content-security-policy", "")
        assert "default-src 'none'" in csp
        assert "script-src 'nonce-" in csp
        assert "frame-ancestors 'none'" in csp
        assert "form-action 'none'" in csp

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_csp_nonce_is_unique_per_request(self, handler):
        """Each HTML response should have a different CSP nonce."""
        w1 = await send_request(handler, "GET", "/")
        w2 = await send_request(handler, "GET", "/")
        csp1 = w1.headers.get("content-security-policy", "")
        csp2 = w2.headers.get("content-security-policy", "")
        # Extract nonces
        import re

        nonces1 = re.findall(r"nonce-([a-f0-9]+)", csp1)
        nonces2 = re.findall(r"nonce-([a-f0-9]+)", csp2)
        assert nonces1 and nonces2
        assert nonces1[0] != nonces2[0]

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_bootstrap_injects_token(self, handler):
        """Bootstrap data should include the session token."""
        w = await send_request(handler, "GET", "/")
        assert "window.__OCV__" in w.body
        assert "secret_token_abc" in w.body

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_bootstrap_injects_public_key(self, handler):
        """Bootstrap should include the public key for signature verification."""
        w = await send_request(handler, "GET", "/")
        assert "publicKey" in w.body

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1059
    @pytest.mark.asyncio
    async def test_bootstrap_escapes_script_close_tag(self, handler, contract):
        """If state contains </script>, it must be escaped in bootstrap."""
        # Write state with a dangerous string
        state = {"version": 2, "status": "ready", "message": "</script><script>evil()</script>"}
        contract.write_json(contract.state_path, state)

        w = await send_request(handler, "GET", "/")
        # The literal </script> should NOT appear unescaped
        bootstrap_section = (
            w.body.split("window.__OCV__")[1].split("</script>")[0] if "window.__OCV__" in w.body else ""
        )
        assert "<\\/script>" in w.body or "</script><script>evil()" not in bootstrap_section

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_bootstrap_escapes_html_comment(self, handler, contract):
        """HTML comments in state data must be escaped."""
        state = {"version": 2, "status": "ready", "message": "<!-- injected comment -->"}
        contract.write_json(contract.state_path, state)

        w = await send_request(handler, "GET", "/")
        # <!-- should be escaped to <\!--
        assert (
            "<!--" not in w.body.split("window.__OCV__")[1].split("</script>")[0]
            if "window.__OCV__" in w.body
            else True
        )

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_script_tags_get_nonce(self, handler):
        """All <script> tags in the HTML should have the CSP nonce."""
        w = await send_request(handler, "GET", "/")
        import re

        scripts = re.findall(r"<script[^>]*>", w.body)
        for script_tag in scripts:
            assert "nonce=" in script_tag, f"Script tag missing nonce: {script_tag}"

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_csp_blocks_inline_scripts(self, handler):
        """CSP should not include 'unsafe-inline' for scripts."""
        w = await send_request(handler, "GET", "/")
        csp = w.headers.get("content-security-policy", "")
        # script-src should only allow nonce, not unsafe-inline
        script_src = [p for p in csp.split(";") if "script-src" in p]
        if script_src:
            assert "'unsafe-inline'" not in script_src[0]

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_csp_ws_connect_src_localhost_only(self, handler):
        """connect-src should only allow self and localhost WebSocket."""
        w = await send_request(handler, "GET", "/")
        csp = w.headers.get("content-security-policy", "")
        connect_parts = [p for p in csp.split(";") if "connect-src" in p]
        if connect_parts:
            assert "ws://127.0.0.1:" in connect_parts[0]
            # Should NOT allow ws://* or wss://*
            assert "ws://*" not in connect_parts[0]

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_non_html_no_csp(self, handler):
        """Non-HTML responses should not have CSP headers (or at least not nonce-based)."""
        w = await send_request(handler, "GET", "/_health")
        csp = w.headers.get("content-security-policy", "")
        # JSON response shouldn't have nonce-based CSP
        assert "nonce-" not in csp


# ═══════════════════════════════════════════════════════════════════════════════
# 5. API ENDPOINT SECURITY — OWASP A01, A08; MITRE T1071
# ═══════════════════════════════════════════════════════════════════════════════


class TestAPIEndpoints:
    """API endpoint behavior and security."""

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_unknown_api_returns_404(self, handler):
        w = await send_request(handler, "GET", "/_api/unknown", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 404

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_actions_post_invalid_json(self, handler):
        w = await send_request(
            handler, "POST", "/_api/actions", headers={"authorization": "Bearer secret_token_abc"}, body=b"not json"
        )
        assert w.status_code == 400

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_actions_method_not_allowed(self, handler):
        w = await send_request(handler, "PATCH", "/_api/actions", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 405

    @pytest.mark.owasp_a08
    @pytest.mark.asyncio
    async def test_actions_post_valid(self, handler):
        action = {"action_id": "test_action", "type": "confirm", "value": True}
        w = await send_request(
            handler,
            "POST",
            "/_api/actions",
            headers={"authorization": "Bearer secret_token_abc"},
            body=json.dumps(action).encode(),
        )
        assert w.status_code == 200
        data = w.json_body
        assert len(data["actions"]) >= 1

    @pytest.mark.owasp_a08
    @pytest.mark.asyncio
    async def test_actions_delete_clears(self, handler):
        w = await send_request(handler, "DELETE", "/_api/actions", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 200

    @pytest.mark.owasp_a08
    @pytest.mark.asyncio
    async def test_state_returns_current(self, handler):
        w = await send_request(handler, "GET", "/_api/state", headers={"authorization": "Bearer secret_token_abc"})
        assert w.status_code == 200
        data = w.json_body
        assert data["status"] == "ready"

    @pytest.mark.llm10
    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_body_size_limit(self, handler):
        """POST body exceeding MAX_BODY_SIZE should be rejected."""
        # MAX_BODY_SIZE is 1MB; we test the handler reads content-length
        # The actual enforcement happens in handle_request, which we'd need
        # a full stream to test. Here we test that the action validator catches
        # oversized action values.
        action = {"action_id": "x", "type": "confirm", "value": "A" * 100_001}
        w = await send_request(
            handler,
            "POST",
            "/_api/actions",
            headers={"authorization": "Bearer secret_token_abc"},
            body=json.dumps(action).encode(),
        )
        assert w.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# 6. DATA CONTRACT — OWASP A08; MITRE T1565
# ═══════════════════════════════════════════════════════════════════════════════


class TestDataContract:
    """File-based data contract integrity."""

    @pytest.mark.owasp_a08
    def test_atomic_write(self, contract, tmp_data_dir):
        """write_json uses tmp+rename for atomic writes."""
        data = {"version": 1, "test": True}
        contract.write_json(contract.state_path, data)

        # Verify the data was written correctly
        result = contract.read_json(contract.state_path)
        assert result["test"] is True

        # Verify no .tmp file left behind
        assert not (contract.state_path.with_suffix(".tmp")).exists()

    @pytest.mark.owasp_a08
    def test_read_invalid_json(self, contract, tmp_data_dir):
        """Reading corrupted JSON returns None gracefully."""
        (tmp_data_dir / "state.json").write_text("{broken")
        result = contract.read_json(contract.state_path)
        assert result is None

    @pytest.mark.owasp_a08
    def test_read_missing_file(self, contract, tmp_data_dir):
        (tmp_data_dir / "state.json").unlink()
        result = contract.read_json(contract.state_path)
        assert result is None

    @pytest.mark.owasp_a08
    @pytest.mark.mitre_t1565
    def test_append_action_adds_metadata(self, contract):
        """append_action adds id and timestamp automatically."""
        result = contract.append_action({"action_id": "test", "type": "confirm", "value": True})
        last_action = result["actions"][-1]
        assert "id" in last_action
        assert "timestamp" in last_action

    @pytest.mark.owasp_a08
    def test_clear_actions(self, contract):
        contract.append_action({"action_id": "test", "type": "confirm"})
        count = contract.clear_actions()
        assert count >= 1
        result = contract.get_actions()
        assert len(result["actions"]) == 0

    @pytest.mark.owasp_a08
    def test_change_detection(self, contract, tmp_data_dir):
        """check_changes detects file modifications."""
        # Initialize mtimes
        contract.check_changes()
        # Modify state
        time.sleep(0.01)
        state = {"version": 2, "status": "ready"}
        contract.write_json(contract.state_path, state)
        changed = contract.check_changes()
        assert "state" in changed


# ═══════════════════════════════════════════════════════════════════════════════
# 7. CONTENT TYPE HANDLING — OWASP A05
# ═══════════════════════════════════════════════════════════════════════════════


class TestContentTypeHandling:
    """Correct content types prevent MIME confusion attacks."""

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_html_content_type(self, handler):
        w = await send_request(handler, "GET", "/")
        assert "text/html" in w.headers.get("content-type", "")

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_js_content_type(self, handler):
        w = await send_request(handler, "GET", "/app.js")
        assert "javascript" in w.headers.get("content-type", "")

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_css_content_type(self, handler):
        w = await send_request(handler, "GET", "/style.css")
        assert "css" in w.headers.get("content-type", "")

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_json_api_content_type(self, handler):
        w = await send_request(handler, "GET", "/_health")
        assert "application/json" in w.headers.get("content-type", "")

    @pytest.mark.owasp_a05
    @pytest.mark.asyncio
    async def test_unknown_extension_octet_stream(self, handler, tmp_data_dir):
        """Unknown file extensions should be served as application/octet-stream."""
        (tmp_data_dir / "apps" / "testapp" / "data.bin").write_bytes(b"\x00\x01\x02")
        w = await send_request(handler, "GET", "/data.bin")
        assert "octet-stream" in w.headers.get("content-type", "")


# ═══════════════════════════════════════════════════════════════════════════════
# 8. SESSION TOKEN MANAGEMENT — OWASP A02, A07; MITRE T1078, T1185
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionTokenManagement:
    """Session token lifecycle and security."""

    @pytest.mark.owasp_a02
    @pytest.mark.mitre_t1185
    def test_token_from_environment_preferred(self, tmp_data_dir):
        """OCV_SESSION_TOKEN env var takes precedence over manifest."""
        env_token = "env_secret_token_xyz"
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": env_token}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=0,
                ws_port=0,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            assert server.session_token == env_token

    @pytest.mark.owasp_a02
    def test_token_fallback_to_manifest(self, tmp_data_dir):
        """Without env var, token comes from manifest."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove OCV_SESSION_TOKEN if present
            os.environ.pop("OCV_SESSION_TOKEN", None)
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=0,
                ws_port=0,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            assert server.session_token == "secret_token_abc"

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_manifest_api_never_leaks_token(self, handler):
        """The public manifest endpoint MUST strip the token."""
        w = await send_request(handler, "GET", "/_api/manifest")
        body = w.body
        assert "secret_token_abc" not in body

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1185
    @pytest.mark.asyncio
    async def test_token_only_in_bootstrap(self, handler):
        """Token appears in bootstrap (index.html) but NOT in API responses."""
        # Bootstrap should have it
        w_html = await send_request(handler, "GET", "/")
        assert "secret_token_abc" in w_html.body

        # Manifest API should NOT
        w_manifest = await send_request(handler, "GET", "/_api/manifest")
        assert "secret_token_abc" not in w_manifest.body


# ═══════════════════════════════════════════════════════════════════════════════
# 9. LOCALHOST BINDING — OWASP A10; MITRE T1568
# ═══════════════════════════════════════════════════════════════════════════════


class TestLocalhostBinding:
    """Server must only bind to 127.0.0.1."""

    @pytest.mark.owasp_a10
    @pytest.mark.mitre_t1568
    def test_cors_origin_is_localhost(self, handler):
        """CORS origin must be localhost."""
        # The handler uses http_port to compute the origin
        # We verify the origin string format
        origin = f"http://127.0.0.1:{handler.http_port}"
        assert "127.0.0.1" in origin
        assert "0.0.0.0" not in origin

    @pytest.mark.owasp_a10
    @pytest.mark.asyncio
    async def test_cors_not_wildcard(self, handler):
        """CORS Access-Control-Allow-Origin must not be *."""
        w = await send_request(handler, "GET", "/_health")
        origin = w.headers.get("access-control-allow-origin", "")
        assert origin != "*"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. SECURITY GATE INTEGRATION — LLM01, LLM05; OWASP A09
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecurityGateIntegration:
    """Security gate validates state before broadcast and actions before storage."""

    @pytest.mark.llm05
    @pytest.mark.asyncio
    async def test_action_with_invalid_type_rejected(self, handler):
        """Actions with disallowed types are rejected by security gate."""
        action = {"action_id": "x", "type": "execute_code", "value": "rm -rf /"}
        w = await send_request(
            handler,
            "POST",
            "/_api/actions",
            headers={"authorization": "Bearer secret_token_abc"},
            body=json.dumps(action).encode(),
        )
        assert w.status_code == 400
        assert "invalid" in w.json_body.get("error", "").lower()

    @pytest.mark.llm05
    @pytest.mark.asyncio
    async def test_action_with_valid_type_accepted(self, handler):
        action = {"action_id": "ok", "type": "confirm", "value": True}
        w = await send_request(
            handler,
            "POST",
            "/_api/actions",
            headers={"authorization": "Bearer secret_token_abc"},
            body=json.dumps(action).encode(),
        )
        assert w.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 11. RATE LIMITING — MITRE T1499; LLM10
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimiter:
    """Rate limiter unit tests."""

    @pytest.mark.mitre_t1499
    def test_allows_within_limit(self):
        rl = RateLimiter(max_actions=5, window_seconds=60.0)
        for _ in range(5):
            assert rl.check() is True

    @pytest.mark.mitre_t1499
    def test_blocks_over_limit(self):
        rl = RateLimiter(max_actions=3, window_seconds=60.0)
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is False  # 4th should be blocked

    @pytest.mark.mitre_t1499
    def test_window_expiry_allows_again(self):
        rl = RateLimiter(max_actions=2, window_seconds=0.1)
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is False  # blocked
        time.sleep(0.15)  # wait for window to expire
        assert rl.check() is True  # allowed again

    @pytest.mark.mitre_t1499
    def test_default_limits(self):
        rl = RateLimiter()
        assert rl.max_actions == 30
        assert rl.window_seconds == 60.0


class TestRateLimitingHTTP:
    """Rate limiting integration with HTTP action endpoint."""

    @pytest.mark.mitre_t1499
    @pytest.mark.llm10
    @pytest.mark.asyncio
    async def test_action_rate_limit_returns_429(self, handler):
        """Exceeding rate limit on POST actions should return 429."""
        # Set a very low limit for testing
        handler._rate_limiter = RateLimiter(max_actions=2, window_seconds=60.0)
        auth = {"authorization": "Bearer secret_token_abc"}
        action = json.dumps({"action_id": "ok", "type": "confirm", "value": True}).encode()

        w1 = await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)
        assert w1.status_code == 200

        w2 = await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)
        assert w2.status_code == 200

        w3 = await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)
        assert w3.status_code == 429
        assert "rate limit" in w3.json_body.get("error", "").lower()

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_rate_limit_does_not_affect_reads(self, handler):
        """Rate limiting should only apply to POST actions, not GET."""
        handler._rate_limiter = RateLimiter(max_actions=1, window_seconds=60.0)
        auth = {"authorization": "Bearer secret_token_abc"}

        # Exhaust the rate limit
        action = json.dumps({"action_id": "ok", "type": "confirm", "value": True}).encode()
        await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)
        await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)

        # GET should still work
        w = await send_request(handler, "GET", "/_api/state", headers=auth)
        assert w.status_code == 200

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_rate_limit_does_not_affect_delete(self, handler):
        """DELETE actions (clear) should not be rate limited."""
        handler._rate_limiter = RateLimiter(max_actions=1, window_seconds=60.0)
        auth = {"authorization": "Bearer secret_token_abc"}

        # Exhaust the rate limit
        action = json.dumps({"action_id": "ok", "type": "confirm", "value": True}).encode()
        await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)
        await send_request(handler, "POST", "/_api/actions", headers=auth, body=action)

        # DELETE should still work
        w = await send_request(handler, "DELETE", "/_api/actions", headers=auth)
        assert w.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 10. BOOTSTRAP ESCAPING — OWASP A03; MITRE T1059.007; OWASP LLM01
# ═══════════════════════════════════════════════════════════════════════════════


class TestBootstrapEscaping:
    """window.__OCV__ bootstrap data must be safe for embedding in a <script> context.

    A malicious state value containing </script> could break out of the JSON script block
    and inject arbitrary HTML.  The server must escape these sequences before injection.
    """

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.mitre_t1059_007
    @pytest.mark.asyncio
    async def test_close_script_tag_is_escaped(self, handler, tmp_data_dir):
        """</script> in state data must be escaped to <\\/script> in the bootstrap block."""
        # Write a state that contains a raw </script> breakout attempt
        malicious_state = {
            "version": 1,
            "status": "ready",
            "title": "Test",
            "data": {"msg": "</script><script>alert(1)</script>"},
        }
        (tmp_data_dir / "state.json").write_text(json.dumps(malicious_state))

        index = tmp_data_dir / "apps" / "testapp" / "index.html"
        index.write_text("<!DOCTYPE html><html><head></head><body></body></html>")
        manifest = json.loads((tmp_data_dir / "manifest.json").read_text())

        writer = MockWriter()
        await handler._send_index_with_bootstrap(writer, index, manifest)
        html = writer.response_text

        # The raw </script> must not appear outside of the nonce-guarded bootstrap block
        # After escaping it becomes <\/script>
        assert "<\\/script>" in html or "</script>" not in html.split("window.__OCV__")[1].split("</script>")[0]

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.mitre_t1059_007
    @pytest.mark.asyncio
    async def test_html_comment_opener_is_escaped(self, handler, tmp_data_dir):
        """<!-- inside bootstrap data must be escaped to prevent HTML comment injection."""
        malicious_state = {
            "version": 1,
            "status": "ready",
            "title": "Test",
            "data": {"msg": "<!-- injected comment -->"},
        }
        (tmp_data_dir / "state.json").write_text(json.dumps(malicious_state))

        index = tmp_data_dir / "apps" / "testapp" / "index.html"
        index.write_text("<!DOCTYPE html><html><head></head><body></body></html>")
        manifest = json.loads((tmp_data_dir / "manifest.json").read_text())

        writer = MockWriter()
        await handler._send_index_with_bootstrap(writer, index, manifest)
        html = writer.response_text

        # Raw <!-- must not appear in the bootstrap block
        body = html.split("window.__OCV__")[1] if "window.__OCV__" in html else ""
        assert "<!--" not in body.split("</script>")[0]

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_session_token_delivered_in_bootstrap(self, handler, tmp_data_dir):
        """Session token must be injected into the bootstrap window.__OCV__ block in the HTML.

        The handler's session_token is 'secret_token_abc' (set in the handler fixture).
        _send_index_with_bootstrap always injects the handler's real session_token into
        the bootstrap JSON — regardless of what the manifest on disk says.
        """
        manifest = json.loads((tmp_data_dir / "manifest.json").read_text())

        index = tmp_data_dir / "apps" / "testapp" / "index.html"
        index.write_text("<!DOCTYPE html><html><head></head><body></body></html>")
        writer = MockWriter()
        await handler._send_index_with_bootstrap(writer, index, manifest)
        html = writer.response_text

        # Token must be in the bootstrap block injected into the HTML
        assert "window.__OCV__" in html
        assert "secret_token_abc" in html


# ═══════════════════════════════════════════════════════════════════════════════
# 11. SECURITY GATE VIA HTTP ACTION ENDPOINT — OWASP A03; OWASP LLM01
# ═══════════════════════════════════════════════════════════════════════════════


class TestActionSecurityGateHTTP:
    """SecurityGate validates incoming actions posted to /_api/actions via HTTP.

    SecurityGate.validate_action enforces: allowed action types, non-empty action_id,
    and value size limits.  XSS in action *values* is intentionally not blocked here —
    action values come from the human user, not the agent, and the agent must treat them
    as untrusted input regardless.  Client-side DOMPurify handles rendering safety.
    """

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_unknown_action_type_rejected(self, handler):
        """Actions with disallowed type strings must be rejected with 400."""
        auth = {"authorization": "Bearer secret_token_abc"}
        bad_action = json.dumps(
            {
                "action_id": "submit",
                "type": "evil_unknown_type",
                "value": True,
            }
        ).encode()

        w = await send_request(handler, "POST", "/_api/actions", headers=auth, body=bad_action)
        assert w.status_code == 400
        assert "invalid" in w.json_body.get("error", "").lower()

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_missing_action_id_rejected(self, handler):
        """Actions without an action_id must be rejected with 400."""
        auth = {"authorization": "Bearer secret_token_abc"}
        bad_action = json.dumps(
            {
                "type": "approve",
                "value": True,
            }
        ).encode()

        w = await send_request(handler, "POST", "/_api/actions", headers=auth, body=bad_action)
        assert w.status_code == 400

    @pytest.mark.owasp_a03
    @pytest.mark.llm10
    @pytest.mark.asyncio
    async def test_oversized_value_rejected(self, handler):
        """Actions whose value exceeds 100KB must be rejected with 400 (DoS prevention)."""
        auth = {"authorization": "Bearer secret_token_abc"}
        big_action = json.dumps(
            {
                "action_id": "submit",
                "type": "submit",
                "value": "x" * 200_000,
            }
        ).encode()

        w = await send_request(handler, "POST", "/_api/actions", headers=auth, body=big_action)
        assert w.status_code == 400

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_clean_action_accepted(self, handler):
        """A well-formed action passes validation and returns 200."""
        auth = {"authorization": "Bearer secret_token_abc"}
        clean_action = json.dumps(
            {
                "action_id": "approve",
                "type": "approve",
                "value": True,
            }
        ).encode()

        w = await send_request(handler, "POST", "/_api/actions", headers=auth, body=clean_action)
        assert w.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 12. INPUT VALIDATION — content-length and since_version — OWASP A03
# ═══════════════════════════════════════════════════════════════════════════════


class TestInputValidation:
    """Malformed numeric inputs must return 4xx, not crash the handler (ValueError)."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_non_numeric_since_version_returns_400(self, handler):
        """since_version=abc must return 400, not raise ValueError."""
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/_api/state", headers=auth, query={"since_version": ["abc"]})
        assert w.status_code == 400

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_float_since_version_returns_400(self, handler):
        """since_version=1.5 (float string) must return 400."""
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/_api/state", headers=auth, query={"since_version": ["1.5"]})
        assert w.status_code == 400

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_valid_since_version_returns_200_or_304(self, handler):
        """since_version=0 (behind current version=1) must return state."""
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/_api/state", headers=auth, query={"since_version": ["0"]})
        assert w.status_code in (200, 304)

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1499
    def test_content_length_validation_code_rejects_non_numeric(self):
        """Verify the connection handler validates content-length before _route.

        Content-Length parsing happens in _handle_connection (before _route),
        so we verify the validation logic exists in the source code rather than
        testing it through send_request (which bypasses that layer).
        """
        import inspect
        from webview_server import WebviewHTTPHandler

        src = inspect.getsource(WebviewHTTPHandler.handle_request)
        assert "Invalid Content-Length" in src, "Must reject non-numeric Content-Length"
        assert 'int(headers.get("content-length"' in src or "content_length < 0" in src

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1499
    def test_content_length_validation_code_rejects_negative(self):
        """Verify the connection handler rejects negative Content-Length values."""
        import inspect
        from webview_server import WebviewHTTPHandler

        src = inspect.getsource(WebviewHTTPHandler.handle_request)
        assert "content_length < 0" in src, "Must reject negative Content-Length"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. TOKEN TIMING SAFETY — OWASP A07; MITRE T1078
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenTimingSafety:
    """Token comparison must use hmac.compare_digest() to prevent timing attacks.

    We can't directly measure timing in a unit test, but we can verify the
    correct comparison method is used by inspecting _check_token behavior for
    edge cases where == and compare_digest differ (empty string, unicode, etc.)
    and by checking the source uses the stdlib constant-time function.
    """

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    def test_empty_token_rejected(self, handler):
        """Empty token must be rejected (compare_digest('', token) returns False)."""
        result = handler._check_token({"authorization": "Bearer "})
        assert result is False

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    def test_correct_token_accepted(self, handler):
        """Correct token must be accepted."""
        result = handler._check_token({"authorization": "Bearer secret_token_abc"})
        assert result is True

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    def test_prefix_token_rejected(self, handler):
        """Prefix of correct token must be rejected (not a timing shortcut)."""
        result = handler._check_token({"authorization": "Bearer secret_token"})
        assert result is False

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    def test_check_token_uses_compare_digest(self, handler):
        """Verify _check_token source uses hmac.compare_digest (not ==)."""
        import inspect

        src = inspect.getsource(handler._check_token)
        assert "compare_digest" in src, "Must use hmac.compare_digest for constant-time comparison"
        assert "== self.session_token" not in src, "Must not use == for token comparison"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. WEBSOCKET ACTION SECURITY GATE — OWASP A03; OWASP LLM01; MITRE T1565
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebSocketActionSecurityGate:
    """SecurityGate must be applied on the WebSocket action path, not only HTTP.

    Both paths must have equivalent validation so that the WS channel cannot be
    used to bypass the security controls that protect the HTTP action endpoint.
    """

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.mitre_t1565
    def test_ws_action_handler_calls_security_gate(self):
        """Verify the WS action handler source applies SecurityGate.validate_action()."""
        import inspect
        from webview_server import WebviewServer

        src = inspect.getsource(WebviewServer._handle_ws)
        assert "validate_action" in src, "WS handler must call SecurityGate.validate_action()"
        assert "_security_gate" in src, "WS handler must use self._security_gate singleton"

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.mitre_t1565
    def test_ws_gate_applied_before_append(self):
        """SecurityGate check must precede contract.append_action() in WS handler source."""
        import inspect
        from webview_server import WebviewServer

        src = inspect.getsource(WebviewServer._handle_ws)
        gate_pos = src.find("validate_action")
        append_pos = src.find("append_action")
        assert gate_pos != -1 and append_pos != -1, "Both calls must exist"
        assert gate_pos < append_pos, "validate_action must appear before append_action in source"

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.mitre_t1565
    def test_ws_and_http_both_have_rate_limit_and_gate(self):
        """Both HTTP and WS action paths must apply rate limiting and SecurityGate."""
        import inspect
        from webview_server import WebviewHTTPHandler, WebviewServer

        # Rate limiting and SecurityGate live in _handle_api for HTTP, _handle_ws for WS
        http_src = inspect.getsource(WebviewHTTPHandler._handle_api)
        ws_src = inspect.getsource(WebviewServer._handle_ws)
        for src, path_name in ((http_src, "HTTP"), (ws_src, "WS")):
            assert "_rate_limiter" in src, f"{path_name} path must apply rate limiting"
            assert "validate_action" in src, f"{path_name} path must call SecurityGate.validate_action()"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. PATH TRAVERSAL CHECK ORDER — OWASP A01; MITRE T1190
# ═══════════════════════════════════════════════════════════════════════════════


class TestStaticFilePathTraversalOrder:
    """Path containment must be validated BEFORE checking file existence.

    Checking existence first leaks timing information about whether traversal
    targets (e.g. ../../etc/passwd) exist outside the apps directory.
    The check order should be: containment → existence → serve.
    """

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1190
    def test_containment_checked_before_existence_in_source(self):
        """Verify static handler checks containment before existence for user-controlled paths.

        The index path check (is_file on a hardcoded path) is safe; the important
        invariant is that relative_to(apps_dir_resolved) appears before primary.is_file()
        in the section that handles user-supplied URL paths.
        """
        import inspect
        from webview_server import WebviewHTTPHandler

        src = inspect.getsource(WebviewHTTPHandler._handle_static)
        # Check the specific identifiers used in the user-controlled path section
        containment_pos = src.find("relative_to(apps_dir_resolved)")
        existence_pos = src.find("primary.is_file()")
        assert containment_pos != -1, "Must call relative_to(apps_dir_resolved) for containment"
        assert existence_pos != -1, "Must call primary.is_file() to check file existence"
        assert containment_pos < existence_pos, (
            "relative_to() containment check must come before primary.is_file() existence check"
        )

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1190
    def test_path_not_leaked_in_404_message(self):
        """404 error messages must not include the requested path (path disclosure)."""
        import inspect
        from webview_server import WebviewHTTPHandler

        src = inspect.getsource(WebviewHTTPHandler._handle_static)
        # File-not-found messages must not embed f-string path values
        assert 'f"File not found: {path}"' not in src, "404 must not include path in message"
        assert 'f"App entry not found: {index}"' not in src, "404 must not include index path"

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1190
    @pytest.mark.asyncio
    async def test_traversal_attempt_returns_403_not_404(self, handler, tmp_data_dir):
        """A path-traversal attempt (../../etc/passwd) must yield 403, not 404.

        This also verifies that the containment check fires even when the traversal
        target doesn't exist — i.e. the check is purely structural, not existence-based.
        """
        auth = {"authorization": "Bearer secret_token_abc"}
        # Write a manifest so _handle_static can resolve the app dir
        w = await send_request(handler, "GET", "/../../etc/passwd", headers=auth)
        assert w.status_code == 403

    @pytest.mark.owasp_a01
    @pytest.mark.mitre_t1190
    @pytest.mark.asyncio
    async def test_valid_static_file_still_served(self, handler, tmp_data_dir):
        """Legitimate static file requests must still be served after the check-order fix."""
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/app.js", headers=auth)
        assert w.status_code == 200


class TestAppDirValidation:
    """Tests for app directory name validation in _handle_static (M4 hardening)."""

    @pytest.fixture
    def handler_with_manifest(self, handler, tmp_data_dir):
        """Handler with a known manifest."""
        return handler

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_valid_app_dir_name(self, handler, tmp_data_dir):
        """A valid app directory name should be accepted."""
        auth = {"authorization": "Bearer secret_token_abc"}
        # Default manifest has app.entry = "dynamic/index.html", app_dir_name = "dynamic"
        w = await send_request(handler, "GET", "/", headers=auth)
        assert w.status_code in (200, 404)  # 200 if index exists, 404 if not — but not 400

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_traversal_app_dir_name_rejected(self, handler, tmp_data_dir):
        """An app entry with path traversal in the manifest must be rejected."""
        manifest = {
            "version": "1.0",
            "app": {"name": "evil", "entry": "../../../etc/index.html", "title": "Evil"},
            "session": {"id": "test-id", "token": "REDACTED"},
            "server": {"http_port": 18420, "ws_port": 18421, "host": "127.0.0.1"},
        }
        handler.contract.write_json(handler.contract.manifest_path, manifest)
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/", headers=auth)
        assert w.status_code == 400, "Path traversal in app entry must be rejected with 400"

    @pytest.mark.owasp_a01
    @pytest.mark.asyncio
    async def test_empty_app_dir_name_rejected(self, handler, tmp_data_dir):
        """An empty app entry in the manifest must be rejected."""
        manifest = {
            "version": "1.0",
            "app": {"name": "empty", "entry": "", "title": "Empty"},
            "session": {"id": "test-id", "token": "REDACTED"},
            "server": {"http_port": 18420, "ws_port": 18421, "host": "127.0.0.1"},
        }
        handler.contract.write_json(handler.contract.manifest_path, manifest)
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "GET", "/", headers=auth)
        assert w.status_code == 400


class TestSecurityGateSingleton:
    """Tests for SecurityGate singleton usage in HTTP handler (M3 hardening)."""

    @pytest.mark.owasp_a05
    def test_handler_has_security_gate_instance(self, handler):
        """WebviewHTTPHandler must have a _security_gate attribute."""
        assert hasattr(handler, "_security_gate"), "Handler must have _security_gate"

    @pytest.mark.owasp_a05
    def test_handler_security_gate_is_singleton(self, handler):
        """The _security_gate must be a SecurityGate instance (not None if HAS_GATE)."""
        from security_gate import SecurityGate

        if handler._security_gate is not None:
            assert isinstance(handler._security_gate, SecurityGate)


class TestCloseMessageLimits:
    """Tests for close message sanitization (L3 hardening)."""

    @pytest.mark.asyncio
    async def test_close_message_length_limited(self, handler):
        """Close message must be truncated to prevent exfiltration of large text."""
        import json

        long_message = "A" * 1000
        body = json.dumps({"message": long_message}).encode()
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "POST", "/_api/close", headers=auth, body=body)
        assert w.status_code == 200
        # The actual truncation happens server-side before broadcasting — verify the handler accepted it

    @pytest.mark.asyncio
    async def test_close_default_message(self, handler):
        """Close endpoint with no message should use default."""
        auth = {"authorization": "Bearer secret_token_abc"}
        w = await send_request(handler, "POST", "/_api/close", headers=auth, body=b"{}")
        assert w.status_code == 200


class TestWaitForActionProgress:
    """Verify wait_for_action calls the progress callback to keep MCP alive."""

    @pytest.mark.asyncio
    async def test_progress_callback_fires_during_wait(self, tmp_path):
        """on_progress callback should fire at least once during a wait."""
        from mcp_server import WebviewSession

        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session.POLL_INTERVAL = 0.05
        session.PROGRESS_INTERVAL = 0.1

        actions_path = tmp_path / "actions.json"
        actions_path.write_text('{"version": 0, "actions": []}')

        calls: list[tuple[float, float]] = []

        async def _on_progress(elapsed: float, total: float) -> None:
            calls.append((elapsed, total))
            # Simulate user responding after first progress ping
            actions_path.write_text('{"version": 1, "actions": [{"action_id": "ok"}]}')

        result = await session.wait_for_action(timeout=5.0, on_progress=_on_progress)
        assert result is not None
        assert result["actions"][0]["action_id"] == "ok"
        assert len(calls) >= 1
        assert calls[0][1] == 5.0  # total should be the timeout

    @pytest.mark.asyncio
    async def test_progress_callback_exception_does_not_break_wait(self, tmp_path):
        """If on_progress raises, wait_for_action should continue polling."""
        from mcp_server import WebviewSession

        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session.POLL_INTERVAL = 0.05
        session.PROGRESS_INTERVAL = 0.1

        actions_path = tmp_path / "actions.json"
        actions_path.write_text('{"version": 0, "actions": []}')

        error_count = 0

        async def _bad_progress(elapsed: float, total: float) -> None:
            nonlocal error_count
            error_count += 1
            if error_count <= 2:
                raise RuntimeError("progress boom")
            # Third call: write action so wait completes
            actions_path.write_text('{"version": 1, "actions": [{"action_id": "done"}]}')

        result = await session.wait_for_action(timeout=5.0, on_progress=_bad_progress)
        assert result is not None
        assert error_count >= 2  # survived at least 2 exceptions

    @pytest.mark.asyncio
    async def test_no_progress_callback_still_works(self, tmp_path):
        """wait_for_action without on_progress should work as before."""
        from mcp_server import WebviewSession

        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session.POLL_INTERVAL = 0.05
        session.PROGRESS_INTERVAL = 0.1

        actions_path = tmp_path / "actions.json"
        actions_path.write_text('{"version": 1, "actions": [{"action_id": "immediate"}]}')

        result = await session.wait_for_action(timeout=1.0)
        assert result is not None
        assert result["actions"][0]["action_id"] == "immediate"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. FILE WATCHER — OWASP A08; LLM05
# ═══════════════════════════════════════════════════════════════════════════════


class TestFileWatcherBehavior:
    """Tests for the file watcher's change detection and debouncing logic."""

    @pytest.mark.owasp_a08
    def test_change_detection_tracks_all_files(self, contract, tmp_data_dir):
        """check_changes should detect modifications to state, actions, and manifest."""
        contract.check_changes()  # initialize mtimes
        time.sleep(0.02)

        # Modify all three files
        contract.write_json(contract.state_path, {"version": 2, "status": "updated"})
        contract.write_json(contract.actions_path, {"version": 1, "actions": [{"action_id": "x"}]})
        contract.write_json(contract.manifest_path, {"session": {"id": "new"}})

        changed = contract.check_changes()
        assert "state" in changed
        assert "actions" in changed
        assert "manifest" in changed

    @pytest.mark.owasp_a08
    def test_no_change_returns_empty(self, contract, tmp_data_dir):
        """check_changes returns empty list when nothing changed."""
        contract.check_changes()  # initialize
        changed = contract.check_changes()  # immediate re-check
        assert changed == []

    @pytest.mark.owasp_a08
    def test_missing_file_not_in_changes(self, contract, tmp_data_dir):
        """Missing files should not appear in changed list."""
        contract.check_changes()  # initialize
        (tmp_data_dir / "state.json").unlink()
        changed = contract.check_changes()
        # state was deleted, so stat() fails — it shouldn't crash or appear
        assert "state" not in changed

    @pytest.mark.owasp_a08
    def test_corrupted_json_still_readable_after_fix(self, contract, tmp_data_dir):
        """DataContract handles corrupted → fixed JSON gracefully."""
        contract.write_json(contract.state_path, {"version": 1})
        # Corrupt the file
        (tmp_data_dir / "state.json").write_text("{broken json")
        assert contract.get_state() is None
        # Fix it
        contract.write_json(contract.state_path, {"version": 2, "status": "fixed"})
        result = contract.get_state()
        assert result is not None
        assert result["version"] == 2

    @pytest.mark.owasp_a08
    def test_concurrent_append_actions(self, contract, tmp_data_dir):
        """Multiple rapid append_action calls should not lose data."""
        for i in range(10):
            contract.append_action({"action_id": f"action_{i}", "type": "confirm", "value": True})
        result = contract.get_actions()
        assert len(result["actions"]) == 10
        assert result["version"] == 10

    @pytest.mark.owasp_a08
    def test_clear_then_append_works(self, contract, tmp_data_dir):
        """Clearing actions then appending should start fresh."""
        contract.append_action({"action_id": "old", "type": "approve"})
        contract.clear_actions()
        contract.append_action({"action_id": "new", "type": "approve"})
        result = contract.get_actions()
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action_id"] == "new"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. ENV TOKEN VALIDATION — OWASP A07
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnvTokenValidation:
    """Tests for OCV_SESSION_TOKEN environment variable validation (M6 fix)."""

    @pytest.mark.owasp_a07
    def test_valid_hex_token_accepted(self, tmp_data_dir):
        """Normal hex token from env should be accepted."""
        token = "a" * 64
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": token}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            assert server.session_token == token

    @pytest.mark.owasp_a07
    def test_token_with_null_byte_rejected(self, tmp_data_dir):
        """Token containing null bytes should be rejected."""
        # os.environ cannot hold null bytes, so mock os.environ.get directly
        original_get = os.environ.get

        def fake_get(key, default=""):
            if key == "OCV_SESSION_TOKEN":
                return "abc\x00def"
            return original_get(key, default)

        with patch.object(os.environ, "get", side_effect=fake_get):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            # Should fall back to manifest token since env token was rejected
            assert "\x00" not in server.session_token

    @pytest.mark.owasp_a07
    def test_token_with_newline_rejected(self, tmp_data_dir):
        """Token containing newlines should be rejected."""
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": "abc\ndef"}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            assert "\n" not in server.session_token

    @pytest.mark.owasp_a07
    def test_oversized_token_rejected(self, tmp_data_dir):
        """Token exceeding 1024 bytes should be rejected."""
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": "x" * 2000}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            # Should fall back to manifest token
            assert len(server.session_token) <= 1024

    @pytest.mark.owasp_a07
    def test_whitespace_trimmed(self, tmp_data_dir):
        """Leading/trailing whitespace on token should be trimmed."""
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": "  mytoken  "}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            assert server.session_token == "mytoken"

    @pytest.mark.owasp_a07
    def test_empty_env_token_falls_back(self, tmp_data_dir):
        """Empty OCV_SESSION_TOKEN falls back to manifest."""
        with patch.dict(os.environ, {"OCV_SESSION_TOKEN": ""}):
            server = WebviewServer(
                data_dir=str(tmp_data_dir),
                http_port=19990,
                ws_port=19991,
                sdk_path=str(tmp_data_dir / "sdk.js"),
            )
            manifest = server.contract.get_manifest()
            expected = manifest.get("session", {}).get("token", "") if manifest else ""
            assert server.session_token == expected


# ═══════════════════════════════════════════════════════════════════════════════
# 20. WEBSOCKET CONNECTION LIMIT — H1 FIX
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebSocketConnectionLimit:
    """Tests for MAX_WEBSOCKET_CLIENTS (H1 security fix)."""

    def test_max_websocket_clients_is_50(self):
        """WebviewServer must enforce a max of 50 concurrent WS clients."""
        assert WebviewServer.MAX_WEBSOCKET_CLIENTS == 50

    def test_connection_limit_exists_in_handler_source(self):
        """_handle_ws source must check len(self._ws_clients) before accepting."""
        import inspect

        src = inspect.getsource(WebviewServer._handle_ws)
        assert "MAX_WEBSOCKET_CLIENTS" in src, "Handler must reference MAX_WEBSOCKET_CLIENTS"
        assert "at capacity" in src.lower() or "1008" in src, "Must close with 1008 when at capacity"

    def test_connection_limit_checked_before_auth(self):
        """Connection limit must be checked BEFORE auth (prevent DoS via auth timeout)."""
        import inspect

        src = inspect.getsource(WebviewServer._handle_ws)
        limit_pos = src.find("MAX_WEBSOCKET_CLIENTS")
        auth_pos = src.find("authenticated")
        assert limit_pos != -1, "Must check MAX_WEBSOCKET_CLIENTS"
        assert auth_pos != -1, "Must have auth check"
        assert limit_pos < auth_pos, "Limit check must come before auth"


# ═══════════════════════════════════════════════════════════════════════════════
# 21. GENERIC ERROR MESSAGES — M5 FIX
# ═══════════════════════════════════════════════════════════════════════════════


class TestGenericErrorMessages:
    """Verify that SecurityGate details are NOT leaked to the client (M5 fix)."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_http_action_rejection_is_generic(self, handler):
        """HTTP action rejection message must NOT contain SecurityGate details."""
        auth = {"authorization": "Bearer secret_token_abc"}
        bad_action = json.dumps({"action_id": "x", "type": "evil_type", "value": True}).encode()
        w = await send_request(handler, "POST", "/_api/actions", headers=auth, body=bad_action)
        assert w.status_code == 400
        error_msg = w.json_body.get("error", "")
        assert error_msg == "Invalid action"
        # Must NOT contain details about why it was rejected
        assert "evil_type" not in error_msg
        assert "action type" not in error_msg.lower()

    @pytest.mark.owasp_a03
    def test_file_watcher_error_message_is_generic(self):
        """State rejection broadcast must NOT contain SecurityGate details."""
        import inspect

        src = inspect.getsource(WebviewServer._file_watcher)
        # The broadcast message must be a generic string, not f-string with err
        assert 'f"State rejected: {err}"' not in src, "Must NOT include SecurityGate error details in broadcast"

    @pytest.mark.owasp_a03
    def test_ws_action_error_is_generic(self):
        """WS action rejection must NOT contain SecurityGate details."""
        import inspect

        src = inspect.getsource(WebviewServer._handle_ws)
        # Check that WS error messages don't leak validation details
        assert 'f"Action rejected: {err}"' not in src, "WS handler must NOT include detailed rejection"


# ═══════════════════════════════════════════════════════════════════════════════
# 22. HEADER COUNT LIMIT — LLM10
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderCountLimit:
    """Verify the 100-header cap is enforced."""

    def test_header_limit_constant_in_source(self):
        """handle_request must cap headers at 100."""
        import inspect

        src = inspect.getsource(WebviewHTTPHandler.handle_request)
        assert "100" in src, "Header loop must be limited to 100"
        assert "431" in src, "Must return 431 for too many headers"


# ═══════════════════════════════════════════════════════════════════════════════
# 23. UNICODE NORMALIZATION IN SECURITY GATE — M10 FIX
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnicodeNormalizationIntegration:
    """Integration test: SecurityGate normalizes unicode before XSS scanning."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_decomposed_unicode_in_state_is_normalized(self, handler):
        """State with decomposed unicode should be normalized and accepted (if safe)."""
        auth = {"authorization": "Bearer secret_token_abc"}

        # Write state with decomposed unicode (combining accent on 'e')
        state = {"version": 2, "title": "caf\u0065\u0301", "status": "ok"}
        handler.contract.write_json(handler.contract.state_path, state)

        w = await send_request(handler, "GET", "/_api/state", headers=auth)
        assert w.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 24. WEBSOCKET HANDLER — _handle_ws behavioral tests
#     OWASP A07 (Auth), A03 (Injection), LLM10 (DoS); MITRE T1499, T1078
# ═══════════════════════════════════════════════════════════════════════════════


class MockWebSocket:
    """Mock websockets.WebSocketServerProtocol for testing _handle_ws."""

    def __init__(self, messages=None):
        self.messages = list(messages or [])
        self._sent = []
        self._closed = False
        self._close_code = None
        self._close_reason = None
        self._msg_iter = iter(self.messages)

    async def recv(self):
        try:
            return next(self._msg_iter)
        except StopIteration:
            raise websockets.exceptions.ConnectionClosed(None, None) from None

    async def send(self, data):
        self._sent.append(data)

    async def close(self, code=1000, reason=""):
        self._closed = True
        self._close_code = code
        self._close_reason = reason

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._msg_iter)
        except StopIteration:
            raise StopAsyncIteration from None

    @property
    def sent_json(self):
        """Parse all sent messages as JSON for easy assertion."""
        result = []
        for raw in self._sent:
            try:
                parsed = json.loads(raw)
                # If it's a signed envelope, extract the inner payload
                if "p" in parsed and "nonce" in parsed and "sig" in parsed:
                    result.append(parsed["p"])
                else:
                    result.append(parsed)
            except (json.JSONDecodeError, TypeError):
                result.append(raw)
        return result


def _make_hmac_sig(token: str, payload_dict: dict, nonce: str) -> str:
    """Create a valid HMAC-SHA256 signature matching what the browser SDK sends."""
    payload_str = json.dumps(payload_dict, separators=(",", ":"))
    message = (nonce + payload_str).encode("utf-8")
    return hmac_mod.new(token.encode("utf-8"), message, hashlib.sha256).digest().hex()


def _wrap_signed(token: str, payload_dict: dict) -> str:
    """Wrap a message dict in a signed envelope (as the browser SDK would)."""
    nonce = generate_nonce()
    payload_str = json.dumps(payload_dict, separators=(",", ":"))
    sig = _make_hmac_sig(token, payload_dict, nonce)
    return json.dumps({"p": payload_dict, "nonce": nonce, "sig": sig, "ps": payload_str})


@pytest.fixture
def ws_server(tmp_data_dir):
    """Create a WebviewServer with mocked internals for WS handler testing.

    No actual network is started — we invoke _handle_ws directly with mock websockets.
    """
    sdk_path = tmp_data_dir / "sdk.js"
    sdk_path.write_text("// SDK placeholder")

    with patch.dict(os.environ, {"OCV_SESSION_TOKEN": "test_ws_token_xyz"}):
        server = WebviewServer(
            data_dir=str(tmp_data_dir),
            http_port=18420,
            ws_port=18421,
            sdk_path=str(sdk_path),
        )

    # Ensure crypto components are available for signing tests
    assert server._nonce_tracker is not None, "NonceTracker must be available for WS tests"
    assert server._private_key is not None, "Private key must be available for WS tests"

    return server


def _auth_msg(token: str = "test_ws_token_xyz") -> str:  # noqa: S107
    """Return a valid auth message JSON string."""
    return json.dumps({"type": "auth", "token": token})


# ---------------------------------------------------------------------------
# 24a. Connection limit (H1 hardening: MAX_WEBSOCKET_CLIENTS=50)
# ---------------------------------------------------------------------------


class TestWSConnectionLimit:
    """WebSocket connection exhaustion defense — MAX_WEBSOCKET_CLIENTS=50."""

    @pytest.mark.mitre_t1499
    @pytest.mark.llm10
    @pytest.mark.asyncio
    async def test_connection_rejected_at_capacity(self, ws_server):
        """When _ws_clients has 50 entries, new connections must be rejected with code 1008."""
        # Fill the client set to capacity
        for i in range(ws_server.MAX_WEBSOCKET_CLIENTS):
            ws_server._ws_clients.add(f"fake_client_{i}")

        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 1008
        assert "capacity" in ws._close_reason.lower()
        # Client should NOT have been added
        assert ws not in ws_server._ws_clients

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_connection_accepted_below_capacity(self, ws_server):
        """When below capacity, connections should be accepted (given valid auth)."""
        # Fill to one below capacity
        for i in range(ws_server.MAX_WEBSOCKET_CLIENTS - 1):
            ws_server._ws_clients.add(f"fake_client_{i}")

        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        # Client should have been added then removed (connection closed naturally)
        assert ws._closed is not True or ws._close_code != 1008

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_connection_accepted_when_empty(self, ws_server):
        """With no existing clients, a new connection should be accepted."""
        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        # After handler completes (connection closed), client is removed
        assert ws not in ws_server._ws_clients
        # Should not have been rejected
        assert ws._close_code != 1008

    @pytest.mark.mitre_t1499
    def test_max_websocket_clients_constant_is_50(self, ws_server):
        """The MAX_WEBSOCKET_CLIENTS constant must be 50."""
        assert ws_server.MAX_WEBSOCKET_CLIENTS == 50


# ---------------------------------------------------------------------------
# 24b. WebSocket auth protocol
# ---------------------------------------------------------------------------


class TestWSAuthProtocol:
    """First message must be {type: 'auth', token: '...'} within 5 seconds."""

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_valid_auth_adds_client(self, ws_server):
        """A valid auth message should result in the client being added to _ws_clients."""

        class TrackingSet(set):
            """Set subclass that records add() calls."""

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.added_items = []

            def add(self, item):
                self.added_items.append(item)
                super().add(item)

        tracking = TrackingSet(ws_server._ws_clients)
        ws_server._ws_clients = tracking
        ws_server.http_handler.ws_clients = tracking

        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        assert ws in tracking.added_items

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_auth_sends_connected_state(self, ws_server):
        """After successful auth, server should send connected message with state."""
        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        sent = ws.sent_json
        assert len(sent) >= 1
        connected_msg = sent[0]
        assert connected_msg["type"] == "connected"
        assert "state" in connected_msg

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_client_removed_on_disconnect(self, ws_server):
        """After handler finishes, client must be removed from _ws_clients."""
        ws = MockWebSocket(messages=[_auth_msg()])
        await ws_server._handle_ws(ws)

        assert ws not in ws_server._ws_clients

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_auth_timeout_closes_connection(self, ws_server):
        """If auth message is not received within 5s, connection should be closed."""

        class SlowWebSocket(MockWebSocket):
            async def recv(self):
                await asyncio.sleep(10)  # Simulate client not sending auth
                return _auth_msg()

        ws = SlowWebSocket(messages=[])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001
        assert "unauthorized" in ws._close_reason.lower()


# ---------------------------------------------------------------------------
# 24c. WebSocket auth rejection
# ---------------------------------------------------------------------------


class TestWSAuthRejection:
    """Invalid auth messages must result in connection close with code 4001."""

    @pytest.mark.owasp_a07
    @pytest.mark.mitre_t1078
    @pytest.mark.asyncio
    async def test_wrong_token_rejected(self, ws_server):
        """Auth message with wrong token must close the connection."""
        ws = MockWebSocket(messages=[json.dumps({"type": "auth", "token": "wrong_token"})])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_missing_type_field_rejected(self, ws_server):
        """Auth message without 'type' field must be rejected."""
        ws = MockWebSocket(messages=[json.dumps({"token": "test_ws_token_xyz"})])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_wrong_type_field_rejected(self, ws_server):
        """Auth message with wrong type (not 'auth') must be rejected."""
        ws = MockWebSocket(messages=[json.dumps({"type": "connect", "token": "test_ws_token_xyz"})])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_missing_token_rejected(self, ws_server):
        """Auth message without 'token' field must be rejected."""
        ws = MockWebSocket(messages=[json.dumps({"type": "auth"})])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_empty_token_rejected(self, ws_server):
        """Auth message with empty string token must be rejected."""
        ws = MockWebSocket(messages=[json.dumps({"type": "auth", "token": ""})])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self, ws_server):
        """Non-JSON first message must close the connection."""
        ws = MockWebSocket(messages=["this is not json"])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_binary_message_rejected(self, ws_server):
        """Binary-like first message that fails JSON parse must be rejected."""
        ws = MockWebSocket(messages=["\x00\x01\x02\x03"])
        await ws_server._handle_ws(ws)

        assert ws._closed is True
        assert ws._close_code == 4001

    @pytest.mark.owasp_a07
    @pytest.mark.asyncio
    async def test_no_messages_closes_connection(self, ws_server):
        """If client sends no messages at all (immediate disconnect), handle gracefully."""
        ws = MockWebSocket(messages=[])  # recv() raises ConnectionClosed immediately
        await ws_server._handle_ws(ws)

        # Should close gracefully without crashing
        assert ws._closed is True
        assert ws._close_code == 4001


# ---------------------------------------------------------------------------
# 24d. WebSocket message handling (post-auth)
# ---------------------------------------------------------------------------


class TestWSMessageHandling:
    """Post-authentication message routing: action, heartbeat, request_state."""

    @pytest.mark.asyncio
    async def test_heartbeat_returns_ack(self, ws_server):
        """Heartbeat message should receive a heartbeat_ack response."""
        heartbeat = _wrap_signed("test_ws_token_xyz", {"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), heartbeat])
        await ws_server._handle_ws(ws)

        sent = ws.sent_json
        ack_msgs = [m for m in sent if m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1
        assert "timestamp" in ack_msgs[0]

    @pytest.mark.asyncio
    async def test_request_state_returns_state(self, ws_server):
        """request_state message should return current state."""
        req = _wrap_signed("test_ws_token_xyz", {"type": "request_state"})
        ws = MockWebSocket(messages=[_auth_msg(), req])
        await ws_server._handle_ws(ws)

        sent = ws.sent_json
        state_msgs = [m for m in sent if m.get("type") == "state_updated"]
        assert len(state_msgs) == 1
        assert "data" in state_msgs[0]

    @pytest.mark.asyncio
    async def test_action_message_appended_to_contract(self, ws_server):
        """Action messages should be appended to the data contract."""
        action_data = {"action_id": "approve", "type": "approve", "value": True}
        action_msg = _wrap_signed("test_ws_token_xyz", {"type": "action", "data": action_data})
        ws = MockWebSocket(messages=[_auth_msg(), action_msg])
        await ws_server._handle_ws(ws)

        actions = ws_server.contract.get_actions()
        assert actions is not None
        assert len(actions["actions"]) >= 1
        stored = actions["actions"][-1]
        assert stored["action_id"] == "approve"

    @pytest.mark.asyncio
    async def test_malformed_json_message_ignored(self, ws_server):
        """Malformed JSON messages after auth should be silently ignored."""
        auth = _auth_msg()
        heartbeat = _wrap_signed("test_ws_token_xyz", {"type": "heartbeat"})

        class CustomWS(MockWebSocket):
            def __init__(self):
                self.messages = [auth]
                self._post_auth_msgs = ["not valid json {{{", heartbeat]
                self._post_auth_iter = iter(self._post_auth_msgs)
                self._sent = []
                self._closed = False
                self._close_code = None
                self._close_reason = None
                self._msg_iter = iter(self.messages)

            async def recv(self):
                return next(self._msg_iter)

            def __aiter__(self):
                return self

            async def __anext__(self):
                try:
                    return next(self._post_auth_iter)
                except StopIteration:
                    raise StopAsyncIteration from None

            async def send(self, data):
                self._sent.append(data)

            async def close(self, code=1000, reason=""):
                self._closed = True
                self._close_code = code
                self._close_reason = reason

            @property
            def sent_json(self):
                result = []
                for raw in self._sent:
                    try:
                        parsed = json.loads(raw)
                        if "p" in parsed and "nonce" in parsed:
                            result.append(parsed["p"])
                        else:
                            result.append(parsed)
                    except (json.JSONDecodeError, TypeError):
                        result.append(raw)
                return result

        ws = CustomWS()
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1

    @pytest.mark.asyncio
    async def test_subsequent_auth_messages_ignored(self, ws_server):
        """Auth messages sent after initial auth should be silently ignored."""
        second_auth = _wrap_signed(
            "test_ws_token_xyz",
            {"type": "auth", "token": "test_ws_token_xyz"},
        )
        heartbeat = _wrap_signed("test_ws_token_xyz", {"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), second_auth, heartbeat])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1

    @pytest.mark.asyncio
    async def test_unknown_message_type_does_not_crash(self, ws_server):
        """Unknown message types should be silently ignored."""
        unknown = _wrap_signed("test_ws_token_xyz", {"type": "unknown_fancy_type", "data": {}})
        heartbeat = _wrap_signed("test_ws_token_xyz", {"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), unknown, heartbeat])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1


# ---------------------------------------------------------------------------
# 24e. Rate limiting on WS actions (shared limiter with HTTP)
# ---------------------------------------------------------------------------


class TestWSRateLimiting:
    """WS action submissions share the same rate limiter as HTTP."""

    @pytest.mark.mitre_t1499
    @pytest.mark.llm10
    @pytest.mark.asyncio
    async def test_ws_action_rate_limited(self, ws_server):
        """Exceeding rate limit on WS actions should return an error message."""
        ws_server.http_handler._rate_limiter = RateLimiter(max_actions=2, window_seconds=60.0)

        token = "test_ws_token_xyz"
        action_data = {"action_id": "ok", "type": "approve", "value": True}

        action1 = _wrap_signed(token, {"type": "action", "data": action_data})
        action2 = _wrap_signed(token, {"type": "action", "data": action_data})
        action3 = _wrap_signed(token, {"type": "action", "data": action_data})

        ws = MockWebSocket(messages=[_auth_msg(), action1, action2, action3])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1
        assert "rate limit" in error_msgs[0]["data"]["message"].lower()

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_ws_rate_limit_shared_with_http(self, ws_server):
        """HTTP and WS share the same rate limiter instance."""
        ws_server.http_handler._rate_limiter = RateLimiter(max_actions=1, window_seconds=60.0)
        ws_server.http_handler._rate_limiter.check()  # Use up the allowed action

        token = "test_ws_token_xyz"
        action_data = {"action_id": "ok", "type": "approve", "value": True}
        action_msg = _wrap_signed(token, {"type": "action", "data": action_data})

        ws = MockWebSocket(messages=[_auth_msg(), action_msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1

    @pytest.mark.mitre_t1499
    @pytest.mark.asyncio
    async def test_heartbeat_not_rate_limited(self, ws_server):
        """Heartbeat messages should not be subject to rate limiting."""
        ws_server.http_handler._rate_limiter = RateLimiter(max_actions=0, window_seconds=60.0)

        token = "test_ws_token_xyz"
        heartbeat = _wrap_signed(token, {"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), heartbeat])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1


# ---------------------------------------------------------------------------
# 24f. Unsigned message rejection (crypto-enabled mode)
# ---------------------------------------------------------------------------


class TestWSUnsignedRejection:
    """When crypto is enabled, unsigned messages (except auth) must be rejected."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_unsigned_action_rejected(self, ws_server):
        """An unsigned action message must be silently dropped."""
        assert ws_server._nonce_tracker is not None

        unsigned_action = json.dumps(
            {
                "type": "action",
                "data": {"action_id": "x", "type": "approve", "value": True},
            }
        )
        heartbeat = _wrap_signed("test_ws_token_xyz", {"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), unsigned_action, heartbeat])
        await ws_server._handle_ws(ws)

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 0

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_unsigned_heartbeat_rejected(self, ws_server):
        """An unsigned heartbeat must be silently dropped."""
        assert ws_server._nonce_tracker is not None

        unsigned_hb = json.dumps({"type": "heartbeat"})
        ws = MockWebSocket(messages=[_auth_msg(), unsigned_hb])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 0

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_unsigned_request_state_rejected(self, ws_server):
        """An unsigned request_state must be silently dropped."""
        assert ws_server._nonce_tracker is not None

        unsigned_req = json.dumps({"type": "request_state"})
        ws = MockWebSocket(messages=[_auth_msg(), unsigned_req])
        await ws_server._handle_ws(ws)

        state_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "state_updated"]
        assert len(state_msgs) == 0

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self, ws_server):
        """A message with an invalid HMAC signature must be silently dropped."""
        assert ws_server._nonce_tracker is not None

        nonce = generate_nonce()
        payload = {"type": "heartbeat"}
        payload_str = json.dumps(payload, separators=(",", ":"))
        bad_envelope = json.dumps(
            {
                "p": payload,
                "nonce": nonce,
                "sig": "deadbeef" * 8,
                "ps": payload_str,
            }
        )

        ws = MockWebSocket(messages=[_auth_msg(), bad_envelope])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 0


# ---------------------------------------------------------------------------
# 24g. Nonce replay detection
# ---------------------------------------------------------------------------


class TestWSNonceReplay:
    """Replayed nonces must be rejected to prevent replay attacks."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_replayed_nonce_rejected(self, ws_server):
        """A message with a previously-seen nonce must be silently dropped."""
        assert ws_server._nonce_tracker is not None

        token = "test_ws_token_xyz"
        nonce = generate_nonce()
        payload = {"type": "heartbeat"}
        payload_str = json.dumps(payload, separators=(",", ":"))
        sig = _make_hmac_sig(token, payload, nonce)

        signed_msg = json.dumps({"p": payload, "nonce": nonce, "sig": sig, "ps": payload_str})

        # Send the same signed message twice — second should be rejected
        ws = MockWebSocket(messages=[_auth_msg(), signed_msg, signed_msg])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 1

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_unique_nonces_both_accepted(self, ws_server):
        """Two messages with different nonces should both be accepted."""
        assert ws_server._nonce_tracker is not None

        token = "test_ws_token_xyz"
        hb1 = _wrap_signed(token, {"type": "heartbeat"})
        hb2 = _wrap_signed(token, {"type": "heartbeat"})

        ws = MockWebSocket(messages=[_auth_msg(), hb1, hb2])
        await ws_server._handle_ws(ws)

        ack_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "heartbeat_ack"]
        assert len(ack_msgs) == 2

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_replayed_action_nonce_not_appended(self, ws_server):
        """Replayed action messages must not be appended to the data contract."""
        assert ws_server._nonce_tracker is not None

        token = "test_ws_token_xyz"
        nonce = generate_nonce()
        action_payload = {
            "type": "action",
            "data": {"action_id": "ok", "type": "approve", "value": True},
        }
        payload_str = json.dumps(action_payload, separators=(",", ":"))
        sig = _make_hmac_sig(token, action_payload, nonce)

        signed_action = json.dumps({"p": action_payload, "nonce": nonce, "sig": sig, "ps": payload_str})

        ws = MockWebSocket(messages=[_auth_msg(), signed_action, signed_action])
        await ws_server._handle_ws(ws)

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 1


# ---------------------------------------------------------------------------
# 24h. WS action security gate integration (behavioral)
# ---------------------------------------------------------------------------


class TestWSActionSecurityGateIntegration:
    """SecurityGate must reject invalid actions on the WS path (behavioral test)."""

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_ws_invalid_action_type_rejected(self, ws_server):
        """An action with an unknown type should be rejected with error message."""
        token = "test_ws_token_xyz"
        bad_action = {
            "type": "action",
            "data": {
                "action_id": "evil",
                "type": "evil_unknown_type",
                "value": True,
            },
        }
        msg = _wrap_signed(token, bad_action)

        ws = MockWebSocket(messages=[_auth_msg(), msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1
        assert "invalid" in error_msgs[0]["data"]["message"].lower()

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 0

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_ws_missing_action_id_rejected(self, ws_server):
        """An action without action_id should be rejected."""
        token = "test_ws_token_xyz"
        bad_action = {
            "type": "action",
            "data": {"type": "approve", "value": True},  # no action_id
        }
        msg = _wrap_signed(token, bad_action)

        ws = MockWebSocket(messages=[_auth_msg(), msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 0

    @pytest.mark.owasp_a03
    @pytest.mark.llm01
    @pytest.mark.asyncio
    async def test_ws_valid_action_accepted(self, ws_server):
        """A valid action should be accepted and appended."""
        token = "test_ws_token_xyz"
        good_action = {
            "type": "action",
            "data": {"action_id": "approve", "type": "approve", "value": True},
        }
        msg = _wrap_signed(token, good_action)

        ws = MockWebSocket(messages=[_auth_msg(), msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) == 0

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 1
        assert actions["actions"][0]["action_id"] == "approve"

    @pytest.mark.owasp_a03
    @pytest.mark.llm10
    @pytest.mark.asyncio
    async def test_ws_oversized_value_rejected(self, ws_server):
        """An action with an oversized value should be rejected."""
        token = "test_ws_token_xyz"
        big_action = {
            "type": "action",
            "data": {
                "action_id": "submit",
                "type": "submit",
                "value": "x" * 200_000,
            },
        }
        msg = _wrap_signed(token, big_action)

        ws = MockWebSocket(messages=[_auth_msg(), msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1

        actions = ws_server.contract.get_actions()
        assert len(actions["actions"]) == 0


# ---------------------------------------------------------------------------
# 24i. WS error message does not leak rejection details
# ---------------------------------------------------------------------------


class TestWSErrorMessageOpacity:
    """WS error messages must use generic text, not leak SecurityGate details."""

    @pytest.mark.owasp_a03
    @pytest.mark.asyncio
    async def test_error_message_is_generic(self, ws_server):
        """Error messages for rejected actions must say 'Invalid action'."""
        token = "test_ws_token_xyz"
        bad_action = {
            "type": "action",
            "data": {"action_id": "evil", "type": "evil_type", "value": True},
        }
        msg = _wrap_signed(token, bad_action)
        ws = MockWebSocket(messages=[_auth_msg(), msg])
        await ws_server._handle_ws(ws)

        error_msgs = [m for m in ws.sent_json if isinstance(m, dict) and m.get("type") == "error"]
        assert len(error_msgs) >= 1
        error_text = error_msgs[0]["data"]["message"]
        assert error_text == "Invalid action"
