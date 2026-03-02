"""
Shared fixtures for the openwebgoggles security test suite.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

# Ensure the scripts directory and tests directory are on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    NonceTracker,
    generate_session_keys,
)
from security_gate import SecurityGate


@pytest.fixture
def gate():
    """Fresh SecurityGate instance."""
    return SecurityGate()


@pytest.fixture
def session_keys():
    """Ephemeral Ed25519 session keypair."""
    private_key, public_hex, verify_hex = generate_session_keys()
    return private_key, public_hex, verify_hex


@pytest.fixture
def nonce_tracker():
    """Fresh NonceTracker with default 300s window."""
    return NonceTracker(window_seconds=300)


@pytest.fixture
def session_token():
    """Random 32-byte hex session token."""
    return os.urandom(32).hex()


# ---------------------------------------------------------------------------
# Playwright E2E fixtures (only loaded when playwright is installed)
# Uses SYNC Playwright API to avoid async event loop scoping issues.
# ---------------------------------------------------------------------------

try:
    from playwright.sync_api import sync_playwright  # noqa: F401

    _HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    _HAS_PLAYWRIGHT = False

if _HAS_PLAYWRIGHT:
    import asyncio
    import threading

    from mcp_server import WebviewSession  # noqa: I001

    # Shared across all E2E tests in a single pytest run — avoids restarting
    # the subprocess for every test function (saves ~3s per test).
    _shared_session: WebviewSession | None = None
    _shared_browser = None
    _shared_pw = None

    def _run_async(coro):
        """Run an async coroutine in a separate thread to avoid event loop conflicts.

        pytest-asyncio keeps an event loop running on the main thread, so
        ``loop.run_until_complete`` would raise *RuntimeError: Cannot run the
        event loop while another loop is running*.  By executing in a
        dedicated thread we get our own pristine event loop.
        """
        result = None
        exception = None

        def _target():
            nonlocal result, exception
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(coro)
            except Exception as exc:  # noqa: BLE001
                exception = exc
            finally:
                loop.close()

        thread = threading.Thread(target=_target)
        thread.start()
        thread.join()
        if exception:
            raise exception
        return result

    @pytest.fixture
    def webview_session(tmp_path_factory):
        """Return the shared WebviewSession (started once, reused)."""
        global _shared_session  # noqa: PLW0603
        if _shared_session is None or not _shared_session.is_alive():
            tmp_dir = tmp_path_factory.mktemp("e2e")
            _shared_session = WebviewSession(work_dir=tmp_dir, open_browser=False)
            _run_async(_shared_session.ensure_started(app="dynamic"))
        return _shared_session

    @pytest.fixture
    def playwright_browser():
        """Return the shared headless Chromium browser (sync API)."""
        global _shared_browser, _shared_pw  # noqa: PLW0603
        if _shared_browser is None or not _shared_browser.is_connected():
            _shared_pw = sync_playwright().start()
            _shared_browser = _shared_pw.chromium.launch(headless=True)
        return _shared_browser

    @pytest.fixture
    def e2e_page(playwright_browser, webview_session):
        """Fresh browser page navigated to the webview URL."""
        context = playwright_browser.new_context()
        pg = context.new_page()
        pg.goto(webview_session.url)
        # Wait for the app to connect (connection dot turns green)
        pg.wait_for_selector("#conn-dot.on", timeout=10000)
        yield pg
        context.close()


def wait_for_title(page, title, timeout=5000):
    """Wait until the header title matches the expected text.

    Each test sets a unique ``title`` in the state payload.  Because the
    server reuses the same session, the DOM may still contain elements from
    the *previous* test's state.  Waiting for the title to update guarantees
    the new state has been rendered before any assertions run.
    """
    page.wait_for_function(
        "(t) => document.getElementById('hdr-title')?.textContent?.includes(t)",
        arg=title,
        timeout=timeout,
    )


def write_and_wait(session, page, state, selector, timeout=5000):
    """Write state to the webview session, wait for title sync, then selector."""
    session.write_state(state)
    title = state.get("title", "")
    if title:
        wait_for_title(page, title, timeout)
    page.wait_for_selector(selector, timeout=timeout)


def read_actions_with_retry(session, retries=6, delay=0.5):
    """Poll actions.json until non-empty, with retries."""
    for _ in range(retries):
        data = session.read_actions()
        actions = data.get("actions", [])
        if actions:
            return actions
        time.sleep(delay)
    return []  # pragma: no cover


def clear_and_write(session, page, state, timeout=5000):
    """Clear actions, write new state, and wait for state to propagate.

    Uses the title in *state* to synchronise — ensures the new state has
    been rendered before the calling test interacts with the DOM.
    """
    actions_path = session.data_dir / "actions.json"
    actions_path.write_text(json.dumps({"version": 0, "actions": []}))
    session.write_state(state)
    title = state.get("title", "")
    if title:
        wait_for_title(page, title, timeout)
