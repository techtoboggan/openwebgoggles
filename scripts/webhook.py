"""
Webhook notification for HITL decisions.

Fires a non-blocking HTTP POST when an agent is waiting for human input.
Configuration via environment variables:
  OWG_WEBHOOK_URL      — Webhook endpoint (Slack, Discord, or generic HTTP)
  OWG_WEBHOOK_TEMPLATE — Message template with {title}, {status}, {url} placeholders
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlparse

logger = logging.getLogger("openwebgoggles.webhook")

_DEFAULT_TEMPLATE = "OpenWebGoggles: {title} — {status} — {url}"

# Rate limit: 1 notification per 60 seconds per session
_RATE_WINDOW = 60.0

# Allowed URL schemes for webhook endpoints (prevents file:// SSRF, etc.)
_ALLOWED_SCHEMES = frozenset({"https", "http"})


def _validate_webhook_url(url: str) -> str | None:
    """Validate webhook URL against SSRF. Returns error message or None if valid."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except Exception:
        return f"Invalid webhook URL: {url!r}"
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f"Webhook URL scheme must be http or https, got: {parsed.scheme!r}"
    if not parsed.hostname:
        return f"Webhook URL missing hostname: {url!r}"
    # Block cloud metadata endpoints (169.254.x.x link-local)
    if parsed.hostname.startswith("169.254."):
        return f"Webhook URL targets link-local address (possible SSRF): {parsed.hostname}"
    return None


class _SafeDict(defaultdict):
    """Dict that returns empty string for missing keys in str.format_map."""

    def __missing__(self, key: str) -> str:
        return ""


class WebhookNotifier:
    """Fire-and-forget webhook notifications for pending HITL decisions."""

    def __init__(self) -> None:
        raw_url = os.environ.get("OWG_WEBHOOK_URL", "").strip()
        err = _validate_webhook_url(raw_url)
        if err:
            logger.warning("Webhook disabled: %s", err)
            self._url = ""
        else:
            self._url = raw_url
        self._template = os.environ.get("OWG_WEBHOOK_TEMPLATE", "").strip() or _DEFAULT_TEMPLATE
        self._provider = self._detect_provider(self._url)
        self._last_sent: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        """True if a webhook URL is configured."""
        return bool(self._url)

    @staticmethod
    def _detect_provider(url: str) -> str:
        """Detect webhook provider from URL."""
        if "hooks.slack.com" in url:
            return "slack"
        if "discord.com/api/webhooks" in url:
            return "discord"
        return "generic"

    def notify(
        self,
        title: str = "",
        status: str = "",
        url: str = "",
        session: str = "default",
    ) -> None:
        """Send a webhook notification (non-blocking).

        Rate-limited to 1 per minute per session. Failures are logged, never raised.
        """
        if not self.enabled:
            return

        # Per-session rate limit
        now = time.monotonic()
        last = self._last_sent.get(session, 0.0)
        if now - last < _RATE_WINDOW:
            logger.debug("Webhook rate-limited for session %r", session)
            return
        self._last_sent[session] = now

        # Cap session tracking to prevent unbounded growth
        if len(self._last_sent) > 100:  # noqa: PLR2004
            oldest = min(self._last_sent, key=self._last_sent.get)  # type: ignore[arg-type]
            del self._last_sent[oldest]

        # Format message
        values = _SafeDict(str, title=title, status=status, url=url, session=session)
        message = self._template.format_map(values)

        # Build provider-specific payload
        if self._provider == "slack":
            body = json.dumps({"text": message}).encode()
        elif self._provider == "discord":
            body = json.dumps({"content": message}).encode()
        else:
            body = json.dumps(
                {
                    "text": message,
                    "title": title,
                    "status": status,
                    "url": url,
                    "session": session,
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                }
            ).encode()

        # Fire in background thread (daemon so it doesn't block shutdown)
        thread = threading.Thread(target=self._send, args=(body,), daemon=True)
        thread.start()

    def _send(self, body: bytes) -> None:
        """POST the webhook payload. Errors are logged, never raised."""
        try:
            req = urllib.request.Request(  # noqa: S310
                self._url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
        except Exception:
            logger.warning("Webhook POST failed", exc_info=True)
