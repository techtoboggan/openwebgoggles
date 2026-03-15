"""Tests for webhook notification system."""

from __future__ import annotations

import json
import os
import sys
from unittest import mock


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from webhook import WebhookNotifier, _RATE_WINDOW


# ---------------------------------------------------------------------------
# Enabled / disabled
# ---------------------------------------------------------------------------


class TestWebhookEnabled:
    def test_disabled_when_no_env(self, monkeypatch):
        monkeypatch.delenv("OWG_WEBHOOK_URL", raising=False)
        notifier = WebhookNotifier()
        assert not notifier.enabled

    def test_enabled_when_url_set(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()
        assert notifier.enabled

    def test_disabled_no_op(self, monkeypatch):
        monkeypatch.delenv("OWG_WEBHOOK_URL", raising=False)
        notifier = WebhookNotifier()
        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="test")
            mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


class TestProviderDetection:
    def test_slack_detection(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/xxx")
        notifier = WebhookNotifier()
        assert notifier._provider == "slack"

    def test_discord_detection(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://discord.com/api/webhooks/123/abc")
        notifier = WebhookNotifier()
        assert notifier._provider == "discord"

    def test_generic_detection(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/webhook")
        notifier = WebhookNotifier()
        assert notifier._provider == "generic"


# ---------------------------------------------------------------------------
# Payload format
# ---------------------------------------------------------------------------


class TestPayloadFormat:
    def test_slack_payload(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/xxx")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="Deploy Review", status="pending")
            # Wait for daemon thread
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            call_args = mock_urlopen.call_args
            req = call_args[0][0]
            body = json.loads(req.data)
            assert "text" in body
            assert "Deploy Review" in body["text"]

    def test_discord_payload(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://discord.com/api/webhooks/123/abc")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="Test", status="waiting")
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            body = json.loads(mock_urlopen.call_args[0][0].data)
            assert "content" in body

    def test_generic_payload(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="T", status="S", url="http://localhost:18420", session="main")
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            body = json.loads(mock_urlopen.call_args[0][0].data)
            assert body["title"] == "T"
            assert body["status"] == "S"
            assert body["url"] == "http://localhost:18420"
            assert body["session"] == "main"
            assert "timestamp" in body
            assert "text" in body


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------


class TestTemplate:
    def test_default_template(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/xxx")
        monkeypatch.delenv("OWG_WEBHOOK_TEMPLATE", raising=False)
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="My Title", status="pending", url="http://localhost")
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            body = json.loads(mock_urlopen.call_args[0][0].data)
            assert "My Title" in body["text"]
            assert "pending" in body["text"]

    def test_custom_template(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/xxx")
        monkeypatch.setenv("OWG_WEBHOOK_TEMPLATE", "Action needed: {title} [{status}]")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="Deploy", status="waiting")
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            body = json.loads(mock_urlopen.call_args[0][0].data)
            assert body["text"] == "Action needed: Deploy [waiting]"

    def test_template_missing_keys(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/xxx")
        monkeypatch.setenv("OWG_WEBHOOK_TEMPLATE", "Hello {title} {nonexistent}")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier.notify(title="X")
            import threading

            for t in threading.enumerate():
                if t.daemon and t.is_alive():
                    t.join(timeout=2)

            body = json.loads(mock_urlopen.call_args[0][0].data)
            assert body["text"] == "Hello X "


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_rate_limit_per_session(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen"):
            with mock.patch("webhook.threading.Thread") as mock_thread:
                notifier.notify(title="first", session="a")
                assert mock_thread.call_count == 1

                # Second call within rate window — suppressed
                notifier.notify(title="second", session="a")
                assert mock_thread.call_count == 1

                # Different session — allowed
                notifier.notify(title="third", session="b")
                assert mock_thread.call_count == 2

    def test_rate_limit_expires(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.threading.Thread") as mock_thread:
            with mock.patch("webhook.time.monotonic", return_value=1000.0):
                notifier.notify(title="first", session="a")
                assert mock_thread.call_count == 1

            # Advance past rate window
            with mock.patch("webhook.time.monotonic", return_value=1000.0 + _RATE_WINDOW + 1):
                notifier.notify(title="second", session="a")
                assert mock_thread.call_count == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_failure_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen", side_effect=Exception("network error")):
            # _send should catch and log, not raise
            notifier._send(b'{"text": "test"}')

    def test_non_blocking(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.threading.Thread") as mock_thread:
            mock_instance = mock.Mock()
            mock_thread.return_value = mock_instance

            notifier.notify(title="test")

            mock_thread.assert_called_once()
            assert mock_thread.call_args[1]["daemon"] is True
            mock_instance.start.assert_called_once()

    def test_request_timeout(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.urllib.request.urlopen") as mock_urlopen:
            notifier._send(b'{"text": "test"}')
            # Verify timeout=10 is passed
            assert mock_urlopen.call_args[1]["timeout"] == 10


# ---------------------------------------------------------------------------
# Session cap
# ---------------------------------------------------------------------------


class TestSessionCap:
    def test_caps_session_tracking(self, monkeypatch):
        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.threading.Thread"):
            for i in range(110):
                notifier.notify(title=f"test-{i}", session=f"session-{i}")

        # Should never exceed 101 (100 cap + 1 for the new entry before eviction)
        assert len(notifier._last_sent) <= 101
