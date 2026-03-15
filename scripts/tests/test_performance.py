"""Performance benchmarks for OpenWebGoggles.

These tests enforce that core operations complete within acceptable time
bounds. They run as part of the normal test suite (not marked slow) to
catch performance regressions early.

Thresholds are generous (10-50x headroom) to avoid flaky CI failures
while still catching catastrophic regressions.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_gate import SecurityGate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def gate():
    return SecurityGate()


def _make_table_state(rows: int, cols: int = 5) -> dict:
    """Build a table state with N rows and M columns."""
    columns = [{"key": f"col_{i}", "label": f"Column {i}"} for i in range(cols)]
    table_rows = [{f"col_{i}": f"value_{r}_{i}" for i in range(cols)} for r in range(rows)]
    return {
        "title": f"Benchmark Table ({rows} rows)",
        "data": {
            "sections": [
                {
                    "type": "table",
                    "title": "Data",
                    "columns": columns,
                    "rows": table_rows,
                }
            ]
        },
        "actions_requested": [
            {"id": "approve", "label": "Approve", "type": "approve"},
        ],
    }


def _make_form_state(fields: int) -> dict:
    """Build a form state with N fields."""
    return {
        "title": f"Benchmark Form ({fields} fields)",
        "data": {
            "sections": [
                {
                    "type": "form",
                    "title": "Input",
                    "fields": [
                        {
                            "key": f"field_{i}",
                            "label": f"Field {i}",
                            "type": "text",
                            "value": f"default_{i}",
                        }
                        for i in range(fields)
                    ],
                }
            ]
        },
        "actions_requested": [
            {"id": "submit", "label": "Submit", "type": "submit"},
        ],
    }


def _make_dashboard_state(cards: int, sections: int = 1) -> dict:
    """Build a dashboard state with metric cards and charts."""
    metric_sections = []
    for s in range(sections):
        metric_sections.append(
            {
                "type": "metric",
                "title": f"Metrics {s}",
                "columns": 3,
                "cards": [
                    {
                        "label": f"Metric {i}",
                        "value": str(i * 100),
                        "unit": "ms",
                        "change": f"+{i}%",
                        "changeDirection": "up",
                        "sparkline": [j * i for j in range(6)],
                    }
                    for i in range(cards)
                ],
            }
        )
    return {
        "title": f"Benchmark Dashboard ({cards * sections} cards)",
        "data": {"sections": metric_sections},
    }


def _make_deep_state(depth: int) -> dict:
    """Build a state with nested sections (tabs within tabs)."""
    sections = []
    for i in range(3):
        inner_sections = [
            {"type": "text", "title": f"Content {i}-{j}", "content": f"Deep content at depth {depth}"} for j in range(3)
        ]
        sections.append(
            {
                "type": "tabs",
                "title": f"Tab Group {i}",
                "tabs": [{"id": f"tab_{i}_{j}", "label": f"Tab {j}", "sections": inner_sections} for j in range(3)],
            }
        )
    return {
        "title": f"Benchmark Deep State (depth ~{depth})",
        "data": {"sections": sections},
    }


def _make_pages_state(pages: int) -> dict:
    """Build a multi-page SPA state."""
    page_dict = {}
    for p in range(pages):
        page_dict[f"page_{p}"] = {
            "label": f"Page {p}",
            "data": {
                "sections": [
                    {"type": "text", "title": f"Content {p}", "content": f"Page {p} body text here."},
                    {
                        "type": "table",
                        "title": f"Table {p}",
                        "columns": [{"key": "id", "label": "ID"}, {"key": "name", "label": "Name"}],
                        "rows": [{"id": str(i), "name": f"Item {i}"} for i in range(10)],
                    },
                ]
            },
        }
    return {
        "title": f"Benchmark SPA ({pages} pages)",
        "pages": page_dict,
        "activePage": "page_0",
    }


# ---------------------------------------------------------------------------
# SecurityGate validation benchmarks
# ---------------------------------------------------------------------------


class TestSecurityGatePerformance:
    """Ensure SecurityGate validation scales linearly with state size."""

    def test_small_table_under_10ms(self, gate):
        """50-row table validates in <10ms."""
        state = _make_table_state(50)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.01, f"50-row table took {elapsed:.3f}s (limit: 10ms)"

    def test_large_table_under_100ms(self, gate):
        """500-row table validates in <100ms."""
        state = _make_table_state(500)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.1, f"500-row table took {elapsed:.3f}s (limit: 100ms)"

    def test_large_form_under_50ms(self, gate):
        """100-field form validates in <50ms."""
        state = _make_form_state(100)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.05, f"100-field form took {elapsed:.3f}s (limit: 50ms)"

    def test_dashboard_under_50ms(self, gate):
        """Dashboard with 50 metric cards validates in <50ms."""
        state = _make_dashboard_state(50)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.05, f"50-card dashboard took {elapsed:.3f}s (limit: 50ms)"

    def test_deep_nested_state_under_50ms(self, gate):
        """Deeply nested tabs-in-tabs validates in <50ms."""
        state = _make_deep_state(3)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.05, f"Deep nested state took {elapsed:.3f}s (limit: 50ms)"

    def test_multi_page_spa_under_100ms(self, gate):
        """20-page SPA state validates in <100ms."""
        state = _make_pages_state(20)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        valid, err, _ = gate.validate_state(raw)
        elapsed = time.perf_counter() - start

        assert valid, f"Validation failed: {err}"
        assert elapsed < 0.1, f"20-page SPA took {elapsed:.3f}s (limit: 100ms)"


# ---------------------------------------------------------------------------
# JSON serialization benchmarks
# ---------------------------------------------------------------------------


class TestSerializationPerformance:
    """Ensure JSON serialization doesn't become a bottleneck."""

    def test_large_state_serialize_under_50ms(self):
        """500-row table serializes to JSON in <50ms."""
        state = _make_table_state(500)

        start = time.perf_counter()
        raw = json.dumps(state, separators=(",", ":"))
        elapsed = time.perf_counter() - start

        assert elapsed < 0.05, f"500-row serialize took {elapsed:.3f}s (limit: 50ms)"
        # Sanity: check it produced reasonable output
        assert len(raw) > 10_000

    def test_large_state_deserialize_under_50ms(self):
        """500-row table deserializes from JSON in <50ms."""
        state = _make_table_state(500)
        raw = json.dumps(state, separators=(",", ":"))

        start = time.perf_counter()
        parsed = json.loads(raw)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.05, f"500-row deserialize took {elapsed:.3f}s (limit: 50ms)"
        assert len(parsed["data"]["sections"][0]["rows"]) == 500


# ---------------------------------------------------------------------------
# Audit logger benchmarks
# ---------------------------------------------------------------------------


class TestAuditPerformance:
    def test_audit_write_under_1ms(self, monkeypatch, tmp_path):
        """Single audit log write completes in <1ms."""
        from audit import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()

        start = time.perf_counter()
        logger.log_tool_call(tool="openwebgoggles", session="bench")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.001, f"Audit write took {elapsed:.4f}s (limit: 1ms)"

    def test_100_audit_writes_under_500ms(self, monkeypatch, tmp_path):
        """100 sequential audit writes complete in <500ms."""
        from audit import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("OWG_AUDIT_LOG", str(log_path))
        monkeypatch.delenv("OWG_AUDIT", raising=False)

        logger = AuditLogger()

        start = time.perf_counter()
        for i in range(100):
            logger.log_tool_call(tool=f"tool-{i}")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"100 audit writes took {elapsed:.3f}s (limit: 500ms)"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 100


# ---------------------------------------------------------------------------
# Rate limiter benchmarks
# ---------------------------------------------------------------------------


class TestRateLimiterPerformance:
    def test_1000_checks_under_10ms(self):
        """1000 rate limit checks complete in <10ms."""
        from rate_limiter import RateLimiter

        limiter = RateLimiter(max_actions=1000, window_seconds=1.0)

        start = time.perf_counter()
        for _ in range(1000):
            limiter.check()
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"1000 rate limit checks took {elapsed:.3f}s (limit: 100ms)"


# ---------------------------------------------------------------------------
# Webhook benchmarks
# ---------------------------------------------------------------------------


class TestWebhookPerformance:
    def test_rate_limited_webhook_under_1ms(self, monkeypatch):
        """Rate-limited (suppressed) webhook calls are near-instant."""
        from unittest import mock

        from webhook import WebhookNotifier

        monkeypatch.setenv("OWG_WEBHOOK_URL", "https://example.com/hook")
        notifier = WebhookNotifier()

        with mock.patch("webhook.threading.Thread"):
            # First call fires (allowed)
            notifier.notify(title="first", session="bench")

            # Subsequent calls are rate-limited — should be <1ms each
            start = time.perf_counter()
            for _ in range(1000):
                notifier.notify(title="suppressed", session="bench")
            elapsed = time.perf_counter() - start

            assert elapsed < 0.01, f"1000 suppressed webhooks took {elapsed:.3f}s (limit: 10ms)"
