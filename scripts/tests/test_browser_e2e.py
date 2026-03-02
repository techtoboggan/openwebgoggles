"""
Playwright E2E browser tests for the OpenWebGoggles dynamic renderer.

These tests start a real WebviewSession subprocess, connect a headless
Chromium browser, and verify that every section type, SPA navigation
feature, form interaction, and chart type renders correctly.

Requires: pip install pytest-playwright && playwright install chromium
Run: python -m pytest scripts/tests/test_browser_e2e.py -v -m slow
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from playwright.sync_api import sync_playwright  # noqa: F401

    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

# Skip the entire module if playwright is not installed
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not _HAS_PLAYWRIGHT, reason="playwright not installed"),
]

# Import helpers from conftest (available when playwright is installed)
if _HAS_PLAYWRIGHT:
    from conftest import clear_and_write, read_actions_with_retry, write_and_wait


# =============================================================================
# Section Rendering Tests
# =============================================================================


class TestTextSection:
    """Verify text section rendering."""

    def test_plain_text(self, e2e_page, webview_session):
        """Plain text content renders inside a section."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Text Test",
                "data": {"sections": [{"type": "text", "title": "Greeting", "content": "Hello World"}]},
            },
            ".section",
        )
        text = e2e_page.locator(".section").first.inner_text()
        assert "Hello World" in text

    def test_markdown_text(self, e2e_page, webview_session):
        """Markdown text renders HTML tags (e.g. strong)."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "MD Test",
                "data": {"sections": [{"type": "text", "format": "markdown", "content": "**bold** text"}]},
            },
            ".section strong",
        )
        bold = e2e_page.locator(".section strong").first.inner_text()
        assert "bold" in bold


class TestFormSection:
    """Verify form field rendering."""

    def test_text_input(self, e2e_page, webview_session):
        """Text input renders with correct pre-populated value."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Form Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "name", "label": "Name", "type": "text", "value": "Alice"}],
                        }
                    ]
                },
            },
            'input[data-field-key="name"]',
        )
        val = e2e_page.locator('input[data-field-key="name"]').input_value()
        assert val == "Alice"

    def test_select_options(self, e2e_page, webview_session):
        """Select field renders all options."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Select Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "color",
                                    "label": "Color",
                                    "type": "select",
                                    "options": ["Red", "Green", "Blue"],
                                }
                            ],
                        }
                    ]
                },
            },
            'select[data-field-key="color"]',
        )
        count = e2e_page.locator('select[data-field-key="color"] option').count()
        assert count == 3

    def test_checkbox(self, e2e_page, webview_session):
        """Checkbox field renders."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Checkbox Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "agree", "label": "I agree", "type": "checkbox"}],
                        }
                    ]
                },
            },
            'input[data-field-key="agree"]',
        )
        is_checkbox = e2e_page.locator('input[data-field-key="agree"]').get_attribute("type")
        assert is_checkbox == "checkbox"

    def test_textarea(self, e2e_page, webview_session):
        """Textarea field renders."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Textarea Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "notes", "label": "Notes", "type": "textarea"}],
                        }
                    ]
                },
            },
            'textarea[data-field-key="notes"]',
        )
        assert e2e_page.locator('textarea[data-field-key="notes"]').count() == 1


class TestItemsSection:
    """Verify items list rendering."""

    def test_items_render(self, e2e_page, webview_session):
        """Item rows render with correct count."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Items Test",
                "data": {
                    "sections": [
                        {
                            "type": "items",
                            "items": [
                                {"title": "Item A"},
                                {"title": "Item B"},
                                {"title": "Item C"},
                            ],
                        }
                    ]
                },
            },
            ".item-row",
        )
        count = e2e_page.locator(".item-row").count()
        assert count == 3

    def test_subtitle(self, e2e_page, webview_session):
        """Item subtitles render."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Subtitle Test",
                "data": {"sections": [{"type": "items", "items": [{"title": "Main", "subtitle": "Secondary text"}]}]},
            },
            ".item-subtitle",
        )
        text = e2e_page.locator(".item-subtitle").first.inner_text()
        assert "Secondary text" in text

    def test_per_item_actions(self, e2e_page, webview_session):
        """Per-item action buttons render."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Item Actions Test",
                "data": {
                    "sections": [
                        {
                            "type": "items",
                            "items": [
                                {
                                    "title": "Task",
                                    "actions": [{"id": "edit", "label": "Edit", "type": "primary"}],
                                }
                            ],
                        }
                    ]
                },
            },
            ".item-actions [data-action-id]",
        )
        count = e2e_page.locator(".item-actions [data-action-id]").count()
        assert count >= 1


class TestProgressSection:
    """Verify progress section rendering."""

    def test_progress_bar(self, e2e_page, webview_session):
        """Progress bar renders with percentage."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Progress Test",
                "data": {
                    "sections": [
                        {
                            "type": "progress",
                            "percentage": 75,
                            "tasks": [
                                {"label": "Step 1", "status": "completed"},
                                {"label": "Step 2", "status": "in_progress"},
                            ],
                        }
                    ]
                },
            },
            ".progress-pct",
        )
        pct = e2e_page.locator(".progress-pct").inner_text()
        assert "75%" in pct

    def test_task_statuses(self, e2e_page, webview_session):
        """Progress tasks render with correct count."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Tasks Test",
                "data": {
                    "sections": [
                        {
                            "type": "progress",
                            "tasks": [
                                {"label": "A", "status": "completed"},
                                {"label": "B", "status": "in_progress"},
                                {"label": "C", "status": "pending"},
                            ],
                        }
                    ]
                },
            },
            ".progress-task",
        )
        count = e2e_page.locator(".progress-task").count()
        assert count == 3


class TestLogSection:
    """Verify log section rendering."""

    def test_log_lines(self, e2e_page, webview_session):
        """Log lines render with correct count."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Log Test",
                "data": {"sections": [{"type": "log", "lines": ["Line one", "Line two", "Line three"]}]},
            },
            ".log-line",
        )
        count = e2e_page.locator(".log-line").count()
        assert count == 3

    def test_ansi_colors(self, e2e_page, webview_session):
        """ANSI color codes render as styled spans."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "ANSI Test",
                "data": {
                    "sections": [
                        {"type": "log", "lines": ["\u001b[32m✓ passed\u001b[0m", "\u001b[31m✗ failed\u001b[0m"]}
                    ]
                },
            },
            ".log-line",
        )
        # ANSI codes should be converted to spans with color classes
        html = e2e_page.locator(".log-container").inner_html()
        assert "ansi-" in html or "color:" in html


class TestDiffSection:
    """Verify diff section rendering."""

    def test_diff_lines(self, e2e_page, webview_session):
        """Diff lines render."""
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1,3 +1,4 @@\n def hello():\n+    print('hi')\n     return True"
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Diff Test",
                "data": {"sections": [{"type": "diff", "content": diff}]},
            },
            ".diff-line",
        )
        count = e2e_page.locator(".diff-line").count()
        assert count >= 4  # header + hunk + context + add lines

    def test_add_remove_classes(self, e2e_page, webview_session):
        """Diff add/remove lines get correct CSS classes."""
        diff = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n-old line\n+new line"
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Diff Classes Test",
                "data": {"sections": [{"type": "diff", "content": diff}]},
            },
            ".diff-add",
        )
        assert e2e_page.locator(".diff-add").count() >= 1
        assert e2e_page.locator(".diff-remove").count() >= 1


class TestTableSection:
    """Verify table section rendering."""

    def test_headers_and_rows(self, e2e_page, webview_session):
        """Table renders correct header and row count."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Table Test",
                "data": {
                    "sections": [
                        {
                            "type": "table",
                            "columns": [{"key": "name", "label": "Name"}, {"key": "age", "label": "Age"}],
                            "rows": [
                                {"name": "Alice", "age": 30},
                                {"name": "Bob", "age": 25},
                            ],
                        }
                    ]
                },
            },
            "table",
        )
        th_count = e2e_page.locator("th").count()
        assert th_count == 2
        tr_count = e2e_page.locator("tbody tr").count()
        assert tr_count == 2

    def test_clickable_row_emits_action(self, e2e_page, webview_session):
        """Clicking a clickable table row writes an action to actions.json."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Clickable Table Test",
                "data": {
                    "sections": [
                        {
                            "type": "table",
                            "clickable": True,
                            "clickActionId": "row_click",
                            "columns": [{"key": "id", "label": "ID"}, {"key": "name", "label": "Name"}],
                            "rows": [{"id": "1", "name": "Alpha"}, {"id": "2", "name": "Beta"}],
                        }
                    ]
                },
            },
        )
        e2e_page.wait_for_selector("tbody tr", timeout=5000)
        e2e_page.locator("tbody tr").first.click()
        actions = read_actions_with_retry(webview_session)
        assert len(actions) >= 1
        assert actions[0]["action_id"] == "row_click"


class TestTabsSection:
    """Verify tabs section rendering."""

    def test_tab_switch(self, e2e_page, webview_session):
        """Clicking a tab switches the visible panel."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Tabs Test",
                "data": {
                    "sections": [
                        {
                            "type": "tabs",
                            "tabs": [
                                {
                                    "id": "tab1",
                                    "label": "First",
                                    "sections": [{"type": "text", "content": "Tab one content"}],
                                },
                                {
                                    "id": "tab2",
                                    "label": "Second",
                                    "sections": [{"type": "text", "content": "Tab two content"}],
                                },
                            ],
                        }
                    ]
                },
            },
            ".tabs-btn",
        )
        # Click second tab
        e2e_page.locator(".tabs-btn").nth(1).click()
        # Wait for tab2 panel to become visible (class-based visibility)
        e2e_page.wait_for_function(
            "() => {"
            "  const panels = document.querySelectorAll('.tabs-panel');"
            "  for (const p of panels) {"
            "    if (!p.classList.contains('owg-tabs-hidden') && p.textContent.includes('Tab two')) return true;"
            "  }"
            "  return false;"
            "}",
            timeout=5000,
        )
        text = e2e_page.locator(".tabs-panel:not(.owg-tabs-hidden)").inner_text()
        assert "Tab two content" in text


class TestMetricSection:
    """Verify metric card rendering."""

    def test_cards_render(self, e2e_page, webview_session):
        """Metric cards render with label, value, and unit."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Metric Test",
                "data": {
                    "sections": [
                        {
                            "type": "metric",
                            "cards": [{"label": "Users", "value": "1,234", "unit": "active"}],
                        }
                    ]
                },
            },
            ".metric-card",
        )
        # CSS text-transform: uppercase on .metric-label → inner_text returns uppercase
        label = e2e_page.locator(".metric-label").first.inner_text()
        assert "users" in label.lower()
        value = e2e_page.locator(".metric-value").first.inner_text()
        assert "1,234" in value
        unit = e2e_page.locator(".metric-unit").first.inner_text()
        assert "active" in unit.lower()

    def test_change_indicator(self, e2e_page, webview_session):
        """Change indicator renders with direction class."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Change Test",
                "data": {
                    "sections": [
                        {
                            "type": "metric",
                            "cards": [{"label": "Revenue", "value": "$10k", "change": "+12%", "changeDirection": "up"}],
                        }
                    ]
                },
            },
            ".metric-up",
        )
        assert e2e_page.locator(".metric-up").count() >= 1
        assert e2e_page.locator(".metric-arrow").count() >= 1

    def test_sparkline_svg(self, e2e_page, webview_session):
        """Sparkline renders as SVG with polyline."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Sparkline Test",
                "data": {
                    "sections": [
                        {
                            "type": "metric",
                            "cards": [{"label": "Trend", "value": "42", "sparkline": [10, 20, 30, 25, 42]}],
                        }
                    ]
                },
            },
            ".owg-sparkline",
        )
        assert e2e_page.locator(".owg-sparkline").count() >= 1
        assert e2e_page.locator(".owg-sparkline polyline").count() >= 1


class TestActionsSection:
    """Verify action button rendering."""

    def test_button_styles(self, e2e_page, webview_session):
        """Action buttons render with correct style classes."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Actions Test",
                "data": {"sections": []},
                "actions_requested": [
                    {"id": "ok", "label": "OK", "type": "approve"},
                    {"id": "del", "label": "Delete", "type": "danger"},
                    {"id": "back", "label": "Back", "type": "ghost"},
                ],
            },
            "[data-action-id]",
        )
        assert e2e_page.locator(".btn-primary").count() >= 1
        assert e2e_page.locator(".btn-danger").count() >= 1
        assert e2e_page.locator(".btn-ghost").count() >= 1


# =============================================================================
# Chart Rendering Tests
# =============================================================================


class TestChartRendering:
    """Verify SVG chart rendering for each chart type."""

    def test_bar_chart(self, e2e_page, webview_session):
        """Bar chart renders rect elements."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Bar Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "bar",
                            "data": {
                                "labels": ["A", "B", "C"],
                                "datasets": [{"label": "Sales", "values": [10, 20, 30], "color": "blue"}],
                            },
                        }
                    ]
                },
            },
            ".owg-chart .chart-bar",
        )
        bars = e2e_page.locator(".owg-chart .chart-bar").count()
        assert bars == 3

    def test_line_chart(self, e2e_page, webview_session):
        """Line chart renders polyline and dots."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Line Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "line",
                            "data": {
                                "labels": ["Jan", "Feb", "Mar"],
                                "datasets": [{"label": "Views", "values": [100, 200, 150], "color": "green"}],
                            },
                        }
                    ]
                },
            },
            ".owg-chart .chart-line",
        )
        assert e2e_page.locator(".owg-chart .chart-line").count() >= 1
        assert e2e_page.locator(".owg-chart .chart-dot").count() >= 3

    def test_area_chart(self, e2e_page, webview_session):
        """Area chart renders filled polygon and line."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Area Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "area",
                            "data": {
                                "labels": ["Q1", "Q2", "Q3"],
                                "datasets": [{"label": "Revenue", "values": [50, 80, 60], "color": "purple"}],
                            },
                        }
                    ]
                },
            },
            ".owg-chart .chart-area",
        )
        assert e2e_page.locator(".owg-chart .chart-area").count() >= 1
        assert e2e_page.locator(".owg-chart .chart-line").count() >= 1

    def test_pie_chart(self, e2e_page, webview_session):
        """Pie chart renders SVG path elements."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Pie Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "pie",
                            "data": {
                                "labels": ["Desktop", "Mobile", "Tablet"],
                                "datasets": [{"label": "Traffic", "values": [60, 30, 10]}],
                            },
                        }
                    ]
                },
            },
            ".owg-chart path",
        )
        paths = e2e_page.locator(".owg-chart path").count()
        assert paths >= 3  # one per slice

    def test_donut_chart(self, e2e_page, webview_session):
        """Donut chart renders SVG path elements."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Donut Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "donut",
                            "data": {
                                "labels": ["Used", "Free"],
                                "datasets": [{"label": "Disk", "values": [75, 25]}],
                            },
                        }
                    ]
                },
            },
            ".owg-chart path",
        )
        paths = e2e_page.locator(".owg-chart path").count()
        assert paths >= 2

    def test_sparkline_chart(self, e2e_page, webview_session):
        """Standalone sparkline chart renders SVG."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Sparkline Chart",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "sparkline",
                            "data": {
                                "labels": [],
                                "datasets": [{"values": [5, 10, 8, 15, 12]}],
                            },
                        }
                    ]
                },
            },
            ".owg-sparkline",
        )
        assert e2e_page.locator(".owg-sparkline").count() >= 1

    def test_chart_legend(self, e2e_page, webview_session):
        """Multi-dataset chart renders legend items."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Legend Test",
                "data": {
                    "sections": [
                        {
                            "type": "chart",
                            "chartType": "bar",
                            "data": {
                                "labels": ["A", "B"],
                                "datasets": [
                                    {"label": "Series 1", "values": [10, 20], "color": "blue"},
                                    {"label": "Series 2", "values": [15, 25], "color": "red"},
                                ],
                            },
                        }
                    ]
                },
            },
            ".owg-chart-legend-item",
        )
        count = e2e_page.locator(".owg-chart-legend-item").count()
        assert count == 2


# =============================================================================
# SPA Navigation Tests
# =============================================================================


class TestSPANavigation:
    """Verify SPA page navigation features."""

    def test_nav_bar_renders(self, e2e_page, webview_session):
        """Nav bar renders buttons for non-hidden pages."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Nav Test",
                "pages": {
                    "home": {"label": "Home", "data": {"sections": [{"type": "text", "content": "Home"}]}},
                    "settings": {
                        "label": "Settings",
                        "data": {"sections": [{"type": "text", "content": "Settings"}]},
                    },
                },
                "activePage": "home",
            },
            ".owg-nav-btn",
        )
        count = e2e_page.locator(".owg-nav-btn").count()
        assert count == 2

    def test_active_page_shown(self, e2e_page, webview_session):
        """Active page is visible, others are hidden."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Active Page Test",
                "pages": {
                    "home": {"label": "Home", "data": {"sections": [{"type": "text", "content": "Home page"}]}},
                    "other": {
                        "label": "Other",
                        "data": {"sections": [{"type": "text", "content": "Other page"}]},
                    },
                },
                "activePage": "home",
            },
            '.owg-page[data-page-id="home"]',
        )
        home_visible = e2e_page.locator('.owg-page[data-page-id="home"]').is_visible()
        other_visible = e2e_page.locator('.owg-page[data-page-id="other"]').is_visible()
        assert home_visible
        assert not other_visible

    def test_nav_click_switches(self, e2e_page, webview_session):
        """Clicking a nav button switches the visible page."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Nav Click Test",
                "pages": {
                    "home": {"label": "Home", "data": {"sections": [{"type": "text", "content": "Home"}]}},
                    "about": {"label": "About", "data": {"sections": [{"type": "text", "content": "About"}]}},
                },
                "activePage": "home",
            },
            ".owg-nav-btn",
        )
        # Click "About" nav button and wait for page switch
        e2e_page.locator('.owg-nav-btn[data-page="about"]').click()
        e2e_page.wait_for_function(
            "() => !document.querySelector('.owg-page[data-page-id=\"about\"]')?.classList.contains('owg-page-hidden')",
            timeout=5000,
        )
        about_visible = e2e_page.locator('.owg-page[data-page-id="about"]').is_visible()
        home_visible = e2e_page.locator('.owg-page[data-page-id="home"]').is_visible()
        assert about_visible
        assert not home_visible

    def test_hidden_page_excluded(self, e2e_page, webview_session):
        """Hidden pages are excluded from the nav bar."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Hidden Page Test",
                "pages": {
                    "home": {"label": "Home", "data": {"sections": [{"type": "text", "content": "Home"}]}},
                    "detail": {
                        "label": "Detail",
                        "hidden": True,
                        "data": {"sections": [{"type": "text", "content": "Detail"}]},
                    },
                },
                "activePage": "home",
            },
            ".owg-nav-btn",
        )
        nav_count = e2e_page.locator(".owg-nav-btn").count()
        assert nav_count == 1  # Only "Home" in nav, "Detail" is hidden
        # But the page container still exists in DOM
        assert e2e_page.locator('.owg-page[data-page-id="detail"]').count() == 1

    def test_show_nav_false(self, e2e_page, webview_session):
        """showNav: false hides the entire nav bar."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "No Nav Test",
                "showNav": False,
                "pages": {
                    "home": {"label": "Home", "data": {"sections": [{"type": "text", "content": "Home"}]}},
                    "other": {"label": "Other", "data": {"sections": [{"type": "text", "content": "Other"}]}},
                },
                "activePage": "home",
            },
            '.owg-page[data-page-id="home"]',
        )
        # Nav bar should not be rendered at all
        nav_count = e2e_page.locator(".owg-nav").count()
        assert nav_count == 0

    def test_navigate_to_on_action(self, e2e_page, webview_session):
        """navigateTo on an action button switches pages without emitting an action."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "NavigateTo Test",
                "showNav": False,
                "pages": {
                    "home": {
                        "label": "Home",
                        "data": {"sections": [{"type": "text", "content": "Home page"}]},
                        "actions_requested": [
                            {"id": "go", "label": "Go to Other", "type": "primary", "navigateTo": "other"}
                        ],
                    },
                    "other": {
                        "label": "Other",
                        "hidden": True,
                        "data": {"sections": [{"type": "text", "content": "Other page"}]},
                    },
                },
                "activePage": "home",
            },
        )
        e2e_page.wait_for_selector('[data-action-id="go"]', timeout=5000)
        e2e_page.locator('[data-action-id="go"]').click()
        # Wait for navigateTo to show the other page
        e2e_page.wait_for_function(
            "() => !document.querySelector('.owg-page[data-page-id=\"other\"]')?.classList.contains('owg-page-hidden')",
            timeout=5000,
        )
        other_visible = e2e_page.locator('.owg-page[data-page-id="other"]').is_visible()
        assert other_visible
        # No action should have been emitted
        actions = read_actions_with_retry(webview_session, retries=2, delay=0.3)
        assert len(actions) == 0


# =============================================================================
# Form Interaction Tests
# =============================================================================


class TestFormInteraction:
    """Verify form submission round-trips (browser → actions.json)."""

    def test_submit_text_field(self, e2e_page, webview_session):
        """Filling a text field and submitting records the value in actions.json."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Submit Text Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "name", "label": "Name", "type": "text"}],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('input[data-field-key="name"]', timeout=5000)
        e2e_page.locator('input[data-field-key="name"]').fill("TestUser")
        e2e_page.locator('[data-action-id="submit"]').click()
        actions = read_actions_with_retry(webview_session)
        assert len(actions) >= 1
        value = actions[0].get("value", {})
        assert value.get("name") == "TestUser"

    def test_submit_select(self, e2e_page, webview_session):
        """Changing a select and submitting records the selected value."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Submit Select Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "color",
                                    "label": "Color",
                                    "type": "select",
                                    "options": ["Red", "Green", "Blue"],
                                }
                            ],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('select[data-field-key="color"]', timeout=5000)
        e2e_page.locator('select[data-field-key="color"]').select_option("Blue")
        e2e_page.locator('[data-action-id="submit"]').click()
        actions = read_actions_with_retry(webview_session)
        assert len(actions) >= 1
        value = actions[0].get("value", {})
        assert value.get("color") == "Blue"

    def test_submit_checkbox(self, e2e_page, webview_session):
        """Checking a checkbox and submitting records true."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Submit Checkbox Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "agree", "label": "I agree", "type": "checkbox"}],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('input[data-field-key="agree"]', timeout=5000)
        e2e_page.locator('input[data-field-key="agree"]').check()
        e2e_page.locator('[data-action-id="submit"]').click()
        actions = read_actions_with_retry(webview_session)
        assert len(actions) >= 1
        value = actions[0].get("value", {})
        assert value.get("agree") is True

    def test_submit_number(self, e2e_page, webview_session):
        """Filling a number field and submitting records a numeric value."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Submit Number Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "count", "label": "Count", "type": "number"}],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('input[data-field-key="count"]', timeout=5000)
        e2e_page.locator('input[data-field-key="count"]').fill("42")
        e2e_page.locator('[data-action-id="submit"]').click()
        actions = read_actions_with_retry(webview_session)
        assert len(actions) >= 1
        value = actions[0].get("value", {})
        assert value.get("count") == 42


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    """Verify client-side form validation."""

    def test_required_blocks_submit(self, e2e_page, webview_session):
        """Empty required field prevents submission and shows error."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Required Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "email", "label": "Email", "type": "email", "required": True}],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('[data-action-id="submit"]', timeout=5000)
        # Click submit without filling required field
        e2e_page.locator('[data-action-id="submit"]').click()
        # Wait for validation error to appear
        e2e_page.wait_for_function(
            "() => (document.querySelector('[data-error-for=\"email\"]')?.textContent || '').length > 0",
            timeout=5000,
        )
        error_el = e2e_page.locator('[data-error-for="email"]')
        assert error_el.count() >= 1
        error_text = error_el.inner_text()
        assert len(error_text) > 0
        # No action should have been submitted
        actions = read_actions_with_retry(webview_session, retries=2, delay=0.3)
        assert len(actions) == 0

    def test_pattern_validation(self, e2e_page, webview_session):
        """Invalid pattern shows error message."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Pattern Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "code",
                                    "label": "Code",
                                    "type": "text",
                                    "required": True,
                                    "pattern": "^[a-z]+$",
                                    "errorMessage": "Lowercase only",
                                }
                            ],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('input[data-field-key="code"]', timeout=5000)
        e2e_page.locator('input[data-field-key="code"]').fill("UPPER")
        e2e_page.locator('[data-action-id="submit"]').click()
        # Wait for pattern validation error to appear
        e2e_page.wait_for_function(
            "() => (document.querySelector('[data-error-for=\"code\"]')?.textContent || '').length > 0",
            timeout=5000,
        )
        error_text = e2e_page.locator('[data-error-for="code"]').inner_text()
        assert "Lowercase only" in error_text

    def test_valid_input_clears_error(self, e2e_page, webview_session):
        """Fixing an invalid value clears the error."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Clear Error Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "name", "label": "Name", "type": "text", "required": True}],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('[data-action-id="submit"]', timeout=5000)
        # Trigger error by submitting empty
        e2e_page.locator('[data-action-id="submit"]').click()
        # Wait for validation error to appear
        e2e_page.wait_for_function(
            "() => (document.querySelector('[data-error-for=\"name\"]')?.textContent || '').length > 0",
            timeout=5000,
        )
        error_el = e2e_page.locator('[data-error-for="name"]')
        assert error_el.count() >= 1
        error_text = error_el.inner_text()
        assert len(error_text) > 0
        # Fix the value
        e2e_page.locator('input[data-field-key="name"]').fill("valid")
        # Wait for error to clear
        e2e_page.wait_for_function(
            "() => (document.querySelector('[data-error-for=\"name\"]')?.textContent || '').trim() === ''",
            timeout=5000,
        )
        error_after = e2e_page.locator('[data-error-for="name"]').inner_text()
        assert error_after.strip() == ""

    def test_minlength_validation(self, e2e_page, webview_session):
        """Value shorter than minLength shows error."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "MinLength Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "pass",
                                    "label": "Password",
                                    "type": "text",
                                    "required": True,
                                    "minLength": 8,
                                    "errorMessage": "At least 8 characters",
                                }
                            ],
                        }
                    ]
                },
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('input[data-field-key="pass"]', timeout=5000)
        e2e_page.locator('input[data-field-key="pass"]').fill("abc")
        e2e_page.locator('[data-action-id="submit"]').click()
        # Wait for minLength validation error to appear
        e2e_page.wait_for_function(
            "() => (document.querySelector('[data-error-for=\"pass\"]')?.textContent || '').length > 0",
            timeout=5000,
        )
        error_text = e2e_page.locator('[data-error-for="pass"]').inner_text()
        assert len(error_text) > 0


# =============================================================================
# Behaviors Tests
# =============================================================================


class TestBehaviors:
    """Verify conditional field show/hide/enable/disable."""

    def test_show_on_condition(self, e2e_page, webview_session):
        """Field appears when condition is met."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Show Behavior Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "type",
                                    "label": "Type",
                                    "type": "select",
                                    "options": ["standard", "custom"],
                                    "value": "standard",
                                },
                                {"key": "details", "label": "Details", "type": "text"},
                            ],
                        }
                    ]
                },
                "behaviors": [{"when": {"field": "type", "equals": "custom"}, "show": ["details"]}],
                "actions_requested": [],
            },
            'select[data-field-key="type"]',
        )
        # Initially "details" should be hidden
        details_visible = e2e_page.locator('[data-field-key="details"]').is_visible()
        assert not details_visible
        # Change to "custom" and wait for field to become visible
        e2e_page.locator('select[data-field-key="type"]').select_option("custom")
        e2e_page.locator('[data-field-key="details"]').wait_for(state="visible", timeout=5000)
        details_visible = e2e_page.locator('[data-field-key="details"]').is_visible()
        assert details_visible

    def test_hide_on_condition(self, e2e_page, webview_session):
        """Field hides when condition is met."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Hide Behavior Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [
                                {
                                    "key": "mode",
                                    "label": "Mode",
                                    "type": "select",
                                    "options": ["normal", "advanced"],
                                    "value": "normal",
                                },
                                {"key": "simple", "label": "Simple Option", "type": "text", "value": "yes"},
                            ],
                        }
                    ]
                },
                "behaviors": [{"when": {"field": "mode", "equals": "advanced"}, "hide": ["simple"]}],
                "actions_requested": [],
            },
            'select[data-field-key="mode"]',
        )
        # Initially "simple" should be visible
        simple_visible = e2e_page.locator('[data-field-key="simple"]').is_visible()
        assert simple_visible
        # Change to "advanced" and wait for field to be hidden
        e2e_page.locator('select[data-field-key="mode"]').select_option("advanced")
        e2e_page.locator('[data-field-key="simple"]').wait_for(state="hidden", timeout=5000)
        simple_visible = e2e_page.locator('[data-field-key="simple"]').is_visible()
        assert not simple_visible

    def test_enable_disable(self, e2e_page, webview_session):
        """Action button enables when checkbox is checked."""
        clear_and_write(
            webview_session,
            e2e_page,
            {
                "title": "Enable Behavior Test",
                "data": {
                    "sections": [
                        {
                            "type": "form",
                            "fields": [{"key": "agree", "label": "I agree", "type": "checkbox"}],
                        }
                    ]
                },
                "behaviors": [{"when": {"field": "agree", "checked": True}, "enable": ["submit"]}],
                "actions_requested": [{"id": "submit", "label": "Submit", "type": "submit"}],
            },
        )
        e2e_page.wait_for_selector('[data-action-id="submit"]', timeout=5000)
        # Submit button should be disabled initially
        disabled = e2e_page.locator('[data-action-id="submit"]').get_attribute("disabled")
        assert disabled is not None
        # Check the agree checkbox and wait for button to become enabled
        e2e_page.locator('input[data-field-key="agree"]').check()
        e2e_page.wait_for_function(
            "() => !document.querySelector('[data-action-id=\"submit\"]')?.disabled",
            timeout=5000,
        )
        disabled = e2e_page.locator('[data-action-id="submit"]').get_attribute("disabled")
        assert disabled is None


# =============================================================================
# Layout Tests
# =============================================================================


class TestLayouts:
    """Verify multi-panel layout rendering."""

    def test_sidebar_layout(self, e2e_page, webview_session):
        """Sidebar layout renders with two panels."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Sidebar Layout",
                "layout": {"type": "sidebar", "sidebarWidth": "250px"},
                "panels": {
                    "sidebar": {"sections": [{"type": "items", "items": [{"title": "Nav item"}]}]},
                    "main": {"sections": [{"type": "text", "content": "Main content"}]},
                },
            },
            ".layout-sidebar",
        )
        assert e2e_page.locator(".layout-sidebar").count() == 1
        assert e2e_page.locator(".layout-sidebar-panel").count() >= 1
        assert e2e_page.locator(".layout-main-panel").count() >= 1

    def test_split_layout(self, e2e_page, webview_session):
        """Split layout renders with two panels."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "Split Layout",
                "layout": {"type": "split"},
                "panels": {
                    "left": {"sections": [{"type": "text", "content": "Left"}]},
                    "right": {"sections": [{"type": "text", "content": "Right"}]},
                },
            },
            ".layout-split",
        )
        assert e2e_page.locator(".layout-split").count() == 1
        panels = e2e_page.locator(".layout-split .layout-panel").count()
        assert panels == 2


# =============================================================================
# Header & Status Tests
# =============================================================================


class TestHeader:
    """Verify header title and status badge rendering."""

    def test_title_and_badge(self, e2e_page, webview_session):
        """Title and status badge render correctly."""
        write_and_wait(
            webview_session,
            e2e_page,
            {
                "title": "My Dashboard",
                "status": "pending_review",
                "data": {"sections": []},
            },
            "#hdr-title",
        )
        title = e2e_page.locator("#hdr-title").inner_text()
        assert "My Dashboard" in title
        badge = e2e_page.locator("#hdr-badge").inner_text()
        # CSS text-transform: uppercase on .badge → inner_text may return uppercase
        assert "pending" in badge.lower()

    def test_connection_dot(self, e2e_page, webview_session):
        """Connection dot shows green when connected."""
        # The e2e_page fixture already waits for this, but let's verify explicitly
        dot_class = e2e_page.locator("#conn-dot").get_attribute("class")
        assert "on" in dot_class
