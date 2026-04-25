"""
Tests for the bundler (scripts/bundler.py).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bundler  # noqa: E402
from bundler import bundle_html, clear_cache  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _reset_cache():
    """Ensure every test starts with a clean bundle cache."""
    clear_cache()
    yield
    clear_cache()


# ═══════════════════════════════════════════════════════════════════════════════
# TestBundleHTML — end-to-end bundling assertions
# ═══════════════════════════════════════════════════════════════════════════════


class TestBundleHTML:
    """Validate the bundled HTML output produced by bundle_html()."""

    def test_bundle_produces_html(self):
        """bundle_html() returns a string containing valid HTML structure."""
        result = bundle_html()
        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result or "<html" in result

    def test_scripts_inlined(self):
        """All external <script src> tags are removed; JS content is inlined."""
        result = bundle_html()
        # No external script references should remain
        assert "<script src=" not in result
        # Content from utils.js (OWG.esc function)
        assert "OWG.esc" in result
        # Content from app.js (orchestrator module)
        assert "OWG.formValues" in result

    def test_mcp_apps_flag_set(self):
        """The MCP Apps detection flag is present in the bundle."""
        result = bundle_html()
        assert "window.__OWG_MCP_APPS__=true" in result

    def test_header_hidden(self):
        """The <header> element is hidden via inline style for embedded mode."""
        result = bundle_html()
        assert '<header style="display:none"' in result

    def test_min_height_replaced(self):
        """min-height: 100vh is replaced with min-height: auto for iframe sizing."""
        result = bundle_html()
        assert "min-height: auto" in result
        assert "min-height: 100vh" not in result

    def test_script_escape(self):
        """Any </script> literals inside inlined JS are escaped."""
        result = bundle_html()
        # Split on actual closing script tags to inspect inlined content.
        # Between <script> and </script>, the literal </script> must not appear
        # (it would be escaped to <\/script>).
        import re

        for match in re.finditer(r"<script>(.*?)</script>", result, re.DOTALL):
            content = match.group(1)
            assert "</script>" not in content

    def test_size_under_limit(self):
        """Bundled HTML stays under 300KB to keep resource responses lean."""
        result = bundle_html()
        assert len(result) < 300_000, f"Bundle size {len(result)} exceeds 300KB limit"

    def test_cache_returns_same_object(self):
        """Repeated calls return the exact same cached string object."""
        first = bundle_html()
        second = bundle_html()
        assert first is second

    def test_clear_cache(self):
        """clear_cache() forces a fresh bundle on the next call."""
        first = bundle_html()
        clear_cache()
        second = bundle_html()
        # Must be equal but a different object (freshly built)
        assert first == second
        assert first is not second


# ═══════════════════════════════════════════════════════════════════════════════
# TestFindAssetsDir — error handling for missing assets
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindAssetsDir:
    """Validate assets-directory resolution across dev and installed layouts."""

    def test_missing_assets_dir(self):
        """Passing a nonexistent assets_dir raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            bundle_html(assets_dir=Path("/nonexistent"))

    def test_find_assets_dir_dev_layout(self, tmp_path, monkeypatch):
        """Dev layout: assets/ at repo root (sibling of scripts/)."""
        fake_scripts = tmp_path / "scripts"
        fake_scripts.mkdir()
        (tmp_path / "assets").mkdir()
        monkeypatch.setattr(bundler, "__file__", str(fake_scripts / "bundler.py"))
        assert bundler._find_assets_dir() == tmp_path / "assets"

    def test_find_assets_dir_installed_layout(self, tmp_path, monkeypatch):
        """Installed layout: assets/ inside the scripts/ package (pipx/pip install)."""
        fake_scripts = tmp_path / "site-packages" / "scripts"
        fake_scripts.mkdir(parents=True)
        (fake_scripts / "assets").mkdir()
        monkeypatch.setattr(bundler, "__file__", str(fake_scripts / "bundler.py"))
        assert bundler._find_assets_dir() == fake_scripts / "assets"

    def test_find_assets_dir_neither_layout_raises(self, tmp_path, monkeypatch):
        """When neither layout has assets/, raise with both candidate paths named."""
        fake_scripts = tmp_path / "scripts"
        fake_scripts.mkdir()
        monkeypatch.setattr(bundler, "__file__", str(fake_scripts / "bundler.py"))
        with pytest.raises(FileNotFoundError, match="Cannot find assets directory"):
            bundler._find_assets_dir()
