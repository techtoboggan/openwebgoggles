"""Tests for the plugin system.

Covers:
- Plugin discovery (plugin_loader.py)
- SecurityGate extra_section_types
- Bundler plugin injection
- Plugin type validation
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugin_loader import (  # noqa: E402, I001
    MAX_PLUGIN_SIZE,
    PLUGIN_HEADER_RE,
    discover_plugins,
    get_plugin_dirs,
)
from security_gate import SecurityGate  # noqa: E402


# ---------------------------------------------------------------------------
# Plugin header regex
# ---------------------------------------------------------------------------


class TestPluginHeaderRegex:
    """Tests for the @owg-plugin header pattern."""

    def test_valid_header(self):
        assert PLUGIN_HEADER_RE.search("// @owg-plugin type: kanban")

    def test_header_with_dashes(self):
        assert PLUGIN_HEADER_RE.search("// @owg-plugin type: my-custom-type")

    def test_header_with_underscores(self):
        assert PLUGIN_HEADER_RE.search("// @owg-plugin type: my_type")

    def test_header_with_digits(self):
        assert PLUGIN_HEADER_RE.search("// @owg-plugin type: chart2d")

    def test_invalid_uppercase(self):
        assert not PLUGIN_HEADER_RE.search("// @owg-plugin type: MyType")

    def test_invalid_starts_with_digit(self):
        assert not PLUGIN_HEADER_RE.search("// @owg-plugin type: 2chart")

    def test_extracts_type_name(self):
        m = PLUGIN_HEADER_RE.search("// @owg-plugin type: kanban\n")
        assert m.group(1) == "kanban"


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------


class TestDiscoverPlugins:
    """Tests for discover_plugins()."""

    def test_discovers_valid_plugin(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "kanban.js").write_text(
            "// @owg-plugin type: kanban\n"
            '"use strict";\n'
            '(function(OWG) { OWG.registerPlugin("kanban", function(sec, si) { return ""; }); })(window.OWG);\n'
        )
        result = discover_plugins(plugin_dir)
        assert len(result) == 1
        assert result[0].type_name == "kanban"
        assert "registerPlugin" in result[0].content

    def test_skips_missing_header(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "bad.js").write_text('"use strict";\nconsole.log("no header");\n')
        result = discover_plugins(plugin_dir)
        assert len(result) == 0

    def test_skips_dangerous_patterns(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "evil.js").write_text('// @owg-plugin type: evil\ndocument.body.innerHTML = "pwned";\n')
        result = discover_plugins(plugin_dir)
        assert len(result) == 0

    def test_skips_eval(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "bad.js").write_text('// @owg-plugin type: bad\neval("alert(1)");\n')
        result = discover_plugins(plugin_dir)
        assert len(result) == 0

    def test_skips_oversized_plugin(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        content = "// @owg-plugin type: huge\n" + "x" * (MAX_PLUGIN_SIZE + 1)
        (plugin_dir / "huge.js").write_text(content)
        result = discover_plugins(plugin_dir)
        assert len(result) == 0

    def test_deduplicates_by_type(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        for name in ["a.js", "b.js"]:
            (plugin_dir / name).write_text(
                "// @owg-plugin type: dupe\n"
                '(function(OWG) { OWG.registerPlugin("dupe", function() { return ""; }); })(window.OWG);\n'
            )
        result = discover_plugins(plugin_dir)
        assert len(result) == 1

    def test_max_plugins_limit(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        for i in range(5):
            (plugin_dir / f"p{i}.js").write_text(
                f"// @owg-plugin type: type{i}\n"
                f'(function(OWG) {{ OWG.registerPlugin("type{i}", function() {{ return ""; }}); }})(window.OWG);\n'
            )
        result = discover_plugins(plugin_dir, max_plugins=3)
        assert len(result) == 3

    def test_multiple_dirs(self, tmp_path):
        dir1 = tmp_path / "global"
        dir1.mkdir()
        dir2 = tmp_path / "local"
        dir2.mkdir()
        (dir1 / "a.js").write_text(
            "// @owg-plugin type: global-plugin\n"
            '(function(OWG) { OWG.registerPlugin("global-plugin", function() { return ""; }); })(window.OWG);\n'
        )
        (dir2 / "b.js").write_text(
            "// @owg-plugin type: local-plugin\n"
            '(function(OWG) { OWG.registerPlugin("local-plugin", function() { return ""; }); })(window.OWG);\n'
        )
        result = discover_plugins(dir1, dir2)
        assert len(result) == 2
        names = {p.type_name for p in result}
        assert names == {"global-plugin", "local-plugin"}

    def test_nonexistent_dir_skipped(self, tmp_path):
        result = discover_plugins(tmp_path / "does-not-exist")
        assert len(result) == 0

    def test_non_js_files_skipped(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "readme.txt").write_text("// @owg-plugin type: fake\n")
        result = discover_plugins(plugin_dir)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# SecurityGate extra section types
# ---------------------------------------------------------------------------


class TestSecurityGatePlugins:
    """Tests for SecurityGate with extra_section_types."""

    def test_default_rejects_unknown_type(self):
        gate = SecurityGate()
        import json

        state = json.dumps({"title": "x", "data": {"sections": [{"type": "kanban"}]}})
        valid, err, _ = gate.validate_state(state)
        assert not valid
        assert "kanban" in err

    def test_extra_type_accepted(self):
        gate = SecurityGate(extra_section_types=frozenset({"kanban"}))
        import json

        state = json.dumps({"title": "x", "data": {"sections": [{"type": "kanban"}]}})
        valid, err, _ = gate.validate_state(state)
        assert valid, f"Expected valid, got error: {err}"

    def test_multiple_extra_types(self):
        gate = SecurityGate(extra_section_types=frozenset({"kanban", "gantt", "calendar"}))
        import json

        state = json.dumps({"title": "x", "data": {"sections": [{"type": "gantt"}]}})
        valid, err, _ = gate.validate_state(state)
        assert valid, f"Expected valid, got error: {err}"

    def test_builtin_override_rejected(self):
        with pytest.raises(ValueError, match="Cannot override built-in"):
            SecurityGate(extra_section_types=frozenset({"form"}))

    def test_invalid_type_name_rejected(self):
        with pytest.raises(ValueError, match="Invalid plugin section type"):
            SecurityGate(extra_section_types=frozenset({"INVALID"}))

    def test_numeric_start_rejected(self):
        with pytest.raises(ValueError, match="Invalid plugin section type"):
            SecurityGate(extra_section_types=frozenset({"2bad"}))

    def test_empty_extra_types(self):
        """Empty frozenset is fine — no extra types."""
        gate = SecurityGate(extra_section_types=frozenset())
        import json

        state = json.dumps({"title": "x", "data": {"sections": [{"type": "form"}]}})
        valid, _, _ = gate.validate_state(state)
        assert valid

    def test_builtin_types_still_work(self):
        """Extra types don't break builtin type validation."""
        gate = SecurityGate(extra_section_types=frozenset({"custom-viz"}))
        import json

        for t in ["form", "table", "log", "metric", "text"]:
            state = json.dumps({"title": "x", "data": {"sections": [{"type": t}]}})
            valid, err, _ = gate.validate_state(state)
            assert valid, f"Built-in type {t} rejected: {err}"


# ---------------------------------------------------------------------------
# Bundler plugin injection
# ---------------------------------------------------------------------------


class TestBundlerPlugins:
    """Tests for bundler.py plugin injection."""

    def test_bundle_without_plugins(self):
        """Bundler works without plugins (backward compat)."""
        from bundler import bundle_html, clear_cache

        clear_cache()
        html = bundle_html()
        assert "OWG" in html
        assert "__OWG_MCP_APPS__" in html

    def test_bundle_with_plugins(self):
        """Plugin content is injected into the bundle."""
        from bundler import bundle_html, clear_cache

        clear_cache()
        plugin_js = '// @owg-plugin type: test-plugin\nOWG.registerPlugin("test-plugin", function() { return "hi"; });'
        html = bundle_html(plugin_contents=[plugin_js])
        assert "test-plugin" in html
        assert "registerPlugin" in html

    def test_plugins_before_app_js(self):
        """Plugin scripts appear before app.js in the bundle."""
        from bundler import bundle_html, clear_cache

        clear_cache()
        plugin_js = "// PLUGIN_MARKER_XYZ"
        html = bundle_html(plugin_contents=[plugin_js])
        plugin_pos = html.index("PLUGIN_MARKER_XYZ")
        # app.js freezes window.OWG — should come after plugin
        freeze_pos = html.index("Object.freeze(window.OWG)")
        assert plugin_pos < freeze_pos

    def test_script_escape(self):
        """Plugin content with </script> is escaped."""
        from bundler import bundle_html, clear_cache

        clear_cache()
        plugin_js = '// test\nvar x = "</script>";\n'
        html = bundle_html(plugin_contents=[plugin_js])
        assert "</script>" not in html.split("<script>")[-1].split("</script>")[0] or "<\\/script>" in html


# ---------------------------------------------------------------------------
# get_plugin_dirs
# ---------------------------------------------------------------------------


class TestGetPluginDirs:
    """Tests for get_plugin_dirs()."""

    def test_returns_list_of_paths(self):
        dirs = get_plugin_dirs()
        assert isinstance(dirs, list)
        assert len(dirs) >= 2
        # Should include global and local dirs
        assert any("plugins" in str(d) for d in dirs)
