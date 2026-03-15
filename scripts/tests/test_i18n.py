"""Tests for the i18n (internationalization) system.

Structural tests that verify all translation keys are present across locales,
and SecurityGate tests that validate the locale/strings top-level state keys.
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_gate import SecurityGate

# Path to the JS utils file containing the i18n string table
_UTILS_JS = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "apps", "dynamic", "utils.js")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_locale_keys() -> dict[str, set[str]]:
    """Parse _builtinStrings from utils.js and return {locale: {keys}}."""
    with open(_UTILS_JS, encoding="utf-8") as f:
        src = f.read()

    # Find the _builtinStrings block
    match = re.search(r"var _builtinStrings\s*=\s*\{", src)
    assert match, "_builtinStrings not found in utils.js"

    # Extract the full _builtinStrings object via brace counting
    pos = match.end()
    depth = 1
    while pos < len(src) and depth > 0:
        ch = src[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        pos += 1

    block = src[match.start() : pos]

    # Find each locale: { ... } block using brace-counting per locale
    locales: dict[str, set[str]] = {}
    locale_start = re.compile(r"(\w+)\s*:\s*\{")
    for m in locale_start.finditer(block):
        locale_name = m.group(1)
        # Skip the outer "var _builtinStrings" match itself
        if locale_name in ("_builtinStrings", "var"):
            continue
        # Brace-count from the opening { to find the matching }
        brace_start = m.end()
        bd = 1
        bp = brace_start
        while bp < len(block) and bd > 0:
            c = block[bp]
            if c == "{":
                bd += 1
            elif c == "}":
                bd -= 1
            bp += 1
        locale_block = block[brace_start : bp - 1]
        keys = set(re.findall(r'"([^"]+)"\s*:', locale_block))
        if keys:
            locales[locale_name] = keys

    return locales


def _extract_t_calls() -> set[str]:
    """Extract all OWG.t("key") and U.t("key") calls from JS source files."""
    js_dir = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "apps", "dynamic")
    keys: set[str] = set()
    pattern = re.compile(r'(?:OWG|U)\.t\(\s*"([^"]+)"')

    for fname in os.listdir(js_dir):
        if not fname.endswith(".js"):
            continue
        with open(os.path.join(js_dir, fname), encoding="utf-8") as f:
            for m in pattern.finditer(f.read()):
                keys.add(m.group(1))

    return keys


# ---------------------------------------------------------------------------
# Structural: locale key completeness
# ---------------------------------------------------------------------------


class TestLocaleCompleteness:
    """Every key in the English locale must exist in all other locales."""

    @pytest.fixture(scope="class")
    def locale_keys(self) -> dict[str, set[str]]:
        return _extract_locale_keys()

    def test_english_is_baseline(self, locale_keys):
        """English locale exists and has keys."""
        assert "en" in locale_keys
        assert len(locale_keys["en"]) >= 20, "English locale should have at least 20 keys"

    def test_all_locales_present(self, locale_keys):
        """All expected locales are defined."""
        expected = {"en", "es", "fr", "de", "ja", "zh"}
        assert expected.issubset(locale_keys.keys()), f"Missing locales: {expected - locale_keys.keys()}"

    def test_western_locales_complete(self, locale_keys):
        """Western locales (es, fr, de) have all English keys."""
        en_keys = locale_keys["en"]
        for locale in ("es", "fr", "de"):
            missing = en_keys - locale_keys.get(locale, set())
            assert not missing, f"{locale} missing keys: {sorted(missing)}"

    def test_cjk_locales_have_core_keys(self, locale_keys):
        """CJK locales (ja, zh) have at least the core UI keys."""
        core_keys = {
            "session_prefix",
            "connection_lost",
            "session_closed",
            "action_sent",
            "copy",
            "choose_file",
            "filter_placeholder",
            "field_required",
            "invalid_format",
        }
        for locale in ("ja", "zh"):
            missing = core_keys - locale_keys.get(locale, set())
            assert not missing, f"{locale} missing core keys: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Structural: OWG.t() calls match defined keys
# ---------------------------------------------------------------------------


class TestTranslationKeyCoverage:
    """Every OWG.t() call in JS source must reference a key that exists in English."""

    @pytest.fixture(scope="class")
    def en_keys(self) -> set[str]:
        locales = _extract_locale_keys()
        return locales.get("en", set())

    @pytest.fixture(scope="class")
    def used_keys(self) -> set[str]:
        return _extract_t_calls()

    def test_all_used_keys_defined(self, en_keys, used_keys):
        """All OWG.t()/U.t() keys in JS source are defined in the English locale."""
        undefined = used_keys - en_keys
        assert not undefined, f"OWG.t() keys not defined in English locale: {sorted(undefined)}"

    def test_no_unused_keys(self, en_keys, used_keys):
        """All defined English keys are actually used in JS source."""
        # default_title is used in app.js via U.t
        unused = en_keys - used_keys
        assert not unused, f"English locale keys not used in any JS file: {sorted(unused)}"


# ---------------------------------------------------------------------------
# SecurityGate: locale validation
# ---------------------------------------------------------------------------


class TestSecurityGateLocale:
    @pytest.fixture()
    def gate(self):
        return SecurityGate()

    def test_valid_locale_accepted(self, gate):
        state = {"title": "Test", "locale": "en"}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert valid, f"Valid locale rejected: {err}"

    def test_locale_with_region_accepted(self, gate):
        state = {"title": "Test", "locale": "zh-CN"}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert valid, f"Valid locale rejected: {err}"

    def test_locale_bcp47_long(self, gate):
        state = {"title": "Test", "locale": "en-US-x-custom"}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert valid, f"Valid locale rejected: {err}"

    def test_invalid_locale_rejected(self, gate):
        for bad in ["<script>", "en/../../etc/passwd", "a" * 100, "123", ""]:
            state = {"title": "Test", "locale": bad}
            raw = json.dumps(state, separators=(",", ":"))
            valid, err, _ = gate.validate_state(raw)
            assert not valid, f"Invalid locale accepted: {bad!r}"

    def test_locale_non_string_rejected(self, gate):
        state = {"title": "Test", "locale": 42}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "Non-string locale should be rejected"


# ---------------------------------------------------------------------------
# SecurityGate: strings validation
# ---------------------------------------------------------------------------


class TestSecurityGateStrings:
    @pytest.fixture()
    def gate(self):
        return SecurityGate()

    def test_valid_strings_accepted(self, gate):
        state = {"title": "Test", "strings": {"greeting": "Hello"}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert valid, f"Valid strings rejected: {err}"

    def test_strings_non_dict_rejected(self, gate):
        state = {"title": "Test", "strings": "not a dict"}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "strings as string should be rejected"

    def test_strings_too_many_entries_rejected(self, gate):
        state = {"title": "Test", "strings": {f"key_{i}": f"val_{i}" for i in range(201)}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "Too many strings entries should be rejected"

    def test_strings_long_key_rejected(self, gate):
        state = {"title": "Test", "strings": {"k" * 101: "value"}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "Long key should be rejected"

    def test_strings_long_value_rejected(self, gate):
        state = {"title": "Test", "strings": {"key": "x" * 2001}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "Long value should be rejected"

    def test_strings_non_string_value_rejected(self, gate):
        state = {"title": "Test", "strings": {"key": 42}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "Non-string value should be rejected"

    def test_strings_xss_in_value_rejected(self, gate):
        state = {"title": "Test", "strings": {"key": "<script>alert(1)</script>"}}
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert not valid, "XSS in strings value should be rejected"

    def test_locale_and_strings_together(self, gate):
        state = {
            "title": "Test",
            "locale": "es",
            "strings": {"greeting": "Hola", "farewell": "Adi\u00f3s"},
        }
        raw = json.dumps(state, separators=(",", ":"))
        valid, err, _ = gate.validate_state(raw)
        assert valid, f"locale+strings together rejected: {err}"
