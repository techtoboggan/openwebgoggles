"""
Security Gate — validates and sanitizes all agent-generated state payloads
before they reach the browser.

This module acts as a firewall between the untrusted LLM-generated content
(state.json) and the browser renderer. It enforces:
  1. Payload size limits
  2. JSON schema validation (allowlisted section/field/action types)
  3. XSS pattern scanning on all string values
  4. Nesting depth limits
  5. Action schema validation for incoming browser actions

OWASP references:
  - A03:2021 Injection
  - A07:2021 XSS
  - LLM01:2025 Prompt Injection
  - LLM05:2025 Improper Output Handling
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from typing import Any


class SecurityGate:
    """Validates state payloads before they reach the browser."""

    # --- Size limits ---
    MAX_PAYLOAD_SIZE = 512_000  # 512KB total state
    MAX_STRING_LENGTH = 50_000  # 50KB per string value
    MAX_NESTING_DEPTH = 10
    MAX_SECTIONS = 50
    MAX_FIELDS_PER_SECTION = 100
    MAX_ITEMS_PER_SECTION = 500
    MAX_ACTIONS = 50
    MAX_OPTIONS_PER_FIELD = 200

    # --- Allowlists ---
    ALLOWED_FIELD_TYPES = frozenset(
        {
            "text",
            "textarea",
            "number",
            "select",
            "checkbox",
            "email",
            "url",
            "static",
            "slider",
            "date",
            "datetime",
            "autocomplete",
            "file",
        }
    )
    ALLOWED_SECTION_TYPES = frozenset(
        {
            "form",
            "items",
            "text",
            "actions",
            "progress",
            "log",
            "diff",
            "table",
            "tabs",
            "metric",
            "chart",
        }
    )
    ALLOWED_ACTION_STYLES = frozenset(
        {
            "primary",
            "success",
            "danger",
            "warning",
            "ghost",
            "approve",
            "reject",
            "confirm",
            "submit",
            "delete",
        }
    )
    ALLOWED_ACTION_TYPES = frozenset(
        {
            "approve",
            "reject",
            "confirm",
            "submit",
            "delete",
            "select",
            "input",
            "custom",
            "action",
            "primary",
            "danger",
            "success",
            "warning",
            "ghost",
        }
    )
    ALLOWED_STATUS_VALUES = frozenset(
        {
            "initializing",
            "ready",
            "pending_review",
            "waiting_input",
            "processing",
            "completed",
            "error",
        }
    )
    ALLOWED_FORMATS = frozenset(
        {
            "markdown",
            "plain",
            "text",
        }
    )

    # --- Zero-width characters that can bypass pattern matching ---
    # These invisible chars can be inserted between keywords (e.g. java[ZWS]script:)
    # to bypass regex-based XSS detection while still being rendered by browsers.
    ZERO_WIDTH_CHARS = re.compile(
        r"[\x00\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u180e"
        r"\u202a-\u202e"  # Bidi embedding/override (LRE, RLE, PDF, LRO, RLO)
        r"\u2066-\u2069"  # Bidi isolate (LRI, RLI, FSI, PDI)
        r"\u206a-\u206f"  # Deprecated formatting (ISS, ASS, IAFS, AAFS, NADS, NODS)
        r"]"
    )

    # --- XSS detection patterns (case-insensitive) ---
    XSS_PATTERNS = [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),  # event handlers
        re.compile(r"<\s*iframe", re.IGNORECASE),
        re.compile(r"<\s*object", re.IGNORECASE),
        re.compile(r"<\s*embed", re.IGNORECASE),
        re.compile(r"<\s*form\b", re.IGNORECASE),
        re.compile(r"<\s*meta\b", re.IGNORECASE),
        re.compile(r"<\s*link\b", re.IGNORECASE),
        re.compile(r"<\s*base\b", re.IGNORECASE),  # base tag can redirect relative URLs
        re.compile(r"<\s*svg[^>]*\bon", re.IGNORECASE),  # SVG with event handlers
        re.compile(r"<\s*math\b", re.IGNORECASE),  # MathML can be used for XSS
        re.compile(r"expression\s*\(", re.IGNORECASE),  # CSS expression()
        re.compile(r"-moz-binding\s*:", re.IGNORECASE),  # Firefox CSS binding
        re.compile(r"behavior\s*:\s*url\s*\(", re.IGNORECASE),  # IE CSS behavior
        re.compile(r"url\s*\(\s*[\"']?\s*javascript:", re.IGNORECASE),
        re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
        re.compile(r"\\u003c\s*script", re.IGNORECASE),  # Unicode-escaped
        re.compile(r"&#x0*3c;?\s*script", re.IGNORECASE),  # HTML hex entity &#x3c;
        re.compile(r"&#0*60;?\s*script", re.IGNORECASE),  # HTML decimal entity &#60;
        re.compile(r"vbscript\s*:", re.IGNORECASE),  # VBScript protocol
        re.compile(r"<\s*style\b", re.IGNORECASE),  # Style tag injection
        re.compile(r"<\s*img\b", re.IGNORECASE),
        re.compile(r"<\s*video\b", re.IGNORECASE),
        re.compile(r"<\s*audio\b", re.IGNORECASE),
        re.compile(r"<\s*details\b[^>]*\bon", re.IGNORECASE),
        re.compile(r"<\s*marquee\b", re.IGNORECASE),
        re.compile(r"<\s*source\b", re.IGNORECASE),
        re.compile(r"srcdoc\s*=", re.IGNORECASE),  # iframe srcdoc can embed arbitrary HTML
        re.compile(r"xlink:href\s*=", re.IGNORECASE),  # SVG xlink:href can reference javascript: URIs
    ]
    # NOTE: The <img> pattern (above) intentionally blocks <img> tags even in markdown content.
    # This is correct defense-in-depth: DOMPurify's ALLOWED_TAGS in app.js also excludes <img>.

    # --- CSS validation (for custom_css in state) ---
    MAX_BEHAVIORS = 100
    MAX_CSS_LENGTH = 50_000  # 50KB max for custom CSS
    MAX_LOG_LINES = 5000
    MAX_TABLE_COLUMNS = 50
    MAX_TABS = 20
    MAX_PAGES = 20
    ALLOWED_TASK_STATUSES = frozenset({"pending", "in_progress", "completed", "failed", "skipped"})
    # Aliases normalised to canonical values before validation — keeps LLM agents from spinning
    # their wheels on near-misses. Both dicts are case-sensitive (already lower-case).
    STATUS_ALIASES: dict[str, str] = {
        # → processing
        "live": "processing",
        "active": "processing",
        "running": "processing",
        "working": "processing",
        "busy": "processing",
        # → completed
        "done": "completed",
        "complete": "completed",
        "success": "completed",
        "succeeded": "completed",
        "finished": "completed",
        # → error
        "failed": "error",
        "failure": "error",
        "err": "error",
        # → waiting_input
        "waiting": "waiting_input",
        "waiting_for_input": "waiting_input",
        # → ready
        "idle": "ready",
        # → initializing
        "starting": "initializing",
        "init": "initializing",
        "loading": "initializing",
    }
    TASK_STATUS_ALIASES: dict[str, str] = {
        # → completed
        "complete": "completed",
        "done": "completed",
        "success": "completed",
        "succeeded": "completed",
        "finished": "completed",
        "ok": "completed",
        # → in_progress
        "running": "in_progress",
        "active": "in_progress",
        "live": "in_progress",
        "working": "in_progress",
        "processing": "in_progress",
        "busy": "in_progress",
        # → failed
        "error": "failed",
        "failure": "failed",
        "errored": "failed",
        "err": "failed",
        # → pending
        "wait": "pending",
        "waiting": "pending",
        "queued": "pending",
        "todo": "pending",
        "not_started": "pending",
        # → skipped
        "skip": "skipped",
        "ignored": "skipped",
        "cancelled": "skipped",
        "canceled": "skipped",
    }
    ALLOWED_BEHAVIOR_CONDITIONS = frozenset(
        {"equals", "notEquals", "in", "notIn", "checked", "unchecked", "empty", "notEmpty", "matches"}
    )
    ALLOWED_BEHAVIOR_EFFECTS = frozenset({"show", "hide", "enable", "disable"})
    ALLOWED_LAYOUT_TYPES = frozenset({"default", "sidebar", "split"})
    ALLOWED_PANEL_KEYS = frozenset({"sidebar", "main", "left", "right"})
    CSS_LENGTH_PATTERN = re.compile(r"^[0-9]+(px|em|rem|%)$")
    DANGEROUS_CSS_PATTERNS = [
        re.compile(r"expression\s*\(", re.IGNORECASE),  # IE CSS expressions
        re.compile(r"-moz-binding\s*:", re.IGNORECASE),  # Firefox binding
        re.compile(r"behavior\s*:\s*url\s*\(", re.IGNORECASE),  # IE behavior
        re.compile(r"@import", re.IGNORECASE),  # External resource loading
        re.compile(r"@charset", re.IGNORECASE),  # Encoding tricks
        re.compile(r"@namespace", re.IGNORECASE),  # Parsing context override
        re.compile(r"@font-face", re.IGNORECASE),  # Font exfiltration via unicode-range
        re.compile(r"@keyframes", re.IGNORECASE),  # Global animation names bypass CSS scoping
        re.compile(r"@supports", re.IGNORECASE),  # Feature queries can probe browser state
        re.compile(r"@layer", re.IGNORECASE),  # Cascade layer manipulation
        re.compile(r"@media", re.IGNORECASE),  # @media blocks bypass CSS scoping (_scopeCSS)
        re.compile(r"url\s*\(", re.IGNORECASE),  # Block ALL url() — prevents data exfiltration via http(s)
        re.compile(r"\\"),  # Block ALL backslash escapes — non-hex escapes like \m bypass keyword patterns
        re.compile(r"/\*"),  # CSS comments can split keywords to bypass patterns (e.g. ur/**/l())
        re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"),  # zero-width / bidi chars
    ]

    # --- Metric section ---
    ALLOWED_CHANGE_DIRECTIONS = frozenset({"up", "down", "neutral"})
    MAX_SPARKLINE_POINTS = 100
    MAX_METRIC_COLUMNS = 6

    # --- Chart section ---
    ALLOWED_CHART_TYPES = frozenset({"bar", "line", "area", "pie", "donut", "sparkline"})
    ALLOWED_THEME_COLORS = frozenset({"blue", "green", "red", "yellow", "purple", "orange", "cyan", "pink"})
    # Only allow valid CSS hex colors: #rgb (3), #rrggbb (6), or #rrggbbaa (8)
    COLOR_PATTERN = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
    MAX_DATA_POINTS = 500
    MAX_DATASETS = 20
    MAX_CHART_LABELS = 500
    MAX_CHART_WIDTH = 2000
    MAX_CHART_HEIGHT = 1500

    # --- className validation (alphanumeric, hyphens, underscores, spaces) ---
    CLASS_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_ -]*$")

    # --- Key name validation (for form field keys used in data attributes) ---
    # Require leading alpha to be consistent with CLASS_NAME_PATTERN and valid CSS selectors
    KEY_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.\-]*$")

    # --- ReDoS detection: reject patterns with nested quantifiers ---
    # Catches (a+)+, (a*)+, (a+)*, (a{1,})+, etc.
    _REDOS_NESTED_QUANTIFIER = re.compile(
        r"[+*}]\s*\)"  # quantifier before group close
        r"[+*{?]"  # followed by another quantifier
    )
    _REDOS_ALTERNATION_QUANTIFIER = re.compile(
        r"\([^)]*\|[^)]*\)"  # group with alternation
        r"[+*{]"  # followed by quantifier
    )
    # Catch quantifiers ANYWHERE inside a quantified group: (.*a)+, ([a-z]*a)+, etc.
    # These cause exponential backtracking even though the inner quantifier isn't adjacent to the paren.
    _REDOS_INNER_QUANTIFIER = re.compile(
        r"\([^)]*[+*][^)]*\)"  # group containing a quantifier anywhere inside
        r"\s*[+*{]"  # followed by outer quantifier
    )

    @classmethod
    def _is_redos_safe(cls, pattern: str) -> bool:
        """Check if a regex pattern is likely safe from catastrophic backtracking.

        Rejects patterns with nested quantifiers like (a+)+, (.*)*,
        (.*a)+ (inner quantifier not adjacent to paren), and
        alternation under quantifiers like (a|b)+ with overlap.
        """
        if cls._REDOS_NESTED_QUANTIFIER.search(pattern):
            return False
        if cls._REDOS_ALTERNATION_QUANTIFIER.search(pattern):
            return False
        if cls._REDOS_INNER_QUANTIFIER.search(pattern):
            return False
        return True

    def validate_state(self, raw_json: str) -> tuple[bool, str, dict]:  # noqa: C901 — TODO: extract step helpers
        """Validate a state.json payload.

        Returns:
            (is_valid, error_message, parsed_state)
            If invalid, error_message describes why. parsed_state is the
            original parsed JSON (not sanitized — rejection is the model,
            not mutation).
        """
        # 1. Size check
        payload_bytes = len(raw_json.encode("utf-8"))
        if payload_bytes > self.MAX_PAYLOAD_SIZE:
            return False, f"Payload too large: {payload_bytes} bytes (max {self.MAX_PAYLOAD_SIZE})", {}

        # 2. Parse JSON
        try:
            state = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}", {}

        if not isinstance(state, dict):
            return False, "State must be a JSON object", {}

        # 2b. Top-level key allowlist — reject unknown keys (defense against LLM injection)
        ALLOWED_TOP_KEYS = frozenset(
            {
                "version",
                "updated_at",
                "status",
                "title",
                "message",
                "message_format",
                "message_className",
                "data",
                "actions_requested",
                "custom_css",
                "behaviors",
                "layout",
                "panels",
                "pages",
                "activePage",
                "showNav",
            }
        )
        unknown = set(state.keys()) - ALLOWED_TOP_KEYS
        if unknown:
            return False, f"Unknown top-level keys: {', '.join(sorted(unknown))}", {}

        # 2c. Validate message_className if present
        msg_cls = state.get("message_className", "")
        if msg_cls:
            ok, err = self._validate_class_name(msg_cls, "message_className")
            if not ok:
                return False, err, {}

        # 3. Check nesting depth
        if not self._check_depth(state):
            return False, f"Nesting depth exceeds {self.MAX_NESTING_DEPTH}", {}

        # 4. Validate status (normalize aliases first)
        status = state.get("status", "")
        if status:
            status = self.STATUS_ALIASES.get(status, status)
            state["status"] = status
        if status and status not in self.ALLOWED_STATUS_VALUES:
            return False, f"Invalid status: {status!r}", {}

        # 4b. Validate message_format
        msg_fmt = state.get("message_format", "")
        if msg_fmt and msg_fmt not in self.ALLOWED_FORMATS:
            return False, f"Invalid message_format: {msg_fmt!r}", {}

        # 4c. Validate showNav
        show_nav = state.get("showNav")
        if show_nav is not None and not isinstance(show_nav, bool):
            return False, "showNav must be a boolean", {}

        # 5. Scan all strings for XSS patterns (including custom_css — CSS validation
        # catches CSS-specific attacks, but XSS patterns like <script> must also be caught)
        xss_warnings = self._scan_xss(state)
        if xss_warnings:
            return False, f"XSS pattern detected: {xss_warnings[0]}", {}

        # 6. Validate UI schema if present
        data = state.get("data", {})
        if isinstance(data, dict):
            ui = data.get("ui", data)
            if isinstance(ui, dict):
                ok, err = self._validate_ui(ui)
                if not ok:
                    return False, err, {}

        # 7. Validate custom_css if present
        custom_css = state.get("custom_css", "")
        if custom_css:
            ok, err = self.validate_css(custom_css)
            if not ok:
                return False, f"custom_css: {err}", {}

        # 8. Validate top-level actions_requested
        actions = state.get("actions_requested", [])
        if isinstance(actions, list):
            ok, err = self._validate_actions(actions)
            if not ok:
                return False, err, {}

        # 9. Validate behaviors if present
        behaviors = state.get("behaviors", [])
        if behaviors:
            if not isinstance(behaviors, list):
                return False, "behaviors must be an array", {}
            ok, err = self._validate_behaviors(behaviors)
            if not ok:
                return False, err, {}

        # 10. Validate layout if present
        layout = state.get("layout")
        if layout:
            if not isinstance(layout, dict):
                return False, "layout must be an object", {}
            ok, err = self._validate_layout(layout, state.get("panels", {}))
            if not ok:
                return False, err, {}

        # 11. Validate pages if present
        pages = state.get("pages")
        if pages is not None:
            if not isinstance(pages, dict):
                return False, "pages must be an object", {}
            if len(pages) > self.MAX_PAGES:
                return False, f"Too many pages: {len(pages)} (max {self.MAX_PAGES})", {}
            for pk, page in pages.items():
                if not isinstance(pk, str) or not self.KEY_PATTERN.match(pk):
                    return False, f"pages: invalid key {pk!r}", {}
                if not isinstance(page, dict):
                    return False, f"pages.{pk} must be an object", {}
                page_label = page.get("label", "")
                if page_label and not isinstance(page_label, str):
                    return False, f"pages.{pk}.label must be a string", {}
                if isinstance(page_label, str) and len(page_label) > 500:
                    return False, f"pages.{pk}.label: too long (max 500)", {}
                page_hidden = page.get("hidden")
                if page_hidden is not None and not isinstance(page_hidden, bool):
                    return False, f"pages.{pk}.hidden must be a boolean", {}
                page_data = page.get("data", {})
                if isinstance(page_data, dict):
                    page_ui = page_data.get("ui", page_data)
                    if isinstance(page_ui, dict):
                        ok, err = self._validate_ui(page_ui)
                        if not ok:
                            return False, f"pages.{pk}: {err}", {}
                page_actions = page.get("actions_requested", [])
                if isinstance(page_actions, list) and page_actions:
                    ok, err = self._validate_actions(page_actions, f"pages.{pk}")
                    if not ok:
                        return False, err, {}

        active_page = state.get("activePage", "")
        if active_page:
            if not isinstance(active_page, str):
                return False, "activePage must be a string", {}
            if not self.KEY_PATTERN.match(active_page):
                return False, "activePage: invalid format", {}
            if pages and active_page not in pages:
                return False, f"activePage {active_page!r} not in pages", {}

        return True, "", state

    def validate_action(self, action: dict) -> tuple[bool, str]:
        """Validate an incoming action from the browser.

        Returns:
            (is_valid, error_message)
        """
        if not isinstance(action, dict):
            return False, "Action must be an object"

        action_id = action.get("action_id")
        if not isinstance(action_id, str) or not action_id:
            return False, "Action must have a non-empty action_id string"
        if len(action_id) > 200:
            return False, "action_id too long (max 200 chars)"

        action_type = action.get("type")
        if not isinstance(action_type, str):
            return False, "Action must have a type string"
        if action_type not in self.ALLOWED_ACTION_TYPES:
            return False, f"Invalid action type: {action_type!r}"

        # Value size limit
        value = action.get("value")
        if value is not None:
            try:
                value_json = json.dumps(value)
            except (TypeError, ValueError):
                return False, "Action value is not JSON-serializable"
            if len(value_json) > 100_000:
                return False, f"Action value too large: {len(value_json)} bytes (max 100000)"

        # Context (optional, for item-level actions)
        context = action.get("context")
        if context is not None:
            if not isinstance(context, dict):
                return False, "Action context must be an object"
            try:
                context_json = json.dumps(context)
            except (TypeError, ValueError):
                return False, "Action context is not JSON-serializable"
            if len(context_json) > 10_000:
                return False, f"Action context too large: {len(context_json)} bytes (max 10000)"

        # Depth check before XSS scan (prevents RecursionError DoS)
        if not self._check_depth(action):
            return False, "Action nesting exceeds maximum depth"

        # XSS scan action values (defense-in-depth: actions are broadcast to other WS clients)
        xss = self._scan_xss(action, "action")
        if xss:
            return False, f"XSS detected in action: {xss[0]}"

        return True, ""

    # --- CSS validation ---

    def validate_css(self, css: str) -> tuple[bool, str]:
        """Validate a custom CSS string for safety.

        Blocks dangerous CSS patterns that could execute JavaScript or load
        external resources. Returns (is_valid, error_message).
        """
        if not isinstance(css, str):
            return False, "custom_css must be a string"
        if len(css) > self.MAX_CSS_LENGTH:
            return False, f"custom_css too large: {len(css)} chars (max {self.MAX_CSS_LENGTH})"
        # Check zero-width characters
        if self.ZERO_WIDTH_CHARS.search(css):
            return False, "custom_css contains zero-width characters (potential filter bypass)"
        # Strip zero-width chars before pattern matching (defense-in-depth)
        clean = self.ZERO_WIDTH_CHARS.sub("", css)
        for pattern in self.DANGEROUS_CSS_PATTERNS:
            if pattern.search(clean):
                snippet = css[:80] + ("..." if len(css) > 80 else "")
                return False, f"dangerous CSS pattern {pattern.pattern!r} in {snippet!r}"
        return True, ""

    def _validate_class_name(self, cls: str, path: str) -> tuple[bool, str]:
        """Validate a className string for safety."""
        if not isinstance(cls, str):
            return False, f"{path}.className must be a string"
        if not cls:
            return True, ""  # empty is fine
        if len(cls) > 500:
            return False, f"{path}.className too long ({len(cls)} chars, max 500)"
        if not self.CLASS_NAME_PATTERN.match(cls):
            return (
                False,
                f"{path}.className: invalid characters in {cls!r} (must match {self.CLASS_NAME_PATTERN.pattern})",
            )
        return True, ""

    # --- Internal helpers ---

    def _check_depth(self, obj: Any, depth: int = 0) -> bool:
        if depth > self.MAX_NESTING_DEPTH:
            return False
        if isinstance(obj, dict):
            return all(self._check_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return all(self._check_depth(v, depth + 1) for v in obj)
        return True

    def _scan_xss(self, obj: Any, path: str = "") -> list[str]:
        """Recursively scan all string values for XSS patterns."""
        warnings = []
        if isinstance(obj, str):
            if len(obj) > self.MAX_STRING_LENGTH:
                warnings.append(f"{path}: string too long ({len(obj)} chars)")
                return warnings
            # Check for zero-width characters (used to bypass pattern matching)
            if self.ZERO_WIDTH_CHARS.search(obj):
                snippet = repr(obj[:80]) + ("..." if len(obj) > 80 else "")
                warnings.append(f"{path}: contains zero-width characters (potential filter bypass) in {snippet}")
                return warnings
            # Normalize unicode (NFC) and strip zero-width chars before pattern matching.
            # NFC normalization prevents bypass via decomposed characters (e.g. combining
            # accents that visually look like ASCII but bypass regex matching).
            clean = unicodedata.normalize("NFC", obj)
            clean = self.ZERO_WIDTH_CHARS.sub("", clean)
            for pattern in self.XSS_PATTERNS:
                if pattern.search(clean):
                    # Truncate the match for the warning message
                    snippet = obj[:80] + ("..." if len(obj) > 80 else "")
                    warnings.append(f"{path}: matched {pattern.pattern!r} in {snippet!r}")
                    return warnings  # one warning per value is enough
        elif isinstance(obj, dict):
            for k, v in obj.items():
                warnings.extend(self._scan_xss(k, f"{path}.<key:{k[:50]}>"))
                if warnings:
                    return warnings
                warnings.extend(self._scan_xss(v, f"{path}.{k[:50]}"))
                if warnings:
                    return warnings
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                warnings.extend(self._scan_xss(v, f"{path}[{i}]"))
                if warnings:
                    return warnings
        return warnings

    MAX_SECTION_DEPTH = 3  # Maximum nesting depth for tabs-within-tabs

    def _validate_ui(self, ui: dict, _depth: int = 0) -> tuple[bool, str]:  # noqa: C901 — TODO: extract field/item validators
        """Validate the UI schema structure."""
        if _depth > self.MAX_SECTION_DEPTH:
            return False, f"Section nesting too deep (max {self.MAX_SECTION_DEPTH} levels)"
        sections = ui.get("sections", [])
        if not isinstance(sections, list):
            return False, "ui.sections must be an array"
        if len(sections) > self.MAX_SECTIONS:
            return False, f"Too many sections: {len(sections)} (max {self.MAX_SECTIONS})"

        for i, sec in enumerate(sections):
            if not isinstance(sec, dict):
                return False, f"sections[{i}] must be an object"
            sec_type = sec.get("type", "form")
            if sec_type not in self.ALLOWED_SECTION_TYPES:
                return False, f"sections[{i}].type: invalid type {sec_type!r}"

            # Validate section format
            sec_fmt = sec.get("format", "")
            if sec_fmt and sec_fmt not in self.ALLOWED_FORMATS:
                return False, f"sections[{i}].format: invalid format {sec_fmt!r}"

            # Validate section className
            sec_cls = sec.get("className", "")
            if sec_cls:
                ok, err = self._validate_class_name(sec_cls, f"sections[{i}]")
                if not ok:
                    return False, err

            # Validate section id
            sec_id = sec.get("id", "")
            if sec_id:
                if not isinstance(sec_id, str) or not self.KEY_PATTERN.match(sec_id):
                    return False, f"sections[{i}].id: invalid"

            # Validate universal section properties
            collapsible = sec.get("collapsible")
            if collapsible is not None and not isinstance(collapsible, bool):
                return False, f"sections[{i}].collapsible must be a boolean"
            collapsed = sec.get("collapsed")
            if collapsed is not None and not isinstance(collapsed, bool):
                return False, f"sections[{i}].collapsed must be a boolean"
            copyable = sec.get("copyable")
            if copyable is not None and not isinstance(copyable, bool):
                return False, f"sections[{i}].copyable must be a boolean"

            # Validate fields
            fields = sec.get("fields", [])
            if isinstance(fields, list):
                if len(fields) > self.MAX_FIELDS_PER_SECTION:
                    return False, f"sections[{i}]: too many fields ({len(fields)})"
                seen_keys: set[str] = set()
                for j, f in enumerate(fields):
                    if not isinstance(f, dict):
                        continue
                    field_type = f.get("type", "text")
                    if field_type not in self.ALLOWED_FIELD_TYPES:
                        return False, f"sections[{i}].fields[{j}].type: invalid {field_type!r}"
                    key = f.get("key", "")
                    if key and not self.KEY_PATTERN.match(key):
                        return (
                            False,
                            f"sections[{i}].fields[{j}].key: invalid key {key!r} (must match {self.KEY_PATTERN.pattern})",
                        )
                    # Reject duplicate field keys within the same form section
                    if key:
                        if key in seen_keys:
                            return (
                                False,
                                f"sections[{i}].fields[{j}].key: duplicate key {key!r}",
                            )
                        seen_keys.add(key)
                    # Check field format
                    field_fmt = f.get("format", "")
                    if field_fmt and field_fmt not in self.ALLOWED_FORMATS:
                        return False, f"sections[{i}].fields[{j}].format: invalid format {field_fmt!r}"
                    desc_fmt = f.get("description_format", "")
                    if desc_fmt and desc_fmt not in self.ALLOWED_FORMATS:
                        return (
                            False,
                            f"sections[{i}].fields[{j}].description_format: invalid format {desc_fmt!r}",
                        )
                    # Check field className
                    field_cls = f.get("className", "")
                    if field_cls:
                        ok, err = self._validate_class_name(field_cls, f"sections[{i}].fields[{j}]")
                        if not ok:
                            return False, err
                    # Check options count
                    options = f.get("options", [])
                    if isinstance(options, list) and len(options) > self.MAX_OPTIONS_PER_FIELD:
                        return False, f"sections[{i}].fields[{j}]: too many options ({len(options)})"
                    # Validate new field validation properties
                    ok, err = self._validate_field_validation(f, f"sections[{i}].fields[{j}]")
                    if not ok:
                        return False, err

            # Validate items
            items = sec.get("items", [])
            if isinstance(items, list):
                if len(items) > self.MAX_ITEMS_PER_SECTION:
                    return False, f"sections[{i}]: too many items ({len(items)})"
                for k, item in enumerate(items):
                    if isinstance(item, dict):
                        item_fmt = item.get("format", "")
                        if item_fmt and item_fmt not in self.ALLOWED_FORMATS:
                            return False, f"sections[{i}].items[{k}].format: invalid format {item_fmt!r}"
                        item_cls = item.get("className", "")
                        if item_cls:
                            ok, err = self._validate_class_name(item_cls, f"sections[{i}].items[{k}]")
                            if not ok:
                                return False, err
                        item_id = item.get("id", "")
                        if item_id:
                            if not isinstance(item_id, str) or len(item_id) > 500:
                                return False, f"sections[{i}].items[{k}].id: invalid"
                        # navigateTo — client-side page navigation on item click
                        item_nav = item.get("navigateTo", "")
                        if item_nav:
                            if not isinstance(item_nav, str):
                                return False, f"sections[{i}].items[{k}].navigateTo must be a string"
                            if len(item_nav) > 200:
                                return False, f"sections[{i}].items[{k}].navigateTo too long (max 200)"
                            if not self.KEY_PATTERN.match(item_nav):
                                return False, f"sections[{i}].items[{k}].navigateTo: invalid format"

            # Validate new section-type-specific schemas
            ok, err = self._validate_section_specific(sec, sec_type, i, _depth=_depth)
            if not ok:
                return False, err

            # Validate section-level actions
            sec_actions = sec.get("actions", [])
            if isinstance(sec_actions, list):
                ok, err = self._validate_actions(sec_actions, f"sections[{i}]")
                if not ok:
                    return False, err

        return True, ""

    def _validate_actions(self, actions: list, prefix: str = "") -> tuple[bool, str]:
        """Validate an actions array."""
        if not isinstance(actions, list):
            return False, f"{prefix}.actions must be an array"
        if len(actions) > self.MAX_ACTIONS:
            return False, f"{prefix}: too many actions ({len(actions)})"
        for i, a in enumerate(actions):
            if not isinstance(a, dict):
                return False, f"{prefix}.actions[{i}] must be an object"
            aid = a.get("id", "")
            if aid and not isinstance(aid, str):
                return False, f"{prefix}.actions[{i}].id must be a string"
            if aid and len(aid) > 200:
                return False, f"{prefix}.actions[{i}].id too long"
            atype = a.get("type", "")
            if atype and atype not in self.ALLOWED_ACTION_TYPES:
                return False, f"{prefix}.actions[{i}].type: invalid {atype!r}"
            astyle = a.get("style", "")
            if astyle and astyle not in self.ALLOWED_ACTION_STYLES:
                return False, f"{prefix}.actions[{i}].style: invalid {astyle!r}"
            # navigateTo — client-side page navigation (no agent round-trip)
            nav_to = a.get("navigateTo", "")
            if nav_to:
                if not isinstance(nav_to, str):
                    return False, f"{prefix}.actions[{i}].navigateTo must be a string"
                if len(nav_to) > 200:
                    return False, f"{prefix}.actions[{i}].navigateTo too long (max 200)"
                if not self.KEY_PATTERN.match(nav_to):
                    return False, f"{prefix}.actions[{i}].navigateTo: invalid format"
        return True, ""

    # --- Field validation properties ---

    def _validate_field_validation(self, field: dict, path: str) -> tuple[bool, str]:  # noqa: C901 — TODO: split per-property validators
        """Validate new field validation properties (required, pattern, etc.)."""
        required = field.get("required")
        if required is not None and not isinstance(required, bool):
            return False, f"{path}.required must be a boolean"

        pattern = field.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                return False, f"{path}.pattern must be a string"
            if len(pattern) > 500:
                return False, f"{path}.pattern too long (max 500 chars)"
            if not self._is_redos_safe(pattern):
                return False, f"{path}.pattern contains nested quantifiers (ReDoS risk)"
            xss = self._scan_xss(pattern, f"{path}.pattern")
            if xss:
                return False, xss[0]

        min_len = field.get("minLength")
        if min_len is not None:
            if isinstance(min_len, bool) or not isinstance(min_len, int) or min_len < 0:
                return False, f"{path}.minLength must be a non-negative integer"

        max_len = field.get("maxLength")
        if max_len is not None:
            if isinstance(max_len, bool) or not isinstance(max_len, int) or max_len < 0:
                return False, f"{path}.maxLength must be a non-negative integer"

        for prop in ("min", "max"):
            val = field.get(prop)
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, int | float):
                    return False, f"{path}.{prop} must be a number"
                if isinstance(val, float) and not math.isfinite(val):
                    return False, f"{path}.{prop} must be a finite number"

        err_msg = field.get("errorMessage")
        if err_msg is not None:
            if not isinstance(err_msg, str):
                return False, f"{path}.errorMessage must be a string"
            if len(err_msg) > 500:
                return False, f"{path}.errorMessage too long (max 500 chars)"
            xss = self._scan_xss(err_msg, f"{path}.errorMessage")
            if xss:
                return False, xss[0]

        # Validate textarea rows
        rows = field.get("rows")
        if rows is not None:
            if isinstance(rows, bool) or not isinstance(rows, int) or rows < 1 or rows > 50:
                return False, f"{path}.rows must be an integer 1-50"

        # Validate placeholder length
        placeholder = field.get("placeholder")
        if placeholder is not None:
            if not isinstance(placeholder, str):
                return False, f"{path}.placeholder must be a string"
            if len(placeholder) > 500:
                return False, f"{path}.placeholder too long (max 500 chars)"

        # Validate unit (used by slider and metric fields)
        unit = field.get("unit")
        if unit is not None:
            if not isinstance(unit, str):
                return False, f"{path}.unit must be a string"
            if len(unit) > 20:
                return False, f"{path}.unit too long (max 20 chars)"

        # Slider-specific validation
        field_type = field.get("type", "text")
        if field_type == "slider":
            for prop in ("min", "max", "step", "value"):
                val = field.get(prop)
                if val is not None:
                    if isinstance(val, bool) or not isinstance(val, int | float):
                        return False, f"{path}.{prop} must be a number for slider type"
                    if isinstance(val, float) and not math.isfinite(val):
                        return False, f"{path}.{prop} must be a finite number"
            sl_min = field.get("min")
            sl_max = field.get("max")
            if sl_min is not None and sl_max is not None and sl_min >= sl_max:
                return False, f"{path}: slider min must be less than max"
            sl_val = field.get("value")
            if sl_min is not None and sl_max is not None and sl_val is not None:
                if sl_val < sl_min or sl_val > sl_max:
                    return False, f"{path}: slider value must be between min and max"

        # Date/datetime-specific validation
        _DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
        _DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
        if field_type in ("date", "datetime"):
            pattern_re = _DATE_RE if field_type == "date" else _DATETIME_RE
            fmt_name = "YYYY-MM-DD" if field_type == "date" else "YYYY-MM-DDTHH:MM"
            for prop in ("value", "min", "max"):
                val = field.get(prop)
                if val is not None:
                    if not isinstance(val, str):
                        return False, f"{path}.{prop} must be a string for {field_type} type"
                    if not pattern_re.match(val):
                        return False, f"{path}.{prop}: must match {fmt_name} format"

        # Autocomplete-specific validation
        if field_type == "autocomplete":
            allow_custom = field.get("allowCustom")
            if allow_custom is not None and not isinstance(allow_custom, bool):
                return False, f"{path}.allowCustom must be a boolean"

        # File-specific validation
        if field_type == "file":
            accept = field.get("accept")
            if accept is not None:
                if not isinstance(accept, str):
                    return False, f"{path}.accept must be a string"
                if len(accept) > 500:
                    return False, f"{path}.accept too long (max 500 chars)"
                # Allow only safe characters: MIME types (letters/digits/+/-/./*)
                # and extensions (.ext), comma+space separators
                _ACCEPT_RE = re.compile(r"^[a-zA-Z0-9+\-.*/, ]+$")
                if not _ACCEPT_RE.match(accept):
                    return False, f"{path}.accept contains invalid characters"
            multiple = field.get("multiple")
            if multiple is not None and not isinstance(multiple, bool):
                return False, f"{path}.multiple must be a boolean"
            max_size = field.get("maxSize")
            if max_size is not None:
                if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size < 1:
                    return False, f"{path}.maxSize must be a positive integer (bytes)"

        return True, ""

    # --- Section-type-specific validation ---

    def _validate_section_specific(self, sec: dict, sec_type: str, idx: int, _depth: int = 0) -> tuple[bool, str]:  # noqa: C901 — TODO: dispatch to per-type validators
        """Validate section-type-specific properties."""
        prefix = f"sections[{idx}]"

        if sec_type == "progress":
            tasks = sec.get("tasks", [])
            if not isinstance(tasks, list):
                return False, f"{prefix}.tasks must be an array"
            if len(tasks) > self.MAX_ITEMS_PER_SECTION:
                return False, f"{prefix}: too many tasks ({len(tasks)})"
            for ti, task in enumerate(tasks):
                if not isinstance(task, dict):
                    return False, f"{prefix}.tasks[{ti}] must be an object"
                ts = task.get("status", "")
                if ts:
                    ts = self.TASK_STATUS_ALIASES.get(ts, ts)
                    task["status"] = ts
                if ts and ts not in self.ALLOWED_TASK_STATUSES:
                    return False, f"{prefix}.tasks[{ti}].status: invalid {ts!r}"
            pct = sec.get("percentage")
            if pct is not None:
                if isinstance(pct, bool) or not isinstance(pct, int | float):
                    return False, f"{prefix}.percentage must be a number"
                if isinstance(pct, float) and not math.isfinite(pct):
                    return False, f"{prefix}.percentage must be a finite number"
                if pct < 0 or pct > 100:
                    return False, f"{prefix}.percentage must be 0-100"

        elif sec_type == "log":
            lines = sec.get("lines", [])
            if not isinstance(lines, list):
                return False, f"{prefix}.lines must be an array"
            if len(lines) > self.MAX_LOG_LINES:
                return False, f"{prefix}: too many log lines ({len(lines)}, max {self.MAX_LOG_LINES})"
            for li, line in enumerate(lines):
                if not isinstance(line, str):
                    return False, f"{prefix}.lines[{li}] must be a string"
            max_lines = sec.get("maxLines", 500)
            if isinstance(max_lines, bool) or not isinstance(max_lines, int) or max_lines < 1 or max_lines > 10000:
                return False, f"{prefix}.maxLines must be 1-10000"

        elif sec_type == "diff":
            content = sec.get("content", "")
            if not isinstance(content, str):
                return False, f"{prefix}.content must be a string"
            language = sec.get("language", "")
            if language and not re.match(r"^[a-zA-Z0-9_-]+$", language):
                return False, f"{prefix}.language: invalid"

        elif sec_type == "table":
            columns = sec.get("columns", [])
            if not isinstance(columns, list):
                return False, f"{prefix}.columns must be an array"
            if len(columns) > self.MAX_TABLE_COLUMNS:
                return False, f"{prefix}: too many columns ({len(columns)})"
            for ci, col in enumerate(columns):
                if not isinstance(col, dict):
                    return False, f"{prefix}.columns[{ci}] must be an object"
                col_key = col.get("key", "")
                if not col_key or not self.KEY_PATTERN.match(col_key):
                    return False, f"{prefix}.columns[{ci}].key: invalid"
            rows = sec.get("rows", [])
            if not isinstance(rows, list):
                return False, f"{prefix}.rows must be an array"
            if len(rows) > self.MAX_ITEMS_PER_SECTION:
                return False, f"{prefix}: too many rows ({len(rows)})"
            selectable = sec.get("selectable", False)
            if not isinstance(selectable, bool):
                return False, f"{prefix}.selectable must be a boolean"
            # Clickable rows (drill-down on row click)
            clickable = sec.get("clickable", False)
            if not isinstance(clickable, bool):
                return False, f"{prefix}.clickable must be a boolean"
            click_action_id = sec.get("clickActionId", "")
            if click_action_id:
                if not isinstance(click_action_id, str):
                    return False, f"{prefix}.clickActionId must be a string"
                if len(click_action_id) > 200:
                    return False, f"{prefix}.clickActionId too long (max 200)"
                if not self.KEY_PATTERN.match(click_action_id):
                    return False, f"{prefix}.clickActionId: invalid format"
            # navigateToField — client-side page navigation from row data
            nav_field = sec.get("navigateToField", "")
            if nav_field:
                if not isinstance(nav_field, str):
                    return False, f"{prefix}.navigateToField must be a string"
                if len(nav_field) > 200:
                    return False, f"{prefix}.navigateToField too long (max 200)"
                if not self.KEY_PATTERN.match(nav_field):
                    return False, f"{prefix}.navigateToField: invalid format"
            # Client-side table filter
            filterable = sec.get("filterable", False)
            if not isinstance(filterable, bool):
                return False, f"{prefix}.filterable must be a boolean"
            filter_ph = sec.get("filterPlaceholder", "")
            if filter_ph and (not isinstance(filter_ph, str) or len(filter_ph) > 200):
                return False, f"{prefix}.filterPlaceholder: invalid"

        elif sec_type == "metric":
            cards = sec.get("cards", [])
            if not isinstance(cards, list):
                return False, f"{prefix}.cards must be an array"
            if len(cards) > self.MAX_ITEMS_PER_SECTION:
                return False, f"{prefix}: too many cards ({len(cards)})"
            for ci, card in enumerate(cards):
                if not isinstance(card, dict):
                    return False, f"{prefix}.cards[{ci}] must be an object"
                label = card.get("label")
                if not isinstance(label, str) or not label:
                    return False, f"{prefix}.cards[{ci}].label: required string"
                if len(label) > 500:
                    return False, f"{prefix}.cards[{ci}].label: too long (max 500)"
                value = card.get("value")
                if not isinstance(value, str | int | float):
                    return False, f"{prefix}.cards[{ci}].value: must be string or number"
                if isinstance(value, float) and not math.isfinite(value):
                    return False, f"{prefix}.cards[{ci}].value: must be finite"
                unit = card.get("unit", "")
                if unit and (not isinstance(unit, str) or len(unit) > 50):
                    return False, f"{prefix}.cards[{ci}].unit: invalid"
                change = card.get("change", "")
                if change and (not isinstance(change, str) or len(change) > 100):
                    return False, f"{prefix}.cards[{ci}].change: invalid"
                cd = card.get("changeDirection", "")
                if cd and cd not in self.ALLOWED_CHANGE_DIRECTIONS:
                    return False, f"{prefix}.cards[{ci}].changeDirection: invalid {cd!r}"
                sparkline = card.get("sparkline")
                if sparkline is not None:
                    if not isinstance(sparkline, list):
                        return False, f"{prefix}.cards[{ci}].sparkline must be an array"
                    if len(sparkline) > self.MAX_SPARKLINE_POINTS:
                        return False, f"{prefix}.cards[{ci}].sparkline: too many points"
                    for si_val, pt in enumerate(sparkline):
                        if not isinstance(pt, int | float):
                            return False, f"{prefix}.cards[{ci}].sparkline[{si_val}]: must be number"
                        if isinstance(pt, float) and not math.isfinite(pt):
                            return False, f"{prefix}.cards[{ci}].sparkline[{si_val}]: must be finite"
                icon = card.get("icon", "")
                if icon and (not isinstance(icon, str) or not self.KEY_PATTERN.match(icon)):
                    return False, f"{prefix}.cards[{ci}].icon: invalid"
            cols = sec.get("columns", 4)
            if isinstance(cols, bool) or not isinstance(cols, int) or cols < 1 or cols > self.MAX_METRIC_COLUMNS:
                return False, f"{prefix}.columns must be 1-{self.MAX_METRIC_COLUMNS}"

        elif sec_type == "chart":
            chart_type = sec.get("chartType", "")
            if not chart_type or chart_type not in self.ALLOWED_CHART_TYPES:
                return False, f"{prefix}.chartType: invalid {chart_type!r}"

            # Charts accept two data formats:
            #   1. Explicit: data.labels + data.datasets  (chart-native)
            #   2. Tabular:  columns + rows               (same as table sections)
            # The client-side renderer converts tabular → chart-native at render time.
            has_data = isinstance(sec.get("data"), dict)
            has_columns = isinstance(sec.get("columns"), list)

            if has_columns:
                # Tabular format — validate columns/rows like table sections
                cols = sec["columns"]
                if len(cols) < 1:
                    return False, f"{prefix}.columns: need at least 1 column"
                if len(cols) > self.MAX_TABLE_COLUMNS:
                    return False, f"{prefix}.columns: too many ({len(cols)})"
                for ci, col in enumerate(cols):
                    if not isinstance(col, dict):
                        return False, f"{prefix}.columns[{ci}] must be an object"
                    key = col.get("key", "")
                    if not key or not isinstance(key, str):
                        return False, f"{prefix}.columns[{ci}].key must be a non-empty string"
                    if not self.KEY_PATTERN.match(key):
                        return False, f"{prefix}.columns[{ci}].key: invalid format"
                rows = sec.get("rows", [])
                if not isinstance(rows, list):
                    return False, f"{prefix}.rows must be an array"
                if len(rows) > self.MAX_ITEMS_PER_SECTION:
                    return False, f"{prefix}.rows: too many ({len(rows)})"
                for ri, row in enumerate(rows):
                    if not isinstance(row, dict):
                        return False, f"{prefix}.rows[{ri}] must be an object"

            elif has_data:
                # Chart-native format — validate labels + datasets
                data = sec["data"]
                labels = data.get("labels", [])
                if not isinstance(labels, list):
                    return False, f"{prefix}.data.labels must be an array"
                if len(labels) > self.MAX_CHART_LABELS:
                    return False, f"{prefix}.data.labels: too many ({len(labels)})"
                for li, lbl in enumerate(labels):
                    if not isinstance(lbl, str):
                        return False, f"{prefix}.data.labels[{li}]: must be string"
                    if len(lbl) > 500:
                        return False, f"{prefix}.data.labels[{li}]: too long (max 500)"
                datasets = data.get("datasets", [])
                if not isinstance(datasets, list):
                    return False, f"{prefix}.data.datasets must be an array"
                if len(datasets) > self.MAX_DATASETS:
                    return False, f"{prefix}.data.datasets: too many"
                for di, ds in enumerate(datasets):
                    if not isinstance(ds, dict):
                        return False, f"{prefix}.data.datasets[{di}] must be an object"
                    values = ds.get("values", [])
                    if not isinstance(values, list):
                        return False, f"{prefix}.data.datasets[{di}].values must be an array"
                    if len(values) > self.MAX_DATA_POINTS:
                        return False, f"{prefix}.data.datasets[{di}].values: too many points"
                    for vi, v in enumerate(values):
                        if not isinstance(v, int | float):
                            return False, f"{prefix}.data.datasets[{di}].values[{vi}]: must be number"
                        if isinstance(v, float) and not math.isfinite(v):
                            return False, f"{prefix}.data.datasets[{di}].values[{vi}]: must be finite"
                    color = ds.get("color", "")
                    if color:
                        if not isinstance(color, str):
                            return False, f"{prefix}.data.datasets[{di}].color: must be string"
                        if color not in self.ALLOWED_THEME_COLORS and not self.COLOR_PATTERN.match(color):
                            return False, f"{prefix}.data.datasets[{di}].color: invalid"
                    colors = ds.get("colors", [])
                    if colors:
                        if not isinstance(colors, list):
                            return False, f"{prefix}.data.datasets[{di}].colors must be an array"
                        for cci, c in enumerate(colors):
                            if not isinstance(c, str):
                                return False, f"{prefix}.data.datasets[{di}].colors[{cci}]: must be string"
                            if c not in self.ALLOWED_THEME_COLORS and not self.COLOR_PATTERN.match(c):
                                return False, f"{prefix}.data.datasets[{di}].colors[{cci}]: invalid"
                    ds_label = ds.get("label", "")
                    if ds_label and not isinstance(ds_label, str):
                        return False, f"{prefix}.data.datasets[{di}].label: must be string"
                    if isinstance(ds_label, str) and len(ds_label) > 500:
                        return False, f"{prefix}.data.datasets[{di}].label: too long (max 500)"

            else:
                return False, f"{prefix}: chart requires either data or columns"

            options = sec.get("options", {})
            if not isinstance(options, dict):
                return False, f"{prefix}.options must be an object"
            w = options.get("width")
            if w is not None and (isinstance(w, bool) or not isinstance(w, int) or w < 50 or w > self.MAX_CHART_WIDTH):
                return False, f"{prefix}.options.width: must be 50-{self.MAX_CHART_WIDTH}"
            h = options.get("height")
            if h is not None and (isinstance(h, bool) or not isinstance(h, int) or h < 50 or h > self.MAX_CHART_HEIGHT):
                return False, f"{prefix}.options.height: must be 50-{self.MAX_CHART_HEIGHT}"
            for bool_opt in ("showLegend", "showGrid", "showValues", "stacked"):
                val = options.get(bool_opt)
                if val is not None and not isinstance(val, bool):
                    return False, f"{prefix}.options.{bool_opt}: must be boolean"

        elif sec_type == "tabs":
            tabs = sec.get("tabs", [])
            if not isinstance(tabs, list):
                return False, f"{prefix}.tabs must be an array"
            if len(tabs) > self.MAX_TABS:
                return False, f"{prefix}: too many tabs ({len(tabs)})"
            for ti, tab in enumerate(tabs):
                if not isinstance(tab, dict):
                    return False, f"{prefix}.tabs[{ti}] must be an object"
                tab_id = tab.get("id", "")
                if tab_id and not self.KEY_PATTERN.match(tab_id):
                    return False, f"{prefix}.tabs[{ti}].id: invalid"
                # Recursively validate nested sections (with depth tracking)
                nested = tab.get("sections", [])
                if isinstance(nested, list) and nested:
                    ok, err = self._validate_ui({"sections": nested}, _depth=_depth + 1)
                    if not ok:
                        return False, f"{prefix}.tabs[{ti}]: {err}"

        return True, ""

    # --- Behaviors validation ---

    def _validate_behaviors(self, behaviors: list) -> tuple[bool, str]:  # noqa: C901 — TODO: extract condition/effect validators
        """Validate client-side behavior rules."""
        if len(behaviors) > self.MAX_BEHAVIORS:
            return False, f"Too many behaviors: {len(behaviors)} (max {self.MAX_BEHAVIORS})"
        for i, b in enumerate(behaviors):
            if not isinstance(b, dict):
                return False, f"behaviors[{i}] must be an object"
            when = b.get("when")
            if not isinstance(when, dict):
                return False, f"behaviors[{i}].when must be an object"
            field = when.get("field", "")
            if not field or not isinstance(field, str) or not self.KEY_PATTERN.match(field):
                return False, f"behaviors[{i}].when.field: invalid key"
            # Check condition keys
            condition_keys = set(when.keys()) - {"field"}
            if not condition_keys:
                return False, f"behaviors[{i}].when: needs a condition"
            for ck in condition_keys:
                if ck not in self.ALLOWED_BEHAVIOR_CONDITIONS:
                    return False, f"behaviors[{i}].when: invalid condition {ck!r}"
            # Validate matches regex for XSS and ReDoS
            if "matches" in when:
                matches_val = when["matches"]
                if not isinstance(matches_val, str) or len(matches_val) > 500:
                    return False, f"behaviors[{i}].when.matches: invalid"
                if not self._is_redos_safe(matches_val):
                    return False, f"behaviors[{i}].when.matches: nested quantifiers (ReDoS risk)"
                xss = self._scan_xss(matches_val, f"behaviors[{i}].when.matches")
                if xss:
                    return False, xss[0]
            # Check effects
            has_effect = False
            for effect in self.ALLOWED_BEHAVIOR_EFFECTS:
                if effect in b:
                    has_effect = True
                    targets = b[effect]
                    if not isinstance(targets, list):
                        return False, f"behaviors[{i}].{effect} must be an array"
                    for t in targets:
                        if not isinstance(t, str) or not self.KEY_PATTERN.match(t):
                            return False, f"behaviors[{i}].{effect}: invalid target {t!r}"
            if not has_effect:
                return False, f"behaviors[{i}]: needs at least one effect (show/hide/enable/disable)"
        return True, ""

    # --- Layout validation ---

    def _validate_layout(self, layout: dict, panels: Any) -> tuple[bool, str]:
        """Validate layout and panels configuration."""
        layout_type = layout.get("type", "default")
        if layout_type not in self.ALLOWED_LAYOUT_TYPES:
            return False, f"layout.type: invalid {layout_type!r}"

        sidebar_width = layout.get("sidebarWidth", "")
        if sidebar_width:
            if not isinstance(sidebar_width, str):
                return False, "layout.sidebarWidth must be a string"
            if not self.CSS_LENGTH_PATTERN.match(sidebar_width):
                return False, f"layout.sidebarWidth: invalid format {sidebar_width!r}"

        if panels:
            if not isinstance(panels, dict):
                return False, "panels must be an object"
            for pk in panels:
                if pk not in self.ALLOWED_PANEL_KEYS:
                    return False, f"panels: invalid key {pk!r}"
                panel = panels[pk]
                if not isinstance(panel, dict):
                    return False, f"panels.{pk} must be an object"
                panel_sections = panel.get("sections", [])
                if isinstance(panel_sections, list) and panel_sections:
                    ok, err = self._validate_ui({"sections": panel_sections}, _depth=1)
                    if not ok:
                        return False, f"panels.{pk}: {err}"

        return True, ""
