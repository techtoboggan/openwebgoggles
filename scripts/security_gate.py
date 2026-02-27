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
import re
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
    ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u180e]")

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
    ALLOWED_TASK_STATUSES = frozenset({"pending", "in_progress", "completed", "failed", "skipped"})
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
        re.compile(r"url\s*\(", re.IGNORECASE),  # Block ALL url() — prevents data exfiltration via http(s)
        re.compile(r"\\u00[0-9a-fA-F]{2}"),  # Unicode escape obfuscation
        re.compile(r"\\[0-9a-fA-F]{1,6}"),  # CSS hex escape obfuscation
    ]

    # --- className validation (alphanumeric, hyphens, underscores, spaces) ---
    CLASS_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_ -]*$")

    # --- Key name validation (for form field keys used in data attributes) ---
    KEY_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")

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

    @classmethod
    def _is_redos_safe(cls, pattern: str) -> bool:
        """Check if a regex pattern is likely safe from catastrophic backtracking.

        Rejects patterns with nested quantifiers like (a+)+, (.*)*,
        and alternation under quantifiers like (a|b)+ with overlap.
        """
        if cls._REDOS_NESTED_QUANTIFIER.search(pattern):
            return False
        if cls._REDOS_ALTERNATION_QUANTIFIER.search(pattern):
            return False
        return True

    def validate_state(self, raw_json: str) -> tuple[bool, str, dict]:
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

        # 4. Validate status
        status = state.get("status", "")
        if status and status not in self.ALLOWED_STATUS_VALUES:
            return False, f"Invalid status: {status!r}", {}

        # 4b. Validate message_format
        msg_fmt = state.get("message_format", "")
        if msg_fmt and msg_fmt not in self.ALLOWED_FORMATS:
            return False, f"Invalid message_format: {msg_fmt!r}", {}

        # 5. Scan all strings for XSS patterns (skip custom_css — validated separately)
        state_for_xss = {k: v for k, v in state.items() if k != "custom_css"}
        xss_warnings = self._scan_xss(state_for_xss)
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
            # Strip zero-width chars before pattern matching (defense-in-depth)
            clean = self.ZERO_WIDTH_CHARS.sub("", obj)
            for pattern in self.XSS_PATTERNS:
                if pattern.search(clean):
                    # Truncate the match for the warning message
                    snippet = obj[:80] + ("..." if len(obj) > 80 else "")
                    warnings.append(f"{path}: matched {pattern.pattern!r} in {snippet!r}")
                    return warnings  # one warning per value is enough
        elif isinstance(obj, dict):
            for k, v in obj.items():
                warnings.extend(self._scan_xss(k, f"{path}.<key:{k[:20]}>"))
                if warnings:
                    return warnings
                warnings.extend(self._scan_xss(v, f"{path}.{k}"))
                if warnings:
                    return warnings
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                warnings.extend(self._scan_xss(v, f"{path}[{i}]"))
                if warnings:
                    return warnings
        return warnings

    MAX_SECTION_DEPTH = 3  # Maximum nesting depth for tabs-within-tabs

    def _validate_ui(self, ui: dict, _depth: int = 0) -> tuple[bool, str]:
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

            # Validate fields
            fields = sec.get("fields", [])
            if isinstance(fields, list):
                if len(fields) > self.MAX_FIELDS_PER_SECTION:
                    return False, f"sections[{i}]: too many fields ({len(fields)})"
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
        return True, ""

    # --- Field validation properties ---

    def _validate_field_validation(self, field: dict, path: str) -> tuple[bool, str]:
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
            if not isinstance(min_len, int) or min_len < 0:
                return False, f"{path}.minLength must be a non-negative integer"

        max_len = field.get("maxLength")
        if max_len is not None:
            if not isinstance(max_len, int) or max_len < 0:
                return False, f"{path}.maxLength must be a non-negative integer"

        for prop in ("min", "max"):
            val = field.get(prop)
            if val is not None and not isinstance(val, int | float):
                return False, f"{path}.{prop} must be a number"

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
            if not isinstance(rows, int) or rows < 1 or rows > 50:
                return False, f"{path}.rows must be an integer 1-50"

        # Validate placeholder length
        placeholder = field.get("placeholder")
        if placeholder is not None:
            if not isinstance(placeholder, str):
                return False, f"{path}.placeholder must be a string"
            if len(placeholder) > 500:
                return False, f"{path}.placeholder too long (max 500 chars)"

        return True, ""

    # --- Section-type-specific validation ---

    def _validate_section_specific(self, sec: dict, sec_type: str, idx: int, _depth: int = 0) -> tuple[bool, str]:
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
                if ts and ts not in self.ALLOWED_TASK_STATUSES:
                    return False, f"{prefix}.tasks[{ti}].status: invalid {ts!r}"
            pct = sec.get("percentage")
            if pct is not None:
                if not isinstance(pct, int | float):
                    return False, f"{prefix}.percentage must be a number"
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
            if not isinstance(max_lines, int) or max_lines < 1 or max_lines > 10000:
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

    def _validate_behaviors(self, behaviors: list) -> tuple[bool, str]:
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
