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
    MAX_PAYLOAD_SIZE = 512_000          # 512KB total state
    MAX_STRING_LENGTH = 50_000          # 50KB per string value
    MAX_NESTING_DEPTH = 10
    MAX_SECTIONS = 50
    MAX_FIELDS_PER_SECTION = 100
    MAX_ITEMS_PER_SECTION = 500
    MAX_ACTIONS = 50
    MAX_OPTIONS_PER_FIELD = 200

    # --- Allowlists ---
    ALLOWED_FIELD_TYPES = frozenset({
        "text", "textarea", "number", "select", "checkbox",
        "email", "url", "static",
    })
    ALLOWED_SECTION_TYPES = frozenset({
        "form", "items", "text", "actions",
    })
    ALLOWED_ACTION_STYLES = frozenset({
        "primary", "success", "danger", "warning", "ghost",
        "approve", "reject", "confirm", "submit", "delete",
    })
    ALLOWED_ACTION_TYPES = frozenset({
        "approve", "reject", "confirm", "submit", "delete",
        "select", "input", "custom", "action",
        "primary", "danger", "success", "warning", "ghost",
    })
    ALLOWED_STATUS_VALUES = frozenset({
        "initializing", "ready", "pending_review", "waiting_input",
        "processing", "completed", "error",
    })

    # --- Zero-width characters that can bypass pattern matching ---
    # These invisible chars can be inserted between keywords (e.g. java[ZWS]script:)
    # to bypass regex-based XSS detection while still being rendered by browsers.
    ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u180e]")

    # --- XSS detection patterns (case-insensitive) ---
    XSS_PATTERNS = [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),          # event handlers
        re.compile(r"<\s*iframe", re.IGNORECASE),
        re.compile(r"<\s*object", re.IGNORECASE),
        re.compile(r"<\s*embed", re.IGNORECASE),
        re.compile(r"<\s*form\b", re.IGNORECASE),
        re.compile(r"<\s*meta\b", re.IGNORECASE),
        re.compile(r"<\s*link\b", re.IGNORECASE),
        re.compile(r"<\s*base\b", re.IGNORECASE),           # base tag can redirect relative URLs
        re.compile(r"<\s*svg[^>]*\bon", re.IGNORECASE),     # SVG with event handlers
        re.compile(r"<\s*math\b", re.IGNORECASE),           # MathML can be used for XSS
        re.compile(r"expression\s*\(", re.IGNORECASE),       # CSS expression()
        re.compile(r"-moz-binding\s*:", re.IGNORECASE),      # Firefox CSS binding
        re.compile(r"behavior\s*:\s*url\s*\(", re.IGNORECASE),  # IE CSS behavior
        re.compile(r"url\s*\(\s*[\"']?\s*javascript:", re.IGNORECASE),
        re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
        re.compile(r"\\u003c\s*script", re.IGNORECASE),      # Unicode-escaped
        re.compile(r"&#x0*3c;?\s*script", re.IGNORECASE),      # HTML hex entity &#x3c;
        re.compile(r"&#0*60;?\s*script", re.IGNORECASE),       # HTML decimal entity &#60;
        re.compile(r"vbscript\s*:", re.IGNORECASE),          # VBScript protocol
        re.compile(r"<\s*style\b", re.IGNORECASE),           # Style tag injection
    ]

    # --- Key name validation (for form field keys used in data attributes) ---
    KEY_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")

    def validate_state(self, raw_json: str) -> tuple[bool, str, dict]:
        """Validate a state.json payload.

        Returns:
            (is_valid, error_message, parsed_state)
            If invalid, error_message describes why. parsed_state is the
            original parsed JSON (not sanitized — rejection is the model,
            not mutation).
        """
        # 1. Size check
        if len(raw_json) > self.MAX_PAYLOAD_SIZE:
            return False, f"Payload too large: {len(raw_json)} bytes (max {self.MAX_PAYLOAD_SIZE})", {}

        # 2. Parse JSON
        try:
            state = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}", {}

        if not isinstance(state, dict):
            return False, "State must be a JSON object", {}

        # 3. Check nesting depth
        if not self._check_depth(state):
            return False, f"Nesting depth exceeds {self.MAX_NESTING_DEPTH}", {}

        # 4. Validate status
        status = state.get("status", "")
        if status and status not in self.ALLOWED_STATUS_VALUES:
            return False, f"Invalid status: {status!r}", {}

        # 5. Scan all strings for XSS patterns
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

        # 7. Validate top-level actions_requested
        actions = state.get("actions_requested", [])
        if isinstance(actions, list):
            ok, err = self._validate_actions(actions)
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
            value_json = json.dumps(value)
            if len(value_json) > 100_000:
                return False, f"Action value too large: {len(value_json)} bytes (max 100000)"

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
                warnings.extend(self._scan_xss(v, f"{path}.{k}"))
                if warnings:
                    return warnings
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                warnings.extend(self._scan_xss(v, f"{path}[{i}]"))
                if warnings:
                    return warnings
        return warnings

    def _validate_ui(self, ui: dict) -> tuple[bool, str]:
        """Validate the UI schema structure."""
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
                        return False, f"sections[{i}].fields[{j}].key: invalid key {key!r} (must match {self.KEY_PATTERN.pattern})"
                    # Check options count
                    options = f.get("options", [])
                    if isinstance(options, list) and len(options) > self.MAX_OPTIONS_PER_FIELD:
                        return False, f"sections[{i}].fields[{j}]: too many options ({len(options)})"

            # Validate items
            items = sec.get("items", [])
            if isinstance(items, list) and len(items) > self.MAX_ITEMS_PER_SECTION:
                return False, f"sections[{i}]: too many items ({len(items)})"

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
