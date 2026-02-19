"""Shared test helpers."""
from __future__ import annotations

import json


def make_state(overrides: dict | None = None) -> str:
    """Build a minimal valid state.json payload, with optional overrides."""
    state = {
        "version": 1,
        "status": "ready",
        "title": "Test",
        "message": "Hello",
        "data": {
            "ui": {
                "sections": [
                    {
                        "type": "form",
                        "title": "Info",
                        "fields": [
                            {"key": "name", "type": "text", "label": "Name", "value": "Alice"}
                        ],
                    }
                ]
            }
        },
        "actions_requested": [
            {"id": "ok", "type": "confirm", "label": "OK", "style": "primary"}
        ],
    }
    if overrides:
        _deep_merge(state, overrides)
    return json.dumps(state)


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
