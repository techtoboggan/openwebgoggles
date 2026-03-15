"""
Plugin discovery for OpenWebGoggles.

Scans plugin directories for .js files with `@owg-plugin type:` headers.
Returns PluginInfo objects for use by session/bundler/http_handler.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("openwebgoggles")

# Header pattern: // @owg-plugin type: my-custom-type
PLUGIN_HEADER_RE = re.compile(r"//\s*@owg-plugin\s+type:\s*([a-z][a-z0-9_-]{0,30})\s*$", re.MULTILINE)
PLUGIN_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")

# Content safety checks — defense-in-depth (not a sandbox)
_DANGEROUS_PATTERNS = [
    "eval(",
    "innerHTML",
    "document.write",
    "Function(",
    'setTimeout("',
    'setInterval("',
]

MAX_PLUGIN_SIZE = 102_400  # 100KB per plugin file


class PluginInfo(NamedTuple):
    """Metadata and content for a discovered plugin."""

    type_name: str
    path: Path
    content: str


def discover_plugins(
    *dirs: Path,
    max_plugins: int = 20,
) -> list[PluginInfo]:
    """Scan directories for plugin .js files and return valid ones.

    Each plugin file must:
    - Have a .js extension
    - Be under MAX_PLUGIN_SIZE bytes
    - Contain a ``// @owg-plugin type: <name>`` header comment
    - Not contain dangerous patterns (eval, innerHTML, etc.)

    Returns a list of PluginInfo in discovery order, deduplicated by type name.
    """
    plugins: list[PluginInfo] = []
    seen_types: set[str] = set()

    for plugin_dir in dirs:
        if not plugin_dir.is_dir():
            continue
        for js_file in sorted(plugin_dir.glob("*.js")):
            if len(plugins) >= max_plugins:
                logger.warning("Plugin limit reached (%d), skipping remaining", max_plugins)
                break

            try:
                size = js_file.stat().st_size
                if size > MAX_PLUGIN_SIZE:
                    logger.warning(
                        "Plugin %s too large (%d bytes, max %d) — skipped", js_file.name, size, MAX_PLUGIN_SIZE
                    )
                    continue

                content = js_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                logger.warning("Failed to read plugin %s: %s", js_file.name, e)
                continue

            # Extract type name from header
            match = PLUGIN_HEADER_RE.search(content[:500])  # Header should be near top
            if not match:
                logger.warning("Plugin %s missing @owg-plugin header — skipped", js_file.name)
                continue

            type_name = match.group(1)
            if type_name in seen_types:
                logger.warning("Duplicate plugin type %r in %s — skipped", type_name, js_file.name)
                continue

            # Safety checks
            dangerous = [p for p in _DANGEROUS_PATTERNS if p in content]
            if dangerous:
                logger.warning(
                    "Plugin %s contains dangerous patterns (%s) — skipped",
                    js_file.name,
                    ", ".join(dangerous),
                )
                continue

            plugins.append(PluginInfo(type_name=type_name, path=js_file, content=content))
            seen_types.add(type_name)
            logger.info("Discovered plugin: %s (type=%s, %d bytes)", js_file.name, type_name, len(content))

    return plugins


def get_plugin_dirs() -> list[Path]:
    """Return the default plugin directories to scan.

    1. ``~/.local/share/openwebgoggles/plugins/`` (or platform equivalent)
    2. ``.openwebgoggles/plugins/`` relative to CWD (project-local)
    """
    try:
        from session import _get_data_dir

        global_dir = _get_data_dir() / "plugins"
    except ImportError:
        global_dir = Path.home() / ".local" / "share" / "openwebgoggles" / "plugins"

    local_dir = Path.cwd() / ".openwebgoggles" / "plugins"
    return [global_dir, local_dir]
