"""Data-driven registry of MCP-host editors that openwebgoggles can configure.

Every editor we support is described by a single ``EditorSpec`` entry below.
Adding a new editor (e.g. LibreCode, Zed, JetBrains, ...) is a registry change,
not a code change — once the spec captures where the editor reads its MCP
config from and which JSON shape it expects, both ``init`` and ``doctor``
pick it up automatically.

Two pieces of information matter:

  * ``init_target`` — where ``openwebgoggles init <editor>`` writes by default.
    ``None`` means "current working directory" (project-level config). A
    callable means a platform-specific or environment-specific path.

  * ``config_locations(target)`` — every place this editor *might* keep an
    MCP config that mentions openwebgoggles. ``doctor`` scans all of them
    looking for stale ``command`` paths to repair. The same editor can have
    multiple locations (Claude has both project ``.mcp.json`` and global
    ``~/.mcp.json``; OpenCode has project ``opencode.json`` and global
    ``~/.config/opencode/opencode.json``).

The registry is the *only* source of truth — ``_INIT_DISPATCH``,
``_EDITOR_DEFAULT_DIRS``, and the init usage text all derive from it.
"""

from __future__ import annotations

import platform
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ConfigSchema(Enum):
    """How a config file represents its MCP server table.

    ``MCP_SERVERS`` — the standard ``{"mcpServers": {"<name>": {...}}}`` shape
    used by Claude Desktop, Claude Code, Cursor, Windsurf, and most others.

    ``OPENCODE`` — OpenCode's variant: ``{"mcp": {"<name>": {"type": "local",
    "command": ["..."], "enabled": true}}}``. The ``command`` is a list, not
    a string, and the table key is ``mcp`` rather than ``mcpServers``.
    """

    MCP_SERVERS = "mcpServers"
    OPENCODE = "opencode"


@dataclass(frozen=True)
class ConfigLocation:
    """One concrete file that may hold an openwebgoggles MCP entry."""

    path: Path
    schema: ConfigSchema
    description: str  # human-readable, e.g. "Claude Code (project)"


@dataclass(frozen=True)
class EditorSpec:
    """Everything we need to know to init, scan, and repair one editor."""

    name: str  # CLI key — what the user types after `init`
    display_name: str  # for help text and prose
    summary: str  # one-line description shown in `init` usage

    # Where to write when the user runs `init <name>` with no target dir.
    # None  → cwd (project-level)
    # callable → resolves at call time (e.g. global config dir)
    init_target: Callable[[], Path] | None

    # Every config file we're prepared to edit/scan for this editor.
    # The argument is the user-supplied target dir for project-level lookups
    # (or cwd if not specified). Implementations should yield both project-
    # level and global candidates as appropriate.
    config_locations: Callable[[Path], Iterable[ConfigLocation]]

    # Pretty examples for the init usage block. (line, comment) tuples.
    examples: tuple[tuple[str, str], ...] = ()


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def claude_desktop_config_path() -> Path:
    """Platform-specific Claude Desktop config (always global)."""
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.system() == "Windows":
        import os

        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def _claude_locations(target: Path) -> Iterable[ConfigLocation]:
    # Project-level: target/.mcp.json
    yield ConfigLocation(
        path=target / ".mcp.json",
        schema=ConfigSchema.MCP_SERVERS,
        description="Claude Code (project)",
    )
    # Global: ~/.mcp.json
    home_mcp = Path.home() / ".mcp.json"
    if home_mcp != target / ".mcp.json":
        yield ConfigLocation(
            path=home_mcp,
            schema=ConfigSchema.MCP_SERVERS,
            description="Claude Code (global)",
        )
    # Claude Desktop's platform-specific config
    yield ConfigLocation(
        path=claude_desktop_config_path(),
        schema=ConfigSchema.MCP_SERVERS,
        description="Claude Desktop",
    )


def _claude_desktop_locations(_target: Path) -> Iterable[ConfigLocation]:
    yield ConfigLocation(
        path=claude_desktop_config_path(),
        schema=ConfigSchema.MCP_SERVERS,
        description="Claude Desktop",
    )


def _opencode_locations(target: Path) -> Iterable[ConfigLocation]:
    # Project-level (both .json and .jsonc supported)
    yield ConfigLocation(
        path=target / "opencode.json",
        schema=ConfigSchema.OPENCODE,
        description="OpenCode (project)",
    )
    yield ConfigLocation(
        path=target / "opencode.jsonc",
        schema=ConfigSchema.OPENCODE,
        description="OpenCode (project, JSONC)",
    )
    # Global
    global_dir = Path.home() / ".config" / "opencode"
    yield ConfigLocation(
        path=global_dir / "opencode.json",
        schema=ConfigSchema.OPENCODE,
        description="OpenCode (global)",
    )
    yield ConfigLocation(
        path=global_dir / "opencode.jsonc",
        schema=ConfigSchema.OPENCODE,
        description="OpenCode (global, JSONC)",
    )


def _make_subdir_locations(subdir: str, description: str) -> Callable[[Path], Iterable[ConfigLocation]]:
    """Builder for editors using `<target>/<subdir>/mcp.json` (Cursor, Windsurf, etc.)."""

    def fn(target: Path) -> Iterable[ConfigLocation]:
        yield ConfigLocation(
            path=target / subdir / "mcp.json",
            schema=ConfigSchema.MCP_SERVERS,
            description=description,
        )

    return fn


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


EDITORS: dict[str, EditorSpec] = {
    "claude": EditorSpec(
        name="claude",
        display_name="Claude Code + Claude Desktop",
        summary="Claude Code + Claude Desktop (sets up both)",
        init_target=None,  # cwd by default; --global handled in dispatch
        config_locations=_claude_locations,
        examples=(
            ("openwebgoggles init claude", "set up Claude Code for this project"),
            ("openwebgoggles init claude --global", "set up Claude Code for ALL projects"),
            ("openwebgoggles init claude ~/my-proj", "set up a specific project"),
        ),
    ),
    "claude-desktop": EditorSpec(
        name="claude-desktop",
        display_name="Claude Desktop",
        summary="Claude Desktop only — adds to claude_desktop_config.json",
        init_target=None,  # claude-desktop ignores target — uses platform-specific path
        config_locations=_claude_desktop_locations,
        examples=(("openwebgoggles init claude-desktop", "set up Claude Desktop only"),),
    ),
    "opencode": EditorSpec(
        name="opencode",
        display_name="OpenCode",
        summary="OpenCode — creates opencode.json",
        init_target=lambda: Path.home() / ".config" / "opencode",
        config_locations=_opencode_locations,
        examples=(
            ("openwebgoggles init opencode", "set up OpenCode globally"),
            ("openwebgoggles init opencode .", "set up OpenCode for this project only"),
        ),
    ),
    "cursor": EditorSpec(
        name="cursor",
        display_name="Cursor",
        summary="Cursor — creates .cursor/mcp.json",
        init_target=None,
        config_locations=_make_subdir_locations(".cursor", "Cursor"),
        examples=(("openwebgoggles init cursor", "set up Cursor for this project"),),
    ),
    "windsurf": EditorSpec(
        name="windsurf",
        display_name="Windsurf",
        summary="Windsurf — creates .windsurf/mcp.json",
        init_target=None,
        config_locations=_make_subdir_locations(".windsurf", "Windsurf"),
        examples=(("openwebgoggles init windsurf", "set up Windsurf for this project"),),
    ),
}


def all_known_locations(target: Path) -> Iterable[ConfigLocation]:
    """Every config location, across every registered editor.

    Used by the doctor scan to find stale openwebgoggles entries no matter
    which editor wrote them.
    """
    seen: set[Path] = set()
    for spec in EDITORS.values():
        for loc in spec.config_locations(target):
            if loc.path in seen:
                continue
            seen.add(loc.path)
            yield loc
