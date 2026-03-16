"""
Bundler — produces a single self-contained HTML file for MCP Apps mode.

Reads all JS/CSS from assets/apps/dynamic/ and assets/sdk/,
inlines everything into one HTML string suitable for resources/read
with MIME type text/html;profile=mcp-app.
"""

import re
from pathlib import Path

# Scripts loaded in MCP Apps mode (order matters — dependency chain).
# openwebgoggles-sdk.js is excluded: iframe uses mcp-transport.js instead.
_SCRIPT_ORDER = [
    "marked.min.js",
    "purify.min.js",
    "utils.js",
    "mcp-transport.js",
    "sections.js",
    "charts.js",
    "validation.js",
    "behaviors.js",
    "app.js",
]

_bundled_cache: str | None = None


def _find_assets_dir() -> Path:
    """Locate the assets directory relative to this file or the package root."""
    # scripts/bundler.py -> project_root/assets
    project_root = Path(__file__).resolve().parent.parent
    assets = project_root / "assets"
    if assets.is_dir():
        return assets
    msg = f"Assets directory not found at {assets}"
    raise FileNotFoundError(msg)


def bundle_html(assets_dir: Path | None = None, plugin_contents: list[str] | None = None) -> str:
    """Bundle all dynamic app assets into a single self-contained HTML string.

    Args:
        assets_dir: Path to the assets directory. Auto-detected if None.
        plugin_contents: Optional list of plugin JS source strings to inline
            after behaviors.js but before app.js (so plugins register before
            Object.freeze).

    The result is cached for the lifetime of the process (only when no plugins).
    """
    global _bundled_cache  # noqa: PLW0603
    # Only use cache when no plugins (plugins may change between calls)
    if _bundled_cache is not None and not plugin_contents:
        return _bundled_cache

    if assets_dir is None:
        assets_dir = _find_assets_dir()

    app_dir = assets_dir / "apps" / "dynamic"
    sdk_dir = assets_dir / "sdk"

    # Read index.html (contains inline CSS already)
    html = (app_dir / "index.html").read_text(encoding="utf-8")

    # Strip all <script src="..."> tags — we'll inline them
    html = re.sub(r'<script\s+[^>]*src="[^"]*"[^>]*>\s*</script>\s*', "", html)

    # Build inline script blocks
    scripts: list[str] = []

    # Detection flag for MCP Apps mode
    scripts.append("<script>window.__OWG_MCP_APPS__=true;</script>")

    for filename in _SCRIPT_ORDER:
        path = app_dir / filename
        if not path.exists():
            path = sdk_dir / filename
        if not path.exists():
            msg = f"Required asset not found: {filename}"
            raise FileNotFoundError(msg)
        content = path.read_text(encoding="utf-8")
        # Escape </script> inside inline scripts to prevent premature tag close
        content = content.replace("</script>", "<\\/script>")
        scripts.append(f"<script>{content}</script>")

        # Inject plugins after behaviors.js (before app.js) so they register
        # before Object.freeze freezes the OWG namespace
        if filename == "behaviors.js" and plugin_contents:
            for plugin_js in plugin_contents:
                safe_js = plugin_js.replace("</script>", "<\\/script>")
                scripts.append(f"<script>{safe_js}</script>")

    script_block = "\n".join(scripts)

    # Inject before </body>
    html = html.replace("</body>", f"{script_block}\n</body>")

    # Inject CSP meta tag for defense-in-depth when loaded outside MCP host context.
    # script-src 'unsafe-inline' is required since all scripts are inlined.
    csp_meta = (
        '<meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; "
        "script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; "
        "img-src data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "base-uri 'none'; "
        "form-action 'none'"
        '">'
    )
    html = html.replace("<head>", f"<head>\n{csp_meta}", 1)

    # Hide header in embedded mode (host provides its own chrome)
    html = html.replace("<header", '<header style="display:none"', 1)

    # In embedded mode, remove min-height:100vh so iframe can size naturally
    html = html.replace("min-height: 100vh", "min-height: auto")

    if not plugin_contents:
        _bundled_cache = html
    return html


def clear_cache() -> None:
    """Clear the bundled HTML cache (useful for testing)."""
    global _bundled_cache  # noqa: PLW0603
    _bundled_cache = None
