"""
Version monitor utilities for OpenWebGoggles.

Pure helper functions for detecting package version changes via dist-info
inspection.  The background task (_version_monitor) and mutable globals
(_reload_pending, _stale_version_msg, etc.) live in mcp_server.py to avoid
circular-import and test-isolation issues.
"""

import asyncio
import importlib
import importlib.metadata
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger("openwebgoggles")


def _task_done_callback(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks so they don't vanish silently."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Background task %r crashed: %s", task.get_name(), exc, exc_info=exc)


def _get_installed_version_info() -> tuple[str, Path | None]:
    """Return (version_string, dist_info_path) for the installed package.

    Returns ("unknown", None) when running from source without pip install.
    """
    try:
        dist = importlib.metadata.distribution("openwebgoggles")
        version = dist.metadata["Version"]
        dist_path = getattr(dist, "_path", None)
        if dist_path is not None:
            dist_path = Path(dist_path)
        return (version, dist_path)
    except importlib.metadata.PackageNotFoundError:
        return ("unknown", None)


def _get_site_packages_dirs() -> list[Path]:
    """Return candidate site-packages directories for the current environment."""
    dirs: list[Path] = []
    for p in sys.path:
        pp = Path(p)
        if pp.name == "site-packages" and pp.is_dir():
            dirs.append(pp)
    return dirs


def _read_version_fresh(dist_info_hint: Path | None = None) -> str:
    """Read installed version by reading METADATA file directly from disk.

    Bypasses importlib.metadata caches entirely, which don't always flush
    in pipx/venv installs after ``pip install --upgrade``.

    Strategy: (1) read METADATA from the known dist-info hint path,
    (2) fall back to scanning site-packages for any openwebgoggles dist-info,
    (3) fall back to importlib as last resort.
    """
    # Strategy 1: Direct file read from known dist-info path
    if dist_info_hint is not None:
        metadata_file = dist_info_hint / "METADATA"
        try:
            if metadata_file.is_file():
                for line in metadata_file.read_text(encoding="utf-8").splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass

    # Strategy 2: Scan site-packages for any openwebgoggles dist-info
    for site_dir in _get_site_packages_dirs():
        try:
            for entry in site_dir.iterdir():
                if entry.name.startswith("openwebgoggles-") and entry.name.endswith(".dist-info"):
                    metadata_file = entry / "METADATA"
                    try:
                        if metadata_file.is_file():
                            for line in metadata_file.read_text(encoding="utf-8").splitlines():
                                if line.startswith("Version:"):
                                    return line.split(":", 1)[1].strip()
                    except OSError:
                        continue
        except OSError:
            continue

    # Strategy 3: Fall back to importlib as last resort
    importlib.invalidate_caches()
    try:
        dist = importlib.metadata.distribution("openwebgoggles")
        return dist.metadata["Version"]
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


# Type alias to avoid importing Any at module level in a confusing way
_AnyType = Any
