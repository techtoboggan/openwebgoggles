"""BDD-specific fixtures for step definitions."""

from __future__ import annotations

import asyncio
import os
import sys
from unittest import mock

import pytest

# Add scripts/ to path for test imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001


@pytest.fixture
def version_monitor_env():
    """Provides a clean environment for version monitor tests with auto-cleanup."""
    old_state = {
        "_reload_pending": mcp_server._reload_pending,
        "_active_tool_calls": mcp_server._active_tool_calls,
        "_session": mcp_server._session,
        "_stale_version_msg": mcp_server._stale_version_msg,
        "_signal_reload_requested": mcp_server._signal_reload_requested,
    }

    mcp_server._reload_pending = False
    mcp_server._active_tool_calls = 0
    mcp_server._session = None
    mcp_server._stale_version_msg = ""
    mcp_server._signal_reload_requested = False

    yield mcp_server

    for key, value in old_state.items():
        setattr(mcp_server, key, value)


@pytest.fixture
def mock_dist_info(tmp_path):
    """Create a mock dist-info directory with METADATA file."""
    dist_dir = tmp_path / "openwebgoggles-1.0.0.dist-info"
    dist_dir.mkdir()
    metadata = dist_dir / "METADATA"
    metadata.write_text("Metadata-Version: 2.1\nName: openwebgoggles\nVersion: 1.0.0\n")
    return dist_dir


@pytest.fixture
def mock_dist_info_v2(tmp_path):
    """Create a mock dist-info directory for version 2.0.0."""
    dist_dir = tmp_path / "openwebgoggles-2.0.0.dist-info"
    dist_dir.mkdir()
    metadata = dist_dir / "METADATA"
    metadata.write_text("Metadata-Version: 2.1\nName: openwebgoggles\nVersion: 2.0.0\n")
    return dist_dir


@pytest.fixture
def run_monitor_briefly():
    """Helper to run the version monitor for a controlled number of cycles."""

    async def _run(cycles=3, check_interval=0.01):
        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", check_interval):
            task = asyncio.create_task(mcp_server._version_monitor())
            await asyncio.sleep(check_interval * (cycles + 1) * 2)
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            return task

    return _run
