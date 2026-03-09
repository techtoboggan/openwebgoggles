"""
File watcher for OpenWebGoggles dev mode — polls mtime changes and broadcasts reload/state.

Extracted from webview_server.py (Phase 4.2).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("openwebgoggles")

SRC_EXTENSIONS: frozenset[str] = frozenset({".js", ".css", ".html"})


class FileWatcher:
    """Poll the data contract and (in dev mode) source files for changes.

    Broadcasts state/manifest/action updates over WebSocket and sends
    ``{"type": "reload"}`` when a watched source file changes.
    """

    def __init__(
        self,
        contract: Any,
        security_gate: Any | None,
        broadcast_fn: Callable,
        dev_mode: bool = False,
        watch_dirs: list[Path] | None = None,
    ) -> None:
        self._contract = contract
        self._security_gate = security_gate
        self._broadcast = broadcast_fn
        self._dev_mode = dev_mode
        self._watch_dirs: list[Path] = list(watch_dirs or [])
        self._src_mtimes: dict[Path, float] = {}

    def init_src_mtimes(self) -> None:
        """Snapshot current mtimes for all watched source files."""
        for watch_dir in self._watch_dirs:
            try:
                for path in watch_dir.rglob("*"):
                    if path.is_file() and path.suffix in SRC_EXTENSIONS:
                        self._src_mtimes[path] = path.stat().st_mtime
            except OSError:
                pass

    def check_src_changes(self) -> list[Path]:
        """Return list of source files whose mtime has changed since last check."""
        changed: list[Path] = []
        for watch_dir in self._watch_dirs:
            try:
                for path in watch_dir.rglob("*"):
                    if not path.is_file() or path.suffix not in SRC_EXTENSIONS:
                        continue
                    try:
                        mtime = path.stat().st_mtime
                    except OSError:
                        continue
                    prev = self._src_mtimes.get(path)
                    if prev is None:
                        # New file discovered — record but don't trigger reload
                        self._src_mtimes[path] = mtime
                    elif mtime != prev:
                        self._src_mtimes[path] = mtime
                        changed.append(path)
            except OSError:
                pass
        return changed

    async def watch(self, running_ref: list[bool]) -> None:  # pragma: no cover
        """Poll data contract files for changes and broadcast over WebSocket.

        ``running_ref`` is a one-element list whose first item is checked each
        loop iteration so WebviewServer can stop the watcher by setting it False.
        """
        self._contract.check_changes()
        if self._dev_mode:
            self.init_src_mtimes()

        last_broadcast: dict[str, float] = {}
        debounce_ms = 100  # minimum ms between broadcasts for the same file
        last_reload: float = 0.0

        while running_ref[0]:
            await asyncio.sleep(0.5)
            changed = self._contract.check_changes()
            now = time.monotonic()
            # Debounce: skip files that were broadcast too recently
            changed = [c for c in changed if (now - last_broadcast.get(c, 0)) * 1000 >= debounce_ms]
            for name in changed:
                if name == "state":
                    data = self._contract.get_state()
                    if data:
                        # Run through security gate before broadcasting
                        if self._security_gate:
                            valid, err, _ = self._security_gate.validate_state(json.dumps(data))
                            if not valid:
                                logger.error("SECURITY GATE BLOCKED state update: %s", err)
                                await self._broadcast(
                                    {"type": "error", "data": {"message": "State update rejected by security gate"}}
                                )
                                last_broadcast["state"] = now
                                continue
                        await self._broadcast({"type": "state_updated", "data": data})
                        last_broadcast["state"] = time.monotonic()
                elif name == "manifest":
                    data = self._contract.get_manifest()
                    if data:
                        from data_contract import _strip_token  # noqa: I001

                        safe_data = _strip_token(data)
                        await self._broadcast({"type": "manifest_updated", "data": safe_data})
                        last_broadcast["manifest"] = time.monotonic()
                elif name == "actions":
                    data = self._contract.get_actions()
                    if data:
                        await self._broadcast({"type": "actions_updated", "data": data})
                        last_broadcast["actions"] = time.monotonic()

            # Dev mode: watch source files and broadcast reload
            if self._dev_mode:
                src_changed = self.check_src_changes()
                if src_changed and (now - last_reload) >= 0.5:
                    logger.info("Dev: source changed (%s) — broadcasting reload", src_changed[0].name)
                    await self._broadcast({"type": "reload"})
                    last_reload = time.monotonic()
