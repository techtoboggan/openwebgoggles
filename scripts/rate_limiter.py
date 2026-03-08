"""
Rate limiting utility for OpenWebGoggles server.
"""

from __future__ import annotations

import time


class RateLimiter:
    """Simple sliding-window rate limiter for action submissions."""

    def __init__(self, max_actions: int = 30, window_seconds: float = 60.0):
        self.max_actions = max_actions
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def check(self) -> bool:
        """Return True if the action is allowed, False if rate-limited."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_actions:
            return False
        self._timestamps.append(now)
        # Cap at 1000 entries — defence-in-depth against unbounded growth (ROADMAP 1.7)
        if len(self._timestamps) > 1000:
            self._timestamps = self._timestamps[-1000:]
        return True
