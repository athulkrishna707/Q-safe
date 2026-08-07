"""
Q-SAFE Sliding Window Rate Limiter
====================================
Per-session rate limiting using a sliding window algorithm.

OWASP API4:2023 — Unrestricted Resource Consumption
MITRE ATT&CK   — T1498 (Network Denial of Service)

Design:
- Per-session deque of timestamps; O(1) amortized check.
- Pure in-memory — no Redis, no I/O, no async in the hot path.
- Thread-safe via per-session locking.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict, Optional, Tuple

from core.config import get_settings


class SlidingWindowRateLimiter:
    """
    Token-bucket style sliding window rate limiter.

    For each session_id, maintains a deque of request timestamps within the
    current window. On each check:
    1. Prune timestamps older than window_seconds.
    2. If deque length >= limit: rate limited.
    3. Otherwise: record timestamp and allow.

    Thread-safe: per-session locks prevent concurrent write races.
    """

    def __init__(
        self,
        limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self._limit = limit or settings.rate_limit_requests
        self._window = window_seconds or settings.rate_limit_window_seconds

        # session_id → deque of unix timestamps
        self._windows: Dict[str, deque] = {}
        # Per-session locks to prevent race conditions
        self._locks: Dict[str, threading.Lock] = {}
        # Global lock for creating new session entries
        self._global_lock = threading.Lock()

    def _get_session_lock(self, session_id: str) -> threading.Lock:
        """Get or create a per-session lock (thread-safe)."""
        if session_id not in self._locks:
            with self._global_lock:
                if session_id not in self._locks:
                    self._locks[session_id] = threading.Lock()
                    self._windows[session_id] = deque()
        return self._locks[session_id]

    def check_and_record(self, session_id: str) -> Tuple[bool, int]:
        """
        Check if the session is rate-limited and record this request.

        This is the O(1) amortized hot-path call. Each call prunes expired
        entries and checks the current count.

        Args:
            session_id: Session identifier from JWT.

        Returns:
            Tuple of:
            - is_rate_limited (bool): True if this request should be blocked.
            - current_count (int): Number of requests in the current window.
        """
        lock = self._get_session_lock(session_id)
        now = time.monotonic()
        cutoff = now - self._window

        with lock:
            window = self._windows[session_id]

            # Prune expired entries from the left (oldest first)
            while window and window[0] < cutoff:
                window.popleft()

            count = len(window)

            if count >= self._limit:
                # Rate limited — do NOT record this request timestamp
                return True, count

            # Within limit — record this request
            window.append(now)
            return False, count + 1

    def is_rate_limited(self, session_id: str) -> bool:
        """
        Simplified check-only interface (records the timestamp on allow).

        Args:
            session_id: Session identifier.

        Returns:
            True if rate limited.
        """
        limited, _ = self.check_and_record(session_id)
        return limited

    def get_request_count(self, session_id: str) -> int:
        """
        Get the current request count in the window without modifying state.

        Args:
            session_id: Session identifier.

        Returns:
            Current request count in the sliding window.
        """
        lock = self._get_session_lock(session_id)
        now = time.monotonic()
        cutoff = now - self._window

        with lock:
            window = self._windows[session_id]
            # Prune without recording
            while window and window[0] < cutoff:
                window.popleft()
            return len(window)

    def reset_session(self, session_id: str) -> None:
        """
        Clear rate limit state for a session (called on revoke/quarantine).

        Args:
            session_id: Session to reset.
        """
        lock = self._get_session_lock(session_id)
        with lock:
            self._windows[session_id] = deque()

    def active_session_count(self) -> int:
        """Return the number of sessions with active rate limit windows."""
        return len(self._windows)


# ── Module-Level Singleton ────────────────────────────────────────────────────

_rate_limiter: Optional[SlidingWindowRateLimiter] = None
_init_lock = threading.Lock()


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Return the process-wide SlidingWindowRateLimiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        with _init_lock:
            if _rate_limiter is None:
                _rate_limiter = SlidingWindowRateLimiter()
    return _rate_limiter
