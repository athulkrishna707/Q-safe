"""
Q-SAFE Sequence Integrity Engine
==================================
Contextual Control Flow Hashing (CCFH) — the core IP of Q-SAFE.

Algorithm (64-bit register semantics):
    hash = ((hash << 1) & 0xFFFFFFFFFFFFFFFF) ^ endpoint_id

Every registered endpoint has a stable 64-bit ID.
Every session maintains a rolling context hash updated on each authorized access.
The Policy Engine pre-computes valid hashes per role at startup.
Authorization requires O(1) set membership: is hash in role_allowlist?

CRITICAL: Python ints are unbounded; the 64-bit mask is MANDATORY to emulate
register overflow correctly.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Dict, Optional

# ── Core CCFH Algorithm ───────────────────────────────────────────────────────

HASH_MASK: int = 0xFFFFFFFFFFFFFFFF  # 64-bit mask — mandatory


def ccfh_update(current_hash: int, endpoint_id: int) -> int:
    """
    Advance the CCFH rolling context hash by one step.

    This is the core algorithm — a single hot operation called in the
    synchronous enforcement path. Must remain O(1) with no allocations.

    Args:
        current_hash: Current 64-bit hash value for this session.
        endpoint_id:  Stable 64-bit integer ID of the accessed endpoint.

    Returns:
        New 64-bit hash value after incorporating endpoint_id.
    """
    return ((current_hash << 1) & HASH_MASK) ^ endpoint_id


def hash_to_hex(h: int) -> str:
    """
    Format a 64-bit integer hash as a hex string matching the frontend display format.

    Args:
        h: 64-bit integer hash.

    Returns:
        Hex string like '0x8F9A2B1C'.
    """
    return f"0x{h:016X}"


def hash_sequence(endpoint_ids: list[int], initial: int = 0) -> int:
    """
    Compute the hash that results from processing a sequence of endpoint IDs.

    Used by the AllowlistGenerator to pre-compute valid hash states.

    Args:
        endpoint_ids: Ordered list of endpoint IDs representing a valid sequence.
        initial:      Starting hash value (default 0 = fresh session).

    Returns:
        Final 64-bit hash after applying all endpoint_ids in order.
    """
    h = initial
    for eid in endpoint_ids:
        h = ccfh_update(h, eid)
    return h


# ── Session Hash Store ────────────────────────────────────────────────────────


class SequenceEngine:
    """
    Per-session rolling context hash store.

    Maintains the current CCFH hash state for each active session.
    Thread-safe for synchronous callers (enforcement hot path uses threading).
    Provides async variants for agent/telemetry consumers.

    State storage: in-memory dict (Redis adapter can replace _store in future).
    """

    def __init__(self) -> None:
        self._store: Dict[str, int] = {}
        self._lock = threading.Lock()

        # Per-session sequence history for telemetry
        self._history: Dict[str, list[dict]] = {}

    def get_hash(self, session_id: str) -> int:
        """
        Get the current rolling hash for a session.

        Args:
            session_id: Session identifier.

        Returns:
            Current hash (0 if session is new/unknown).
        """
        with self._lock:
            return self._store.get(session_id, 0)

    def advance(
        self,
        session_id: str,
        endpoint_id: int,
        endpoint_path: str = "",
    ) -> int:
        """
        Advance the hash for a session by one endpoint step.

        This is the hot-path call — O(1), no I/O, no allocations beyond dict update.

        Args:
            session_id:    Session identifier.
            endpoint_id:   ID of the endpoint being accessed.
            endpoint_path: Human-readable path (for history only).

        Returns:
            New hash value after incorporating endpoint_id.
        """
        with self._lock:
            current = self._store.get(session_id, 0)
            new_hash = ccfh_update(current, endpoint_id)
            self._store[session_id] = new_hash

            # Record history entry for telemetry/visualizer
            if session_id not in self._history:
                self._history[session_id] = []
            step = len(self._history[session_id])
            self._history[session_id].append(
                {
                    "step": step,
                    "endpoint": endpoint_path,
                    "endpoint_id": endpoint_id,
                    "hash_after": hash_to_hex(new_hash),
                }
            )
            return new_hash

    def revoke(self, session_id: str) -> None:
        """
        Remove a session's hash state (called on BLOCK or quarantine).

        Revoking forces the session to restart its hash from 0 on the next request,
        which will fail the allowlist check.

        Args:
            session_id: Session to revoke.
        """
        with self._lock:
            self._store.pop(session_id, None)

    def get_history(self, session_id: str) -> list[dict]:
        """
        Return the full sequence history for a session.

        Args:
            session_id: Session identifier.

        Returns:
            List of step dicts: {step, endpoint, endpoint_id, hash_after}.
        """
        with self._lock:
            return list(self._history.get(session_id, []))

    def active_sessions(self) -> list[str]:
        """Return list of session IDs with active hash state."""
        with self._lock:
            return list(self._store.keys())


# ── Module-Level Singleton ────────────────────────────────────────────────────

_sequence_engine: Optional[SequenceEngine] = None
_init_lock = threading.Lock()


def get_sequence_engine() -> SequenceEngine:
    """
    Return the process-wide SequenceEngine singleton.

    Returns:
        Shared SequenceEngine instance.
    """
    global _sequence_engine
    if _sequence_engine is None:
        with _init_lock:
            if _sequence_engine is None:
                _sequence_engine = SequenceEngine()
    return _sequence_engine
