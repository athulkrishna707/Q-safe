"""
Q-SAFE In-Memory Telemetry Store
===================================
Central in-memory data store for all telemetry data.

Stores:
  - Event records (capped ring buffer, newest-first)
  - Aggregated metrics counters
  - Per-session risk scores
  - Enforcement latency samples (for p99 computation)
  - Active session registry
  - Quarantined session set

Thread-safe via asyncio.Lock for async consumers and threading.Lock
for sync callers (enforcement hot path updates are dispatched as
background tasks, so they run in the async event loop).
"""

from __future__ import annotations

import asyncio
import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from core.models import EventRecord, EventStatus, OracleAnalysis, RiskScoreRecord, ViolationType


class TelemetryStore:
    """
    Process-wide telemetry data store.

    All writes are async-safe (use async with self._lock).
    Sync methods (update_risk_score) are callable from sync contexts
    via threading.Lock for backward compat.
    """

    MAX_EVENTS = 1000
    MAX_LATENCY_SAMPLES = 5000

    def __init__(self) -> None:
        # Event ring buffer (newest first)
        self._events: deque[EventRecord] = deque(maxlen=self.MAX_EVENTS)
        self._lock = asyncio.Lock()

        # Metric counters
        self._total_requests: int = 0
        self._blocked_total: int = 0
        self._blocked_bola: int = 0
        self._blocked_bfla: int = 0
        self._blocked_rate: int = 0
        self._blocked_sequence: int = 0

        # Latency ring buffer
        self._latencies: deque[float] = deque(maxlen=self.MAX_LATENCY_SAMPLES)

        # Per-session risk scores: session_id → RiskScoreRecord
        self._risk_scores: Dict[str, RiskScoreRecord] = {}

        # Quarantined sessions
        self._quarantined: Set[str] = set()

        # WebSocket subscriber callbacks
        self._ws_subscribers: List[asyncio.Queue] = []

        # Threading lock for sync callers
        self._sync_lock = threading.Lock()

    # ── Event Recording ───────────────────────────────────────────────────────

    async def record_event(self, event: EventRecord) -> None:
        """
        Record a gateway event and update all derived metrics.

        Args:
            event: EventRecord from the enforcement middleware.
        """
        async with self._lock:
            # Prepend (deque maxlen handles overflow)
            self._events.appendleft(event)

            self._total_requests += 1
            self._latencies.append(event.enforcement_latency_ms)

            if event.status == EventStatus.BLOCKED:
                self._blocked_total += 1
                vtype = event.violation_type
                if vtype == ViolationType.BOLA:
                    self._blocked_bola += 1
                elif vtype == ViolationType.BFLA:
                    self._blocked_bfla += 1
                elif vtype == ViolationType.RATE:
                    self._blocked_rate += 1
                elif vtype == ViolationType.SEQUENCE:
                    self._blocked_sequence += 1

        # Push to WebSocket subscribers (outside lock to avoid deadlock)
        await self._push_to_ws(event)

    async def update_event_analysis(
        self,
        event_id: str,
        analysis: OracleAnalysis,
    ) -> None:
        """
        Enrich an existing event record with AI oracle analysis.

        Updates the event in-place in the events deque.

        Args:
            event_id: The event to update.
            analysis: Oracle analysis result.
        """
        async with self._lock:
            for i, event in enumerate(self._events):
                if event.event_id == event_id:
                    updated = event.model_copy(
                        update={
                            "ai_explanation": analysis.explanation,
                            "owasp_tag": analysis.owasp_tag,
                            "mitre_technique": analysis.mitre_technique,
                            "oracle_confidence": analysis.confidence,
                        }
                    )
                    self._events[i] = updated
                    break

    # ── Metrics ───────────────────────────────────────────────────────────────

    async def get_metrics(self) -> dict:
        """
        Compute and return executive dashboard metrics.

        Returns:
            Dict matching MetricsResponse schema.
        """
        async with self._lock:
            latencies = list(self._latencies)
            total = self._total_requests
            blocked = self._blocked_total

        if latencies:
            mean_lat = statistics.mean(latencies)
            sorted_lats = sorted(latencies)
            p99_idx = int(len(sorted_lats) * 0.99)
            p99_lat = sorted_lats[min(p99_idx, len(sorted_lats) - 1)]
        else:
            mean_lat = 0.0
            p99_lat = 0.0

        from gateway.rate_limit import get_rate_limiter
        active = get_rate_limiter().active_session_count()

        return {
            "total_requests": total,
            "blocked_total": blocked,
            "blocked_bola": self._blocked_bola,
            "blocked_bfla": self._blocked_bfla,
            "blocked_rate": self._blocked_rate,
            "blocked_sequence": self._blocked_sequence,
            "active_sessions": active,
            "mean_enforcement_latency_ms": round(mean_lat, 3),
            "p99_enforcement_latency_ms": round(p99_lat, 3),
        }

    # ── Events ────────────────────────────────────────────────────────────────

    async def get_events(self, limit: int = 50) -> List[EventRecord]:
        """
        Return the most recent events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of EventRecord (newest first).
        """
        async with self._lock:
            return list(self._events)[:limit]

    # ── Risk Scores ───────────────────────────────────────────────────────────

    def update_risk_score(
        self,
        session_id: str,
        username: str,
        role: str,
        score: float,
        flagged: List[str],
    ) -> None:
        """
        Update the risk score for a session (sync — called from profiler agent).

        Args:
            session_id: Session identifier.
            username:   Authenticated username.
            role:       User role.
            score:      New risk score (0–100).
            flagged:    List of flagged behaviors.
        """
        with self._sync_lock:
            self._risk_scores[session_id] = RiskScoreRecord(
                session_id=session_id,
                username=username,
                role=role,
                risk_score=score,
                last_updated=datetime.now(timezone.utc).isoformat(),
                flagged_behaviors=flagged,
            )

    async def get_risk_scores(self) -> List[RiskScoreRecord]:
        """
        Return all current per-session risk scores.

        Returns:
            List of RiskScoreRecord, sorted by risk_score descending.
        """
        with self._sync_lock:
            scores = list(self._risk_scores.values())
        return sorted(scores, key=lambda r: r.risk_score, reverse=True)

    # ── Session Management ────────────────────────────────────────────────────

    def quarantine_session(self, session_id: str) -> None:
        """
        Mark a session as quarantined.

        Args:
            session_id: Session to quarantine.
        """
        with self._sync_lock:
            self._quarantined.add(session_id)

    def is_quarantined(self, session_id: str) -> bool:
        """
        Check if a session is quarantined.

        Args:
            session_id: Session identifier.

        Returns:
            True if quarantined.
        """
        with self._sync_lock:
            return session_id in self._quarantined

    async def get_quarantined_sessions(self) -> List[str]:
        """Return list of quarantined session IDs."""
        with self._sync_lock:
            return list(self._quarantined)

    # ── WebSocket Push ────────────────────────────────────────────────────────

    def add_ws_subscriber(self, queue: asyncio.Queue) -> None:
        """Register a WebSocket connection's queue for live event push."""
        self._ws_subscribers.append(queue)

    def remove_ws_subscriber(self, queue: asyncio.Queue) -> None:
        """Remove a WebSocket subscriber on disconnect."""
        try:
            self._ws_subscribers.remove(queue)
        except ValueError:
            pass

    async def _push_to_ws(self, event: EventRecord) -> None:
        """Push an event to all connected WebSocket subscribers."""
        if not self._ws_subscribers:
            return
        payload = event.model_dump_json()
        dead = []
        for q in self._ws_subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.remove_ws_subscriber(q)

    # ── Seed / Demo Helpers ───────────────────────────────────────────────────

    async def seed_event(self, event: EventRecord) -> None:
        """
        Seed a synthetic baseline event (used during startup traffic seeding).

        Same as record_event but marked for tracing.

        Args:
            event: Synthetic EventRecord.
        """
        await self.record_event(event)


# ── Module-Level Singleton ────────────────────────────────────────────────────

_telemetry_store: Optional[TelemetryStore] = None
_store_lock = threading.Lock()


def get_telemetry_store() -> TelemetryStore:
    """
    Return the process-wide TelemetryStore singleton.

    Returns:
        Shared TelemetryStore instance.
    """
    global _telemetry_store
    if _telemetry_store is None:
        with _store_lock:
            if _telemetry_store is None:
                _telemetry_store = TelemetryStore()
    return _telemetry_store
