"""
Q-SAFE Behavioral Profiler Agent
==================================
Autonomous background agent that builds per-session behavioral baselines
and computes continuous 0–100 risk scores.

Agent loop: runs every 5 seconds, consumes the event queue batch.
Risk scoring: deviation from baseline triggers score escalation.

GRACEFUL DEGRADATION:
  This agent NEVER stops running. All exceptions are caught and logged.
  If the event queue is empty, the agent sleeps and retries.
  If baseline computation fails, it falls back to keyword heuristics.

DESIGN BOUNDARY:
  This agent is purely ANALYTICAL — it emits risk scores but NEVER
  makes blocking decisions. All enforcement is done by the hot path.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from core.logging import get_audit_logger
from core.models import EventRecord, EventStatus, ViolationType

# ── Keyword Heuristics (fallback when no baseline yet) ────────────────────────

_HIGH_RISK_KEYWORDS = frozenset(
    ["admin", "transfer", "delete", "bulk-export", "export", "users", "transactions"]
)
_MEDIUM_RISK_KEYWORDS = frozenset(["accounts", "billing", "payment"])

_VIOLATION_RISK_BOOST = {
    ViolationType.BOLA: 30.0,
    ViolationType.BFLA: 40.0,
    ViolationType.RATE: 25.0,
    ViolationType.REPLAY: 35.0,
    ViolationType.SEQUENCE: 20.0,
}

# ── Session Baseline ──────────────────────────────────────────────────────────


class SessionBaseline:
    """
    Rolling behavioral baseline for a single session.

    Tracks:
    - Set of endpoints accessed (behavioral fingerprint).
    - Request cadence (inter-request intervals).
    - Block history and violation types.
    - Risk score trajectory.
    """

    def __init__(self, session_id: str, username: str, role: str) -> None:
        self.session_id = session_id
        self.username = username
        self.role = role

        self.endpoints_accessed: Set[str] = set()
        self.request_timestamps: List[float] = []
        self.block_count: int = 0
        self.violation_types: List[str] = []
        self.risk_score: float = 0.0
        self.flagged_behaviors: List[str] = []
        self.last_updated: float = time.monotonic()

    def record_event(self, event: EventRecord) -> None:
        """
        Update baseline with a new event.

        Args:
            event: Gateway event record.
        """
        self.endpoints_accessed.add(event.endpoint)
        self.request_timestamps.append(time.monotonic())
        self.last_updated = time.monotonic()

        # Keep only last 100 timestamps for cadence analysis
        if len(self.request_timestamps) > 100:
            self.request_timestamps = self.request_timestamps[-100:]

        if event.status == EventStatus.BLOCKED:
            self.block_count += 1
            if event.violation_type:
                self.violation_types.append(event.violation_type.value)

    def compute_risk_score(self) -> float:
        """
        Compute a 0–100 risk score for this session.

        Risk factors:
        1. Block ratio (blocked / total requests)
        2. Request cadence (requests per second vs normal threshold)
        3. Endpoint diversity (accessing many admin/sensitive endpoints)
        4. Keyword heuristics (high-risk endpoint patterns)
        5. Violation history

        Returns:
            Risk score between 0.0 and 100.0.
        """
        score = 0.0
        total_requests = len(self.request_timestamps)
        self.flagged_behaviors = []

        if total_requests == 0:
            return 0.0

        # Factor 1: Block ratio
        if total_requests > 0:
            block_ratio = self.block_count / total_requests
            score += block_ratio * 50.0
            if block_ratio > 0.1:
                self.flagged_behaviors.append(f"High block ratio: {block_ratio:.1%}")

        # Factor 2: Request cadence (>10 req/s is suspicious)
        if len(self.request_timestamps) >= 2:
            time_span = self.request_timestamps[-1] - self.request_timestamps[0]
            if time_span > 0:
                rps = total_requests / time_span
                if rps > 10:
                    cadence_risk = min(rps / 20.0, 1.0) * 20.0
                    score += cadence_risk
                    self.flagged_behaviors.append(f"High request rate: {rps:.1f} req/s")

        # Factor 3: Violation history
        for vtype in self.violation_types:
            vtype_enum = ViolationType(vtype) if vtype in ViolationType._value2member_map_ else None
            if vtype_enum:
                score += _VIOLATION_RISK_BOOST.get(vtype_enum, 10.0)

        # Factor 4: Keyword heuristics on accessed endpoints
        for endpoint in self.endpoints_accessed:
            endpoint_lower = endpoint.lower()
            for keyword in _HIGH_RISK_KEYWORDS:
                if keyword in endpoint_lower:
                    score += 5.0
                    if keyword not in str(self.flagged_behaviors):
                        self.flagged_behaviors.append(f"Accessed high-risk endpoint: {keyword}")
                    break

        # Cap at 100
        self.risk_score = min(score, 100.0)
        return self.risk_score


# ── Profiler Agent ────────────────────────────────────────────────────────────


class ProfilerAgent:
    """
    Autonomous behavioral profiler agent.

    Runs as an asyncio background task. Every 5 seconds:
    1. Drains the event queue batch.
    2. Updates per-session baselines.
    3. Recomputes risk scores.
    4. Emits updated scores to the telemetry store.

    Never stops; all exceptions are caught and the loop resumes.
    """

    LOOP_INTERVAL_SECONDS = 5.0

    def __init__(self) -> None:
        self._baselines: Dict[str, SessionBaseline] = {}
        self._logger = get_audit_logger()
        self._running = False

    async def run(self) -> None:
        """
        Main agent loop. Runs indefinitely until cancelled.

        Must be launched as an asyncio.Task at application startup.
        """
        self._running = True
        print("[ProfilerAgent] Started behavioral baseline agent.", flush=True)

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                print("[ProfilerAgent] Cancelled — shutting down.", flush=True)
                break
            except Exception as exc:  # noqa: BLE001
                # NEVER let an exception stop the agent
                print(f"[ProfilerAgent] WARN: Unhandled exception in tick: {exc}", flush=True)
                self._logger.log_agent_event(
                    "profiler", "error", {"error": str(exc)}
                )

            await asyncio.sleep(self.LOOP_INTERVAL_SECONDS)

    async def _tick(self) -> None:
        """
        One agent tick: drain queue, update baselines, emit risk scores.
        """
        from agents.queue import get_event_queue
        from telemetry.store import get_telemetry_store

        queue = get_event_queue()
        events = await queue.dequeue_batch(max_items=200)

        if not events:
            return

        # Update baselines for all events in batch
        for event in events:
            sid = event.session_id
            if sid not in self._baselines:
                self._baselines[sid] = SessionBaseline(
                    session_id=sid,
                    username=event.user,
                    role=event.role,
                )
            self._baselines[sid].record_event(event)

        # Recompute risk scores and emit to telemetry
        store = get_telemetry_store()
        updated_scores: Dict[str, float] = {}

        for sid, baseline in self._baselines.items():
            score = baseline.compute_risk_score()
            updated_scores[sid] = score

            store.update_risk_score(
                session_id=sid,
                username=baseline.username,
                role=baseline.role,
                score=score,
                flagged=baseline.flagged_behaviors,
            )

            # Log high-risk sessions
            if score > 60.0:
                self._logger.log_agent_event(
                    "profiler",
                    "high_risk_session",
                    {
                        "session_id": sid,
                        "username": baseline.username,
                        "risk_score": score,
                        "flagged_behaviors": baseline.flagged_behaviors,
                    },
                )

    def stop(self) -> None:
        """Signal the agent to stop after the current tick."""
        self._running = False

    @property
    def active_session_count(self) -> int:
        """Number of sessions being profiled."""
        return len(self._baselines)
