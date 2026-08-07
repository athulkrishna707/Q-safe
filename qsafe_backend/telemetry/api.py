"""
Q-SAFE Telemetry API
======================
Dashboard-facing REST endpoints and WebSocket live event stream.

Endpoints:
  GET  /telemetry/metrics           → executive dashboard metrics
  GET  /telemetry/events?limit=50   → recent event records
  GET  /telemetry/risk-scores       → per-session risk scores
  GET  /sessions/{id}/sequence      → CCFH sequence visualizer data
  POST /sessions/{id}/quarantine    → revoke session
  WS   /ws/events                   → live event stream (push)
  POST /api/analyze-threat          → AI re-analysis (frontend compat)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from core.models import (
    AnalyzeThreatRequest,
    AnalyzeThreatResponse,
    EventRecord,
    MetricsResponse,
    OracleAnalysis,
    QuarantineResponse,
    RiskScoreRecord,
    SequenceStep,
)

router = APIRouter(tags=["Telemetry"])


# ── Metrics ───────────────────────────────────────────────────────────────────


@router.get("/telemetry/metrics", response_model=MetricsResponse)
async def get_metrics() -> MetricsResponse:
    """
    Return executive dashboard metrics.

    Metrics computed from in-memory counters and latency samples.
    Always returns valid data — never raises 5xx unless store is uninitialized.

    Returns:
        MetricsResponse with total_requests, blocked counts, latency stats.
    """
    from telemetry.store import get_telemetry_store
    store = get_telemetry_store()
    data = await store.get_metrics()
    return MetricsResponse(**data)


# ── Events ────────────────────────────────────────────────────────────────────


@router.get("/telemetry/events", response_model=List[EventRecord])
async def get_events(
    limit: int = Query(default=50, ge=1, le=1000, description="Max events to return"),
) -> List[EventRecord]:
    """
    Return the most recent gateway events (newest first).

    Includes both allowed and blocked requests. AI oracle fields
    (ai_explanation, owasp_tag, mitre_technique) are populated
    asynchronously and may be null for very recent events.

    Args:
        limit: Maximum number of events to return (1–1000).

    Returns:
        List of EventRecord sorted newest-first.
    """
    from telemetry.store import get_telemetry_store
    store = get_telemetry_store()
    return await store.get_events(limit=limit)


# ── Risk Scores ───────────────────────────────────────────────────────────────


@router.get("/telemetry/risk-scores", response_model=List[RiskScoreRecord])
async def get_risk_scores() -> List[RiskScoreRecord]:
    """
    Return per-session behavioral risk scores (sorted highest first).

    Scores are computed by the profiler_agent and updated every 5 seconds.
    Sessions with no recent activity may not appear.

    Returns:
        List of RiskScoreRecord sorted by risk_score descending.
    """
    from telemetry.store import get_telemetry_store
    store = get_telemetry_store()
    return await store.get_risk_scores()


# ── Session Sequence Visualizer ───────────────────────────────────────────────


@router.get("/sessions/{session_id}/sequence", response_model=List[SequenceStep])
async def get_session_sequence(session_id: str) -> List[SequenceStep]:
    """
    Return the ordered CCFH sequence trace for a session.

    Each step shows the endpoint accessed, its stable ID, and the
    rolling context hash after that step. Used by the frontend
    Sequence Visualizer component.

    Args:
        session_id: Session identifier.

    Returns:
        Ordered list of SequenceStep records.
    """
    from gateway.sequence import get_sequence_engine
    engine = get_sequence_engine()
    history = engine.get_history(session_id)

    if not history:
        return []

    return [
        SequenceStep(
            step=entry["step"],
            endpoint=entry["endpoint"],
            endpoint_id=entry["endpoint_id"],
            hash_after=entry["hash_after"],
        )
        for entry in history
    ]


# ── Session Quarantine ────────────────────────────────────────────────────────


@router.post("/sessions/{session_id}/quarantine", response_model=QuarantineResponse)
async def quarantine_session(session_id: str) -> QuarantineResponse:
    """
    Revoke a session — blocks all future requests from this session_id.

    Actions taken:
    - Clears CCFH hash state (session must re-authenticate)
    - Resets rate limit window
    - Marks session as quarantined in the telemetry store

    Args:
        session_id: Session to quarantine.

    Returns:
        QuarantineResponse with confirmation.
    """
    from telemetry.store import get_telemetry_store
    from gateway.sequence import get_sequence_engine
    from gateway.rate_limit import get_rate_limiter

    store = get_telemetry_store()
    seq_engine = get_sequence_engine()
    rate_limiter = get_rate_limiter()

    # Apply revocation
    seq_engine.revoke(session_id)
    rate_limiter.reset_session(session_id)
    store.quarantine_session(session_id)

    return QuarantineResponse(
        session_id=session_id,
        quarantined=True,
        message=f"Session {session_id} has been quarantined. All future requests from this session will be blocked.",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── WebSocket Live Event Stream ───────────────────────────────────────────────


@router.websocket("/ws/events")
async def websocket_event_stream(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for live event streaming.

    Pushes every new gateway event to all connected clients.
    The frontend dashboard uses this for real-time auto-refresh.

    Protocol:
    - Server sends: JSON-serialized EventRecord on each new event.
    - Client sends: heartbeat "ping" → server replies "pong".
    - Connection drops: server silently removes subscriber.
    """
    from telemetry.store import get_telemetry_store
    store = get_telemetry_store()

    await websocket.accept()

    # Subscribe this connection to the event push queue
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
    store.add_ws_subscriber(queue)

    try:
        while True:
            # Wait for next event or heartbeat timeout
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(payload)
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_text(json.dumps({"type": "ping"}))
            except asyncio.QueueEmpty:
                pass

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        store.remove_ws_subscriber(queue)


# ── AI Analyze-Threat (Frontend Compat) ──────────────────────────────────────


@router.post("/api/analyze-threat", response_model=AnalyzeThreatResponse)
async def analyze_threat(body: AnalyzeThreatRequest) -> AnalyzeThreatResponse:
    """
    Re-analyze a threat event using the AI Oracle.

    Called by the frontend when the user clicks "Re-analyze with AI".
    Dispatches to the oracle agent and returns a synthesized analysis
    in the frontend's expected schema.

    Args:
        body: AnalyzeThreatRequest with the frontend ApiRequestLog.

    Returns:
        AnalyzeThreatResponse with structured analysis matching frontend ThreatExplanation.
    """
    from agents.oracle_agent import OracleAgent
    from core.models import ViolationType, EventStatus, EventRecord

    log = body.requestLog
    violation_str = log.get("threatType", "UNKNOWN")

    # Map frontend threatType to ViolationType
    _vtype_map = {
        "BOLA": ViolationType.BOLA,
        "BFLA": ViolationType.BFLA,
        "SEQUENCE_SKEW": ViolationType.SEQUENCE,
        "TOKEN_REPLAY": ViolationType.REPLAY,
        "EXCESSIVE_DATA": ViolationType.RATE,
        "NONE": None,
    }
    violation_type = _vtype_map.get(violation_str)

    # Build a synthetic EventRecord for oracle processing
    synthetic_event = EventRecord(
        event_id=uuid.uuid4().hex,
        request_id=log.get("id", uuid.uuid4().hex),
        timestamp=datetime.now(timezone.utc).isoformat(),
        endpoint=log.get("endpoint", "/unknown"),
        method=log.get("method", "GET"),
        user=log.get("userId", "unknown"),
        role=log.get("userRole", "unknown"),
        session_id=uuid.uuid4().hex,
        context_hash=log.get("contextHash", "0x0000"),
        status=EventStatus.BLOCKED if log.get("status") == "BLOCKED" else EventStatus.ALLOWED,
        violation_type=violation_type,
        enforcement_latency_ms=log.get("latencyMs", 0.0),
    )

    try:
        from agents.oracle_agent import OracleAgent, _build_template_analysis_static
        from core.config import get_settings
        settings = get_settings()

        if settings.openrouter_api_key:
            agent = OracleAgent()
            # Build a quick analysis via LLM (blocking for this endpoint is acceptable — it's user-triggered)
            analysis = await agent._call_llm(synthetic_event, violation_str)
        else:
            from agents.oracle_agent import _TEMPLATES, _OWASP_TAGS, _MITRE_TAGS
            analysis = OracleAnalysis(
                explanation=_TEMPLATES.get(violation_str, _TEMPLATES.get("UNKNOWN", "")),
                owasp_tag=_OWASP_TAGS.get(violation_str, "OWASP API Security Top 10"),
                mitre_technique=_MITRE_TAGS.get(violation_str, "T1078 — Valid Accounts"),
                confidence=0.95,
            )

        # Convert to frontend ThreatExplanation schema
        endpoint_path = log.get("endpoint", "/unknown")
        context_hash = log.get("contextHash", "0xBAD0")
        expected_hash = log.get("expectedHash", "0x0000")

        frontend_analysis = {
            "title": f"{violation_str.replace('_', ' ').title()} Detected",
            "summary": analysis.explanation[:200] if analysis.explanation else "",
            "detailedAnalysis": analysis.explanation,
            "owaspCategory": analysis.owasp_tag,
            "mitreAttack": analysis.mitre_technique,
            "cweId": "CWE-285: Improper Authorization",
            "riskScore": int(analysis.confidence * 100),
            "recommendedAction": "Quarantine session and enforce zero-trust boundary.",
            "expectedSequence": ["POST /auth/token", "GET /bank/api/v1/users/me", endpoint_path],
            "receivedSequence": [endpoint_path],
            "hashDelta": {
                "expected": expected_hash,
                "received": context_hash,
                "bitwiseCalculation": f"({expected_hash} << 1) ^ Hash({endpoint_path}) = {context_hash} [VIOLATION]",
            },
            "policyRuleViolated": f"POL-{violation_str}-01: Zero-Trust Enforcement Gate",
            "quarantined": False,
        }

        return AnalyzeThreatResponse(success=True, analysis=frontend_analysis)

    except Exception as exc:
        return AnalyzeThreatResponse(
            success=False,
            error=str(exc),
        )
