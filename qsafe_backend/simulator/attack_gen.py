"""
Q-SAFE Attack Simulation Suite
================================
Programmatic red-team payload generator and REST trigger.

POST /simulator/attack  body: {"type": "bola"|"bfla"|"rate_abuse"|"replay"}

Simulations:
  bola:       alice's token requests bob's account B-2002
  bfla:       alice's token calls DELETE /admin/users/bob
  rate_abuse: 200 rapid-fire requests from one session
  replay:     expired/reused JWT

Each simulation returns the full event record including the
enforcement verdict and latency measured by the gateway.

These simulations call the gateway enforcement pipeline DIRECTLY
(not via HTTP) to avoid self-referential network calls in tests.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from core.crypto import generate_session_id, issue_expired_jwt, issue_jwt
from core.models import (
    AttackRequest,
    AttackResponse,
    AttackType,
    EventRecord,
    EventStatus,
    ViolationType,
)

router = APIRouter(prefix="/simulator", tags=["Attack Simulator"])


# ── Internal Gateway Enforcement (direct call, no HTTP) ───────────────────────


async def _run_single_enforcement(
    token: str,
    path: str,
    method: str = "GET",
) -> tuple[bool, float, Optional[str], Optional[ViolationType]]:
    """
    Run a single request through the enforcement pipeline directly.

    Returns:
        (allowed, latency_ms, violation_detail, violation_type)
    """
    from core.crypto import JWTError, verify_jwt
    from gateway.bfla import get_bfla_detector
    from gateway.bola import get_bola_detector
    from gateway.policy import get_policy_engine
    from gateway.rate_limit import get_rate_limiter
    from gateway.sequence import get_sequence_engine, hash_to_hex

    t_start = time.perf_counter()

    # Step 1: JWT verification
    try:
        token_payload = verify_jwt(token)
    except JWTError as exc:
        latency = (time.perf_counter() - t_start) * 1000
        return False, latency, str(exc), ViolationType.REPLAY

    session_id = token_payload.session_id

    # Step 2: Rate limit
    rate_limiter = get_rate_limiter()
    limited, _ = rate_limiter.check_and_record(session_id)
    if limited:
        latency = (time.perf_counter() - t_start) * 1000
        return False, latency, "Rate limit exceeded", ViolationType.RATE

    # Step 3: Endpoint ID resolution
    policy = get_policy_engine()
    endpoint_id = policy.resolve_endpoint_id(path)
    if endpoint_id is None:
        latency = (time.perf_counter() - t_start) * 1000
        return False, latency, f"Path '{path}' not in policy", ViolationType.BFLA

    # Step 4: BFLA check
    bfla = get_bfla_detector()
    bfla_violation, bfla_detail = bfla.check(token_payload.role, endpoint_id)
    if bfla_violation:
        latency = (time.perf_counter() - t_start) * 1000
        return False, latency, bfla_detail, ViolationType.BFLA

    # Step 5: BOLA check
    bola = get_bola_detector()
    bola_violation, bola_detail = bola.check(token_payload, path, endpoint_id)
    if bola_violation:
        latency = (time.perf_counter() - t_start) * 1000
        return False, latency, bola_detail, ViolationType.BOLA

    # Step 6: Sequence check
    seq_engine = get_sequence_engine()
    new_hash = seq_engine.advance(session_id, endpoint_id, path)
    is_allowed = policy.is_sequence_allowed(token_payload.role, new_hash)
    if not is_allowed:
        seq_engine.revoke(session_id)
        latency = (time.perf_counter() - t_start) * 1000
        from gateway.sequence import hash_to_hex
        return (
            False,
            latency,
            f"Sequence hash {hash_to_hex(new_hash)} not in allowlist",
            ViolationType.SEQUENCE,
        )

    latency = (time.perf_counter() - t_start) * 1000
    return True, latency, None, None


def _build_event(
    *,
    user: str,
    role: str,
    session_id: str,
    token: str,
    path: str,
    method: str,
    allowed: bool,
    latency_ms: float,
    violation_type: Optional[ViolationType],
    violation_detail: Optional[str],
    context_hash: str = "0x0000000000000000",
) -> EventRecord:
    """Build an EventRecord for a simulated attack event."""
    return EventRecord(
        event_id=uuid.uuid4().hex,
        request_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc).isoformat(),
        endpoint=path,
        method=method,
        user=user,
        role=role,
        session_id=session_id,
        context_hash=context_hash,
        status=EventStatus.ALLOWED if allowed else EventStatus.BLOCKED,
        violation_type=violation_type,
        enforcement_latency_ms=round(latency_ms, 3),
        ip_address="127.0.0.1",
        user_agent="Q-SAFE/AttackSimulator",
        jwt_snippet=token[:60],
    )


# ── Simulation Implementations ────────────────────────────────────────────────


async def _simulate_bola() -> AttackResponse:
    """
    BOLA attack: alice accesses bob's account B-2002.

    Alice's JWT has account_id=A-1001, but the request targets B-2002.
    Expected outcome: BLOCKED with violation_type=BOLA.
    """
    session_id = generate_session_id()
    token = issue_jwt(sub="alice", role="user", session_id=session_id, account_id="A-1001")
    path = "/bank/api/v1/accounts/B-2002"

    # First do a legitimate step to establish sequence (users/me)
    await _run_single_enforcement(token, "/bank/api/v1/users/me")

    allowed, latency, detail, vtype = await _run_single_enforcement(token, path)

    event = _build_event(
        user="alice",
        role="user",
        session_id=session_id,
        token=token,
        path=path,
        method="GET",
        allowed=allowed,
        latency_ms=latency,
        violation_type=vtype,
        violation_detail=detail,
    )

    # Record in telemetry
    from telemetry.store import get_telemetry_store
    from agents.queue import get_event_queue
    store = get_telemetry_store()
    await store.record_event(event)
    await get_event_queue().enqueue(event)

    return AttackResponse(
        attack_type="bola",
        description="alice's token requests bob's account B-2002 (BOLA: Broken Object Level Authorization)",
        event=event,
        enforcement_verdict="BLOCKED" if not allowed else "ALLOWED (UNEXPECTED — CHECK POLICY)",
        enforcement_latency_ms=latency,
        success=not allowed,
    )


async def _simulate_bfla() -> AttackResponse:
    """
    BFLA attack: alice (role=user) calls DELETE /admin/users/bob.

    Expected outcome: BLOCKED with violation_type=BFLA.
    """
    session_id = generate_session_id()
    token = issue_jwt(sub="alice", role="user", session_id=session_id, account_id="A-1001")
    path = "/bank/api/v1/admin/users/bob"

    allowed, latency, detail, vtype = await _run_single_enforcement(token, path, method="DELETE")

    event = _build_event(
        user="alice",
        role="user",
        session_id=session_id,
        token=token,
        path=path,
        method="DELETE",
        allowed=allowed,
        latency_ms=latency,
        violation_type=vtype,
        violation_detail=detail,
    )

    from telemetry.store import get_telemetry_store
    from agents.queue import get_event_queue
    store = get_telemetry_store()
    await store.record_event(event)
    await get_event_queue().enqueue(event)

    return AttackResponse(
        attack_type="bfla",
        description="alice (role=user) calls DELETE /bank/api/v1/admin/users/bob (BFLA: Broken Function Level Auth)",
        event=event,
        enforcement_verdict="BLOCKED" if not allowed else "ALLOWED (UNEXPECTED — CHECK POLICY)",
        enforcement_latency_ms=latency,
        success=not allowed,
    )


async def _simulate_rate_abuse() -> AttackResponse:
    """
    Rate abuse: 200 rapid-fire requests from one session.

    Expected outcome: Requests after the limit are BLOCKED with violation_type=RATE.
    """
    from core.config import get_settings
    settings = get_settings()

    session_id = generate_session_id()
    token = issue_jwt(sub="alice", role="user", session_id=session_id, account_id="A-1001")
    path = "/bank/api/v1/users/me"

    limit = settings.rate_limit_requests
    total_requests = limit + 10  # Push past the limit

    results: List[tuple[bool, float, Optional[str], Optional[ViolationType]]] = []
    for _ in range(total_requests):
        result = await _run_single_enforcement(token, path)
        results.append(result)
        # Reset sequence on each block so rate_abuse test focuses on rate, not sequence
        if not result[0] and result[3] == ViolationType.SEQUENCE:
            from gateway.sequence import get_sequence_engine
            get_sequence_engine().revoke(session_id)

    # Find first blocked request
    first_block = next((r for r in results if not r[0]), None)

    blocked_count = sum(1 for r in results if not r[0] and r[3] == ViolationType.RATE)
    avg_latency = sum(r[1] for r in results) / len(results)

    allowed = first_block is None
    latency = first_block[1] if first_block else avg_latency
    vtype = first_block[3] if first_block else None

    event = _build_event(
        user="alice",
        role="user",
        session_id=session_id,
        token=token,
        path=path,
        method="GET",
        allowed=allowed,
        latency_ms=latency,
        violation_type=vtype,
        violation_detail=f"{total_requests} rapid-fire requests; {blocked_count} blocked by rate limiter",
    )

    from telemetry.store import get_telemetry_store
    from agents.queue import get_event_queue
    store = get_telemetry_store()
    await store.record_event(event)
    await get_event_queue().enqueue(event)

    return AttackResponse(
        attack_type="rate_abuse",
        description=(
            f"{total_requests} rapid-fire requests from one session; "
            f"{blocked_count} blocked. Rate limit: {limit} req/60s."
        ),
        event=event,
        enforcement_verdict=f"BLOCKED after {limit} requests" if blocked_count > 0 else "NOT_BLOCKED",
        enforcement_latency_ms=avg_latency,
        success=blocked_count > 0,
    )


async def _simulate_replay() -> AttackResponse:
    """
    Token replay: present an expired JWT.

    Expected outcome: BLOCKED with violation_type=REPLAY.
    """
    session_id = generate_session_id()
    expired_token = issue_expired_jwt(sub="alice", role="user", session_id=session_id)
    path = "/bank/api/v1/users/me"

    allowed, latency, detail, vtype = await _run_single_enforcement(expired_token, path)

    event = _build_event(
        user="alice",
        role="user",
        session_id=session_id,
        token=expired_token,
        path=path,
        method="GET",
        allowed=allowed,
        latency_ms=latency,
        violation_type=vtype,
        violation_detail=detail,
    )

    from telemetry.store import get_telemetry_store
    from agents.queue import get_event_queue
    store = get_telemetry_store()
    await store.record_event(event)
    await get_event_queue().enqueue(event)

    return AttackResponse(
        attack_type="replay",
        description="Expired JWT presented — token replay / authentication bypass attempt",
        event=event,
        enforcement_verdict="BLOCKED" if not allowed else "ALLOWED (UNEXPECTED — CHECK TOKEN EXPIRY)",
        enforcement_latency_ms=latency,
        success=not allowed,
    )


# ── REST Endpoint ─────────────────────────────────────────────────────────────


@router.post("/attack", response_model=AttackResponse)
async def trigger_attack(body: AttackRequest) -> AttackResponse:
    """
    Trigger a programmatic red-team attack simulation.

    Each simulation type exercises a specific enforcement check:
    - bola:       BOLA detection (account ownership)
    - bfla:       BFLA detection (role-level auth)
    - rate_abuse: Sliding window rate limiter
    - replay:     JWT signature/expiry validation

    The simulation runs the enforcement pipeline directly and returns
    the full event record including verdict and latency.

    Args:
        body: AttackRequest specifying the attack type.

    Returns:
        AttackResponse with event record and gateway verdict.
    """
    attack_map = {
        AttackType.BOLA: _simulate_bola,
        AttackType.BFLA: _simulate_bfla,
        AttackType.RATE_ABUSE: _simulate_rate_abuse,
        AttackType.REPLAY: _simulate_replay,
    }

    handler = attack_map.get(body.type)
    if handler is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown attack type: {body.type}")

    return await handler()
