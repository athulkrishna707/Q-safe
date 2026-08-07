"""
Q-SAFE Inline Enforcement Engine
==================================
THE HOT PATH — FastAPI middleware executing in every request.

This is the security-critical enforcement core. The entire pipeline is:
  SYNCHRONOUS · O(1) · <15ms · NO network I/O · NO awaits in decision logic

Pipeline order (each step is a potential BLOCK point):
  1. Extract + verify JWT (signature, expiry, role claim, session_id)
  2. Rate-limit check (sliding window, per session)
  3. Resolve endpoint ID from the route table
  4. BFLA check: is this endpoint_id permitted for the token's role?
  5. BOLA check: for ownership-protected routes, does owner match?
  6. Sequence check: update rolling CCFH hash, verify against role allowlist
  7. Verdict: ALLOW → continue; BLOCK → 403 + revoke session + emit event

DESIGN BOUNDARY:
  - Everything in this file is DETERMINISTIC and OFFLINE.
  - AI agents (oracle_agent, profiler_agent) are completely separate and
    run AFTER this path on the async event queue. They NEVER block requests.
  - Audit logging is dispatched as a background asyncio task (non-blocking).
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from core.crypto import JWTError, verify_jwt
from core.logging import get_audit_logger
from core.models import (
    EnforcementVerdict,
    EventRecord,
    EventStatus,
    TokenPayload,
    ViolationType,
)
from gateway.bfla import get_bfla_detector
from gateway.bola import get_bola_detector
from gateway.policy import get_policy_engine
from gateway.rate_limit import get_rate_limiter
from gateway.sequence import get_sequence_engine, hash_to_hex

# Paths that bypass the enforcement middleware entirely
_BYPASS_PREFIXES = (
    "/auth/",
    "/telemetry/",
    "/sessions/",
    "/ws/",
    "/simulator/",
    "/api/analyze-threat",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/favicon.ico",
)


class EnforcementMiddleware(BaseHTTPMiddleware):
    """
    Q-SAFE inline enforcement middleware.

    Intercepts every HTTP request destined for the protected banking API.
    Routes not prefixed with /bank/ (or in _BYPASS_PREFIXES) pass through unchecked.

    The enforcement decision is fully synchronous and deterministic.
    All side effects (audit log, event queue, metrics) are dispatched
    as background tasks after the verdict is reached.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._logger = get_audit_logger()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Enforce the Q-SAFE security pipeline on every incoming request.

        This method is async (required by Starlette), but the DECISION LOGIC
        within _enforce() is purely synchronous. The async overhead is only
        for dispatching background tasks after the verdict.
        """
        # ── Bypass check ───────────────────────────────────────────────────
        path = request.url.path
        if not path.startswith("/bank/") and not self._requires_enforcement(path):
            return await call_next(request)

        request_id = uuid.uuid4().hex

        # ── THE SYNCHRONOUS DECISION (no awaits below until verdict is done) ─
        t_start = time.perf_counter()
        verdict = self._enforce(request, request_id)
        latency_ms = (time.perf_counter() - t_start) * 1000.0

        verdict.latency_ms = latency_ms

        # ── Build event record (before any side effects) ───────────────────
        token_payload = getattr(request.state, "token_payload", None)
        event = self._build_event_record(request, request_id, verdict, token_payload)

        # ── Dispatch side effects as background tasks (non-blocking) ────────
        request.state.enforcement_event = event
        request.state.request_id = request_id

        if verdict.allowed:
            # Forward to the protected route handler
            response = await call_next(request)
            # Record metrics and audit log in background
            request.app.state.background_tasks.append(
                self._post_allow_tasks(event, latency_ms)
            )
            return response
        else:
            # Block immediately — no downstream call
            request.app.state.background_tasks.append(
                self._post_block_tasks(event, verdict, latency_ms)
            )
            return self._block_response(verdict, request_id, latency_ms)

    def _requires_enforcement(self, path: str) -> bool:
        """Return True if the path requires enforcement (not a bypass path)."""
        for prefix in _BYPASS_PREFIXES:
            if path.startswith(prefix) or path == prefix.rstrip("/"):
                return False
        return False  # Only /bank/* paths get enforcement

    def _enforce(self, request: Request, request_id: str) -> EnforcementVerdict:
        """
        Execute the synchronous enforcement pipeline.

        CRITICAL: This method must remain:
          - Purely synchronous (no await)
          - O(1) in all operations
          - Free of network I/O
          - Free of blocking operations

        Args:
            request:    Incoming HTTP request.
            request_id: Unique ID for this request.

        Returns:
            EnforcementVerdict with the final decision.
        """
        path = request.url.path

        # ── Step 1: JWT Extraction + Verification ──────────────────────────
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.REPLAY,
                violation_detail="Missing or malformed Authorization header",
            )

        raw_token = auth_header[len("Bearer "):]
        try:
            token = verify_jwt(raw_token)
        except JWTError as exc:
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.REPLAY,
                violation_detail=f"JWT validation failed: {exc}",
            )

        # Store decoded token on request state for downstream handlers
        request.state.token_payload = token
        request.state.raw_token = raw_token

        session_id = token.session_id

        # ── Step 2: Rate Limit Check ───────────────────────────────────────
        rate_limiter = get_rate_limiter()
        is_limited, _ = rate_limiter.check_and_record(session_id)
        if is_limited:
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.RATE,
                violation_detail=f"Rate limit exceeded for session {session_id}",
                session_id=session_id,
            )

        # ── Step 3: Endpoint ID Resolution ────────────────────────────────
        policy = get_policy_engine()
        endpoint_id = policy.resolve_endpoint_id(path)
        if endpoint_id is None:
            # Registered path prefix /bank/ but not in policy — deny
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.BFLA,
                violation_detail=f"Path '{path}' is not registered in the policy",
                session_id=session_id,
            )

        # ── Step 4: BFLA Check ─────────────────────────────────────────────
        bfla = get_bfla_detector()
        bfla_violation, bfla_detail = bfla.check(token.role, endpoint_id)
        if bfla_violation:
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.BFLA,
                violation_detail=bfla_detail,
                endpoint_id=endpoint_id,
                session_id=session_id,
            )

        # ── Step 5: BOLA Check ─────────────────────────────────────────────
        bola = get_bola_detector()
        bola_violation, bola_detail = bola.check(token, path, endpoint_id)
        if bola_violation:
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.BOLA,
                violation_detail=bola_detail,
                endpoint_id=endpoint_id,
                session_id=session_id,
            )

        # ── Step 6: Sequence Hash Update + Allowlist Check ─────────────────
        seq_engine = get_sequence_engine()
        new_hash = seq_engine.advance(session_id, endpoint_id, path)

        is_allowed = policy.is_sequence_allowed(token.role, new_hash)
        if not is_allowed:
            # Revert hash advance on violation (session stays at previous state)
            seq_engine.revoke(session_id)
            return EnforcementVerdict(
                allowed=False,
                violation_type=ViolationType.SEQUENCE,
                violation_detail=(
                    f"Context hash {hash_to_hex(new_hash)} is not in the "
                    f"allowlist for role '{token.role}'"
                ),
                context_hash=new_hash,
                endpoint_id=endpoint_id,
                session_id=session_id,
            )

        # ── Step 7: ALLOW ──────────────────────────────────────────────────
        return EnforcementVerdict(
            allowed=True,
            context_hash=new_hash,
            endpoint_id=endpoint_id,
            session_id=session_id,
        )

    def _build_event_record(
        self,
        request: Request,
        request_id: str,
        verdict: EnforcementVerdict,
        token: Optional[TokenPayload],
    ) -> EventRecord:
        """
        Build the telemetry EventRecord from request + verdict data.

        Args:
            request:    Incoming HTTP request.
            request_id: Unique request ID.
            verdict:    Enforcement verdict.
            token:      Decoded JWT payload (may be None if JWT failed).

        Returns:
            EventRecord ready for telemetry store and agent queue.
        """
        raw_token = request.headers.get("Authorization", "")
        jwt_snippet = raw_token[len("Bearer "):len("Bearer ") + 60] if raw_token.startswith("Bearer ") else None

        user = token.sub if token else "unknown"
        role = token.role if token else "unknown"
        session_id = verdict.session_id or (token.session_id if token else "unknown")

        return EventRecord(
            event_id=uuid.uuid4().hex,
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            endpoint=request.url.path,
            method=request.method,
            user=user,
            role=role,
            session_id=session_id,
            context_hash=hash_to_hex(verdict.context_hash),
            status=EventStatus.ALLOWED if verdict.allowed else EventStatus.BLOCKED,
            violation_type=verdict.violation_type,
            enforcement_latency_ms=verdict.latency_ms,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
            jwt_snippet=jwt_snippet,
        )

    def _block_response(
        self,
        verdict: EnforcementVerdict,
        request_id: str,
        latency_ms: float,
    ) -> JSONResponse:
        """
        Build the structured 403 JSON error response for a blocked request.

        Args:
            verdict:    Enforcement verdict with violation details.
            request_id: Request correlation ID.
            latency_ms: Enforcement latency.

        Returns:
            JSONResponse with 403 status and structured error body.
        """
        violation = verdict.violation_type.value if verdict.violation_type else "UNKNOWN"
        return JSONResponse(
            status_code=403,
            content={
                "error": "GATEWAY_BLOCKED",
                "request_id": request_id,
                "violation_type": violation,
                "detail": verdict.violation_detail or "Request blocked by Q-SAFE enforcement policy",
                "enforcement_latency_ms": round(latency_ms, 3),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "owasp_ref": _OWASP_MAP.get(violation, "OWASP API Security Top 10"),
                "mitre_ref": _MITRE_MAP.get(violation, ""),
            },
        )

    async def _post_allow_tasks(self, event: EventRecord, latency_ms: float) -> None:
        """
        Async side effects for ALLOWED requests (runs after response is sent).

        - Update telemetry store metrics and event log
        - Write audit log entry
        - Enqueue event for profiler agent

        This method is awaited in a background task — NOT in the hot path.
        """
        try:
            from telemetry.store import get_telemetry_store
            from agents.queue import get_event_queue

            store = get_telemetry_store()
            await store.record_event(event)

            queue = get_event_queue()
            await queue.enqueue(event)

            self._logger.log_enforcement_event(
                request_id=event.request_id,
                session_id=event.session_id,
                user=event.user,
                role=event.role,
                endpoint=event.endpoint,
                method=event.method,
                verdict="allowed",
                violation_type=None,
                latency_ms=latency_ms,
                context_hash=event.context_hash,
                ip_address=event.ip_address,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[Enforcement] WARN: post-allow task error: {exc}", flush=True)

    async def _post_block_tasks(
        self,
        event: EventRecord,
        verdict: EnforcementVerdict,
        latency_ms: float,
    ) -> None:
        """
        Async side effects for BLOCKED requests (runs after 403 is sent).

        - Update telemetry store (blocked counters)
        - Revoke session hash state
        - Write audit log entry
        - Enqueue event for oracle + profiler agents

        This method is awaited in a background task — NOT in the hot path.
        """
        try:
            from telemetry.store import get_telemetry_store
            from agents.queue import get_event_queue
            from gateway.sequence import get_sequence_engine

            store = get_telemetry_store()
            await store.record_event(event)

            # Revoke session on block
            if verdict.session_id:
                get_sequence_engine().revoke(verdict.session_id)
                get_rate_limiter().reset_session(verdict.session_id)
                store.quarantine_session(verdict.session_id)

            queue = get_event_queue()
            await queue.enqueue(event)

            violation = verdict.violation_type.value if verdict.violation_type else "UNKNOWN"
            self._logger.log_enforcement_event(
                request_id=event.request_id,
                session_id=event.session_id,
                user=event.user,
                role=event.role,
                endpoint=event.endpoint,
                method=event.method,
                verdict="blocked",
                violation_type=violation,
                latency_ms=latency_ms,
                context_hash=event.context_hash,
                ip_address=event.ip_address,
                extra={"violation_detail": verdict.violation_detail},
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[Enforcement] WARN: post-block task error: {exc}", flush=True)


# ── OWASP / MITRE Reference Maps ─────────────────────────────────────────────

_OWASP_MAP = {
    "BOLA": "API1:2023 — Broken Object Level Authorization",
    "BFLA": "API5:2023 — Broken Function Level Authorization",
    "RATE": "API4:2023 — Unrestricted Resource Consumption",
    "REPLAY": "API2:2023 — Broken Authentication",
    "SEQUENCE": "API1:2023 — Broken Object Level Authorization (Sequence Violation)",
}

_MITRE_MAP = {
    "BOLA": "T1078 — Valid Accounts",
    "BFLA": "T1134 — Access Token Manipulation",
    "RATE": "T1498 — Network Denial of Service",
    "REPLAY": "T1078 — Valid Accounts",
    "SEQUENCE": "T1078 — Valid Accounts",
}
