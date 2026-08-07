"""
Q-SAFE FastAPI Application Entry Point
========================================
Assembles all components, runs the startup self-check, and launches
the autonomous background agents.

Startup sequence:
  1. Initialize the policy engine (generate allowlist + HMAC sign)
  2. Verify the policy artifact signature (tamper detection)
  3. Run startup self-check:
       a. Valid sequence → must PASS enforcement
       b. BFLA sequence → must BLOCK enforcement
     → App refuses to boot if self-check fails
  4. Start profiler_agent and oracle_agent as asyncio background tasks
  5. Seed 30 synthetic baseline traffic events
  6. Start ambient traffic generator (benign events every ~2s)
  7. Serve all routers with enforcement middleware

Run: uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request

from core.config import get_settings
from core.crypto import generate_session_id, issue_jwt, JWTError, verify_jwt
from core.logging import get_audit_logger
from core.models import (
    EventRecord,
    EventStatus,
    ViolationType,
)
from gateway.enforcement import EnforcementMiddleware
from gateway.policy import get_policy_engine
from gateway.sequence import get_sequence_engine, hash_to_hex
from gateway.rate_limit import get_rate_limiter
from gateway.bfla import get_bfla_detector
from gateway.bola import get_bola_detector


# ── Startup Self-Check ────────────────────────────────────────────────────────


def _run_startup_self_check() -> None:
    """
    Execute the startup self-check.

    Test 1: A valid user sequence (users/me → accounts/{id}) must PASS.
    Test 2: A BFLA attempt (user role → admin endpoint) must BLOCK.

    Raises:
        RuntimeError if any check fails — app refuses to boot.
    """
    logger = get_audit_logger()
    policy = get_policy_engine()
    bfla = get_bfla_detector()

    print("\n" + "=" * 60, flush=True)
    print("  Q-SAFE STARTUP SELF-CHECK", flush=True)
    print("=" * 60, flush=True)

    all_passed = True

    # ── Test 1: Valid sequence must PASS ──────────────────────────────────
    print("\n[SELF-CHECK 1] Valid sequence: users/me → accounts/{id}", flush=True)
    try:
        from gateway.sequence import ccfh_update, hash_sequence

        # Simulate session: alice does /users/me then /accounts/A-1001
        USERS_ME_ID = 0x1A01
        ACCOUNTS_ID = 0x2B02

        h0 = 0
        h1 = ccfh_update(h0, USERS_ME_ID)
        h2 = ccfh_update(h1, ACCOUNTS_ID)

        allowed_h1 = policy.is_sequence_allowed("user", h1)
        allowed_h2 = policy.is_sequence_allowed("user", h2)

        if allowed_h1 and allowed_h2:
            print(f"  ✓ PASS: hash after step 1 = {hash_to_hex(h1)} → IN allowlist", flush=True)
            print(f"  ✓ PASS: hash after step 2 = {hash_to_hex(h2)} → IN allowlist", flush=True)
            logger.log_startup_event("self_check", "PASS", "Valid sequence test passed")
        else:
            print(f"  ✗ FAIL: h1 allowed={allowed_h1}, h2 allowed={allowed_h2}", flush=True)
            logger.log_startup_event("self_check", "FAIL", f"Valid sequence test failed: h1={allowed_h1}, h2={allowed_h2}")
            all_passed = False

    except Exception as exc:
        print(f"  ✗ FAIL: Exception during valid sequence test: {exc}", flush=True)
        logger.log_startup_event("self_check", "FAIL", str(exc))
        all_passed = False

    # ── Test 2: BFLA attempt must BLOCK ───────────────────────────────────
    print("\n[SELF-CHECK 2] BFLA: user role → admin endpoint 0x9F01", flush=True)
    try:
        ADMIN_USERS_ID = 0x9F01
        is_violation, detail = bfla.check("user", ADMIN_USERS_ID)

        if is_violation:
            print(f"  ✓ PASS: BFLA correctly BLOCKED — {detail}", flush=True)
            logger.log_startup_event("self_check", "PASS", "BFLA test passed")
        else:
            print("  ✗ FAIL: BFLA check returned allowed (should have blocked!)", flush=True)
            logger.log_startup_event("self_check", "FAIL", "BFLA test: expected BLOCK but got ALLOW")
            all_passed = False

    except Exception as exc:
        print(f"  ✗ FAIL: Exception during BFLA test: {exc}", flush=True)
        logger.log_startup_event("self_check", "FAIL", str(exc))
        all_passed = False

    # ── Test 3: Policy artifact signature verification ────────────────────
    print("\n[SELF-CHECK 3] Policy artifact HMAC signature verification", flush=True)
    try:
        artifact = policy.get_artifact()
        if artifact is None:
            raise RuntimeError("Policy artifact is None after initialization")
        is_valid = policy.verify_artifact(artifact)
        if is_valid:
            print("  ✓ PASS: Policy artifact HMAC signature valid", flush=True)
            logger.log_startup_event("self_check", "PASS", "Policy HMAC verification passed")
        else:
            print("  ✗ FAIL: Policy artifact signature INVALID — possible tampering", flush=True)
            logger.log_startup_event("self_check", "FAIL", "Policy artifact signature invalid")
            all_passed = False
    except Exception as exc:
        print(f"  ✗ FAIL: Exception during signature check: {exc}", flush=True)
        logger.log_startup_event("self_check", "FAIL", str(exc))
        all_passed = False

    # ── Final verdict ─────────────────────────────────────────────────────
    print("\n" + "=" * 60, flush=True)
    if all_passed:
        print("  ✅ ALL SELF-CHECKS PASSED — BOOT AUTHORIZED", flush=True)
    else:
        print("  ❌ SELF-CHECK FAILED — REFUSING TO BOOT", flush=True)
    print("=" * 60 + "\n", flush=True)

    if not all_passed:
        raise RuntimeError(
            "Q-SAFE startup self-check FAILED. "
            "The policy engine is in an inconsistent state. "
            "Check the logs and review gateway/policy.py."
        )


# ── Ambient Traffic Generator ─────────────────────────────────────────────────

_AMBIENT_USERS = [
    ("alice", "user", "A-1001"),
    ("bob", "user", "B-2002"),
    ("admin", "admin", None),
]

_AMBIENT_ENDPOINTS_USER = [
    "/bank/api/v1/users/me",
    "/bank/api/v1/accounts/{account_id}",
    "/bank/api/v1/accounts/{account_id}/transactions",
]

_AMBIENT_ENDPOINTS_ADMIN = [
    "/bank/api/v1/users/me",
    "/bank/api/v1/admin/users",
]

# Active sessions for ambient traffic: username → (session_id, token)
_ambient_sessions: dict = {}


def _get_ambient_token(username: str, role: str, account_id: str | None) -> tuple[str, str]:
    """Get or create an ambient session token."""
    if username not in _ambient_sessions:
        sid = generate_session_id()
        token = issue_jwt(sub=username, role=role, session_id=sid, account_id=account_id)
        _ambient_sessions[username] = (sid, token)
    return _ambient_sessions[username]


async def _emit_ambient_event(
    username: str,
    role: str,
    account_id: str | None,
    path: str,
) -> None:
    """
    Emit one synthetic ambient traffic event through the enforcement pipeline.
    """
    from simulator.attack_gen import _run_single_enforcement, _build_event
    from telemetry.store import get_telemetry_store
    from agents.queue import get_event_queue

    sid, token = _get_ambient_token(username, role, account_id)

    # Substitute {account_id} template
    actual_path = path.replace("{account_id}", account_id or "A-1001")

    allowed, latency, detail, vtype = await _run_single_enforcement(token, actual_path)

    event = _build_event(
        user=username,
        role=role,
        session_id=sid,
        token=token,
        path=actual_path,
        method="GET",
        allowed=allowed,
        latency_ms=latency,
        violation_type=vtype,
        violation_detail=detail,
    )

    store = get_telemetry_store()
    await store.record_event(event)
    await get_event_queue().enqueue(event)


async def _seed_baseline_traffic(count: int) -> None:
    """
    Seed synthetic baseline traffic events at startup.

    Generates `count` realistic events from alice, bob, and admin
    to populate the dashboard immediately on boot.

    Args:
        count: Number of events to generate.
    """
    print(f"[Startup] Seeding {count} baseline traffic events...", flush=True)

    for i in range(count):
        username, role, acct = random.choice(_AMBIENT_USERS)
        if role == "admin":
            endpoints = _AMBIENT_ENDPOINTS_ADMIN
        else:
            endpoints = _AMBIENT_ENDPOINTS_USER

        path = random.choice(endpoints)
        try:
            await _emit_ambient_event(username, role, acct, path)
        except Exception as exc:
            print(f"[Startup] WARN: seed event {i} failed: {exc}", flush=True)

        await asyncio.sleep(0.01)  # Small delay to spread timestamps

    print(f"[Startup] Baseline seeding complete ({count} events).", flush=True)


async def _ambient_traffic_loop(interval: float) -> None:
    """
    Background task: emit benign ambient traffic every ~interval seconds.

    Runs indefinitely until cancelled.

    Args:
        interval: Target interval between events in seconds.
    """
    print(f"[AmbientTraffic] Started — emitting events every ~{interval}s", flush=True)
    while True:
        try:
            username, role, acct = random.choice(_AMBIENT_USERS)
            if role == "admin":
                endpoints = _AMBIENT_ENDPOINTS_ADMIN
            else:
                endpoints = _AMBIENT_ENDPOINTS_USER

            path = random.choice(endpoints)
            await _emit_ambient_event(username, role, acct, path)

        except asyncio.CancelledError:
            print("[AmbientTraffic] Cancelled.", flush=True)
            break
        except Exception as exc:  # noqa: BLE001
            print(f"[AmbientTraffic] WARN: {exc}", flush=True)

        # Add ±20% jitter to interval
        jitter = interval * 0.2
        delay = interval + random.uniform(-jitter, jitter)
        await asyncio.sleep(max(0.5, delay))


# ── Background Task Registry ──────────────────────────────────────────────────


class BackgroundTaskRegistry:
    """
    Collects and drains async background tasks dispatched by the enforcement middleware.

    The enforcement middleware appends coroutines here; they are drained
    by a background loop after each request.
    """

    def __init__(self) -> None:
        self._pending: List = []

    def append(self, coro) -> None:
        """Add a coroutine to the pending list."""
        self._pending.append(coro)

    async def drain(self) -> None:
        """Drain and await all pending coroutines."""
        tasks = self._pending[:]
        self._pending.clear()
        for coro in tasks:
            try:
                await coro
            except Exception as exc:
                print(f"[BackgroundTask] WARN: {exc}", flush=True)


async def _background_task_drainer(registry: BackgroundTaskRegistry) -> None:
    """Continuously drain the background task registry."""
    while True:
        try:
            await registry.drain()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[TaskDrainer] WARN: {exc}", flush=True)
        await asyncio.sleep(0.05)  # 50ms polling — very fast drain cycle


# ── Application Lifespan ──────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    FastAPI lifespan context manager.

    Startup: initialize everything, run self-check, start agents.
    Shutdown: cancel all background tasks gracefully.
    """
    settings = get_settings()
    logger = get_audit_logger()

    # ── Step 1: Initialize policy engine ──────────────────────────────────
    print("[Startup] Initializing policy engine...", flush=True)
    policy = get_policy_engine()
    artifact = policy.initialize()
    endpoint_count = len(artifact.endpoints)
    role_count = len(artifact.allowlists)
    total_hashes = sum(len(v) for v in artifact.allowlists.values())
    print(
        f"[Startup] Policy engine ready: {endpoint_count} endpoints, "
        f"{role_count} roles, {total_hashes} valid hashes in allowlist.",
        flush=True,
    )
    logger.log_startup_event("policy_init", "OK", f"{total_hashes} hashes generated")

    # ── Step 2: Startup self-check ─────────────────────────────────────────
    # This will raise RuntimeError and abort boot if any check fails
    _run_startup_self_check()

    # ── Step 3: Initialize background task registry ────────────────────────
    task_registry = BackgroundTaskRegistry()
    app.state.background_tasks = task_registry

    # ── Step 4: Start background agents and tasks ──────────────────────────
    from agents.profiler_agent import ProfilerAgent
    from agents.oracle_agent import OracleAgent
    from agents.queue import get_event_queue

    profiler = ProfilerAgent()
    oracle = OracleAgent()
    app.state.profiler_agent = profiler
    app.state.oracle_agent = oracle

    # Wire oracle to consume blocked events from profiler's analysis
    # (Both share the same queue but oracle has a separate internal queue)
    _original_enqueue = get_event_queue().enqueue

    async def _forwarding_enqueue(event: EventRecord) -> None:
        await _original_enqueue(event)
        # Also forward blocked/high-risk events to oracle
        if event.status == EventStatus.BLOCKED:
            await oracle.submit(event)

    get_event_queue().enqueue = _forwarding_enqueue  # type: ignore[method-assign]

    background_tasks = [
        asyncio.create_task(profiler.run(), name="profiler-agent"),
        asyncio.create_task(oracle.run(), name="oracle-agent"),
        asyncio.create_task(
            _background_task_drainer(task_registry), name="task-drainer"
        ),
    ]

    # ── Step 5: Seed baseline traffic ─────────────────────────────────────
    await _seed_baseline_traffic(settings.seed_traffic_events)

    # ── Step 6: Start ambient traffic generator ────────────────────────────
    ambient_task = asyncio.create_task(
        _ambient_traffic_loop(settings.ambient_traffic_interval_seconds),
        name="ambient-traffic",
    )
    background_tasks.append(ambient_task)

    print("\n[Q-SAFE] 🛡️  Gateway is ONLINE. All systems operational.\n", flush=True)
    logger.log_startup_event("boot", "OK", "All systems operational")

    # ── Yield control to FastAPI ───────────────────────────────────────────
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────
    print("\n[Q-SAFE] Shutting down background tasks...", flush=True)
    profiler.stop()
    oracle.stop()
    for task in background_tasks:
        task.cancel()
    await asyncio.gather(*background_tasks, return_exceptions=True)
    print("[Q-SAFE] Shutdown complete.", flush=True)


# ── Application Assembly ──────────────────────────────────────────────────────


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Fully configured FastAPI app instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="Q-SAFE: Zero-Trust API Security Gateway",
        description=(
            "Query-Sequence Authorization & Forensic Enforcement — "
            "Inline enforcement engine, behavioral profiler, and AI threat oracle."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ───────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Enforcement Middleware (must be added AFTER CORS) ──────────────────
    app.add_middleware(EnforcementMiddleware)

    # ── Routers ────────────────────────────────────────────────────────────
    from auth.router import router as auth_router
    from protected_api.banking import router as banking_router
    from simulator.attack_gen import router as simulator_router
    from telemetry.api import router as telemetry_router

    app.include_router(auth_router)
    app.include_router(banking_router)
    app.include_router(simulator_router)
    app.include_router(telemetry_router)

    # ── Health check ───────────────────────────────────────────────────────
    @app.get("/health", tags=["System"])
    async def health() -> dict:
        """Return gateway health status."""
        policy = get_policy_engine()
        return {
            "status": "healthy",
            "policy_initialized": policy.initialized,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
        }

    return app


# ── WSGI App ──────────────────────────────────────────────────────────────────

app = create_app()


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level="info",
    )
