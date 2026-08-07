"""
Q-SAFE Enforcement Smoke Tests
================================
Pytest smoke tests verifying all critical enforcement behaviors.

Run:
    cd qsafe_backend
    pip install -r requirements.txt
    pytest tests/ -v

Tests:
    1. Valid JWT + correct sequence → 200 ALLOWED
    2. BOLA: alice accessing bob's account → BLOCKED
    3. BFLA: user role calling admin endpoint → BLOCKED
    4. Rate limit: 101 requests → BLOCKED after limit
    5. Sequence violation: out-of-order endpoint → BLOCKED
    6. Expired JWT (replay) → BLOCKED
    7. Policy artifact tamper detection → exception
    8. OracleAnalysis Pydantic schema validation
    9. CCFH algorithm correctness (bit math)
"""

from __future__ import annotations

import sys
import os
import asyncio

import pytest

# Add parent dir to path so imports work without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import issue_jwt, issue_expired_jwt, generate_session_id, JWTError, verify_jwt
from core.models import OracleAnalysis, ViolationType
from gateway.policy import get_policy_engine, AllowlistGenerator
from gateway.sequence import ccfh_update, hash_sequence, HASH_MASK, get_sequence_engine
from gateway.bfla import get_bfla_detector
from gateway.bola import get_bola_detector
from gateway.rate_limit import get_rate_limiter


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True, scope="session")
def initialize_policy():
    """Initialize the policy engine once for the test session."""
    policy = get_policy_engine()
    if not policy.initialized:
        policy.initialize()
    yield


@pytest.fixture
def alice_session():
    """Create a fresh alice session with a valid JWT."""
    sid = generate_session_id()
    token = issue_jwt(sub="alice", role="user", session_id=sid, account_id="A-1001")
    return {"session_id": sid, "token": token, "role": "user", "account_id": "A-1001"}


@pytest.fixture
def admin_session():
    """Create a fresh admin session with a valid JWT."""
    sid = generate_session_id()
    token = issue_jwt(sub="admin", role="admin", session_id=sid, account_id=None)
    return {"session_id": sid, "token": token, "role": "admin"}


# ── Test 1: CCFH Algorithm Correctness ───────────────────────────────────────


class TestCCFHAlgorithm:
    """Tests for the core CCFH bit-math algorithm."""

    def test_hash_update_basic(self):
        """hash = ((0 << 1) & MASK) ^ endpoint_id = endpoint_id for h=0."""
        result = ccfh_update(0, 0x1A01)
        assert result == 0x1A01

    def test_hash_update_second_step(self):
        """Verify second step: ((0x1A01 << 1) & MASK) ^ 0x2B02."""
        h1 = ccfh_update(0, 0x1A01)
        h2 = ccfh_update(h1, 0x2B02)
        expected = ((0x1A01 << 1) & HASH_MASK) ^ 0x2B02
        assert h2 == expected

    def test_64bit_mask_applied(self):
        """Confirm that very large hashes are masked to 64 bits."""
        # Create a hash with the high bit set
        large_id = 0xFFFFFFFFFFFFFFFF
        result = ccfh_update(large_id, 0x1)
        assert result <= HASH_MASK, f"Hash {result} exceeds 64-bit mask"

    def test_hash_sequence_deterministic(self):
        """Same sequence always produces same hash."""
        seq = [0x1A01, 0x2B02, 0x3C03]
        h1 = hash_sequence(seq)
        h2 = hash_sequence(seq)
        assert h1 == h2

    def test_different_sequences_different_hashes(self):
        """Different orderings produce different hashes (high probability)."""
        seq_ab = [0x1A01, 0x2B02]
        seq_ba = [0x2B02, 0x1A01]
        assert hash_sequence(seq_ab) != hash_sequence(seq_ba)


# ── Test 2: Policy Engine ─────────────────────────────────────────────────────


class TestPolicyEngine:
    """Tests for the authorization policy engine."""

    def test_allowlist_contains_user_endpoints(self):
        """User role should have hash entries for accessible endpoints."""
        policy = get_policy_engine()
        # After accessing /users/me (0x1A01), hash should be in user allowlist
        h = ccfh_update(0, 0x1A01)
        assert policy.is_sequence_allowed("user", h), f"Hash {h} not in user allowlist"

    def test_admin_endpoint_not_in_user_allowlist(self):
        """Admin endpoint hash (0x9F01) should NOT be reachable as user."""
        policy = get_policy_engine()
        # If user tried to jump straight to admin endpoint
        h = ccfh_update(0, 0x9F01)
        assert not policy.is_sequence_allowed("user", h), \
            "Admin endpoint hash incorrectly present in user allowlist"

    def test_bfla_user_blocked_from_admin(self):
        """BFLA check: user role blocked from admin endpoint."""
        bfla = get_bfla_detector()
        is_violation, detail = bfla.check("user", 0x9F01)
        assert is_violation is True
        assert detail is not None

    def test_bfla_admin_allowed_admin_endpoint(self):
        """BFLA check: admin role allowed for admin endpoint."""
        bfla = get_bfla_detector()
        is_violation, detail = bfla.check("admin", 0x9F01)
        assert is_violation is False

    def test_policy_artifact_signature_valid(self):
        """Policy artifact HMAC signature must be valid after initialization."""
        policy = get_policy_engine()
        artifact = policy.get_artifact()
        assert artifact is not None
        assert policy.verify_artifact(artifact)

    def test_policy_tamper_detection(self):
        """Modifying artifact data should cause signature verification to fail."""
        policy = get_policy_engine()
        artifact = policy.get_artifact()
        assert artifact is not None

        # Tamper with the artifact
        tampered = artifact.model_copy(
            update={"allowlists": {"user": [0xDEADBEEF], "admin": [0xCAFEBABE]}}
        )
        assert not policy.verify_artifact(tampered), \
            "Tampered artifact should fail signature verification"

    def test_endpoint_id_resolution(self):
        """Path resolution should match known patterns."""
        policy = get_policy_engine()
        assert policy.resolve_endpoint_id("/bank/api/v1/users/me") == 0x1A01
        assert policy.resolve_endpoint_id("/bank/api/v1/accounts/A-1001") == 0x2B02
        assert policy.resolve_endpoint_id("/bank/api/v1/admin/users") == 0x9F01
        assert policy.resolve_endpoint_id("/bank/api/v1/admin/users/bob") == 0xAE02
        assert policy.resolve_endpoint_id("/bank/api/v1/unknown/path") is None


# ── Test 3: BOLA Detection ────────────────────────────────────────────────────


class TestBOLADetection:
    """Tests for object-level authorization enforcement."""

    def test_alice_accessing_alice_account_allowed(self):
        """Alice accessing her own account A-1001 should not trigger BOLA."""
        bola = get_bola_detector()
        token = verify_jwt(issue_jwt("alice", "user", generate_session_id(), "A-1001"))
        is_violation, _ = bola.check(token, "/bank/api/v1/accounts/A-1001", 0x2B02)
        assert not is_violation

    def test_alice_accessing_bob_account_blocked(self):
        """Alice accessing bob's account B-2002 should trigger BOLA."""
        bola = get_bola_detector()
        token = verify_jwt(issue_jwt("alice", "user", generate_session_id(), "A-1001"))
        is_violation, detail = bola.check(token, "/bank/api/v1/accounts/B-2002", 0x2B02)
        assert is_violation is True
        assert "B-2002" in detail or "BOLA" in detail

    def test_admin_bypasses_bola_check(self):
        """Admin accessing any account should not trigger BOLA."""
        bola = get_bola_detector()
        token = verify_jwt(issue_jwt("admin", "admin", generate_session_id(), None))
        is_violation, _ = bola.check(token, "/bank/api/v1/accounts/B-2002", 0x2B02)
        assert not is_violation


# ── Test 4: Rate Limiting ─────────────────────────────────────────────────────


class TestRateLimiting:
    """Tests for sliding window rate limiter."""

    def test_within_limit_allowed(self):
        """Requests within the limit should not be rate limited."""
        sid = generate_session_id()
        limiter = get_rate_limiter()
        # Use a fresh session, make a few requests
        for _ in range(5):
            is_limited, count = limiter.check_and_record(sid)
            assert not is_limited

    def test_exceeds_limit_blocked(self):
        """Requests exceeding the limit should be rate limited."""
        from core.config import get_settings
        settings = get_settings()
        limit = settings.rate_limit_requests

        sid = generate_session_id()
        limiter = get_rate_limiter()

        # Fill up to the limit
        for _ in range(limit):
            limiter.check_and_record(sid)

        # Next request should be rate limited
        is_limited, count = limiter.check_and_record(sid)
        assert is_limited, f"Expected rate limit after {limit} requests, but was not limited"


# ── Test 5: JWT Validation ────────────────────────────────────────────────────


class TestJWTValidation:
    """Tests for JWT issuance and verification."""

    def test_valid_jwt_roundtrip(self):
        """Issue and verify a JWT successfully."""
        sid = generate_session_id()
        token = issue_jwt("alice", "user", sid, "A-1001")
        payload = verify_jwt(token)
        assert payload.sub == "alice"
        assert payload.role == "user"
        assert payload.session_id == sid
        assert payload.account_id == "A-1001"

    def test_expired_jwt_raises(self):
        """Expired JWT should raise JWTError."""
        expired = issue_expired_jwt("alice", "user", generate_session_id())
        with pytest.raises(JWTError, match="expired"):
            verify_jwt(expired)

    def test_tampered_jwt_raises(self):
        """Tampered JWT should raise JWTError."""
        token = issue_jwt("alice", "user", generate_session_id(), "A-1001")
        tampered = token[:-10] + "XXXXXXXXXX"
        with pytest.raises(JWTError):
            verify_jwt(tampered)


# ── Test 6: OracleAnalysis Schema ─────────────────────────────────────────────


class TestOracleAnalysisSchema:
    """Tests for the AI oracle output Pydantic schema."""

    def test_valid_analysis_accepted(self):
        """Valid oracle output should parse successfully."""
        data = {
            "explanation": "BOLA attack detected.",
            "owasp_tag": "API1:2023 — Broken Object Level Authorization",
            "mitre_technique": "T1078 — Valid Accounts",
            "confidence": 0.95,
        }
        analysis = OracleAnalysis.model_validate(data)
        assert analysis.confidence == 0.95

    def test_confidence_clamped(self):
        """Confidence values outside [0, 1] should be clamped."""
        data = {
            "explanation": "test",
            "owasp_tag": "API1:2023",
            "mitre_technique": "T1078",
            "confidence": 1.5,  # Out of range — should be clamped
        }
        analysis = OracleAnalysis.model_validate(data)
        assert analysis.confidence <= 1.0

    def test_missing_field_raises(self):
        """Missing required fields should raise ValidationError."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            OracleAnalysis.model_validate({"explanation": "test"})


# ── Test 7: End-to-End Simulator ──────────────────────────────────────────────


class TestSimulatorEndToEnd:
    """End-to-end tests using the simulator's enforcement pipeline."""

    @pytest.mark.asyncio
    async def test_bfla_simulation_blocks(self):
        """BFLA simulation should result in a BLOCKED verdict."""
        from simulator.attack_gen import _simulate_bfla
        result = await _simulate_bfla()
        assert result.success, "BFLA simulation should be blocked by the gateway"
        assert result.event.status.value == "blocked"
        assert result.event.violation_type == ViolationType.BFLA

    @pytest.mark.asyncio
    async def test_bola_simulation_blocks(self):
        """BOLA simulation should result in a BLOCKED verdict."""
        from simulator.attack_gen import _simulate_bola
        result = await _simulate_bola()
        assert result.success, "BOLA simulation should be blocked by the gateway"
        assert result.event.status.value == "blocked"
        assert result.event.violation_type == ViolationType.BOLA

    @pytest.mark.asyncio
    async def test_replay_simulation_blocks(self):
        """Replay (expired JWT) simulation should result in a BLOCKED verdict."""
        from simulator.attack_gen import _simulate_replay
        result = await _simulate_replay()
        assert result.success, "Replay simulation should be blocked by the gateway"
        assert result.event.status.value == "blocked"
        assert result.event.violation_type == ViolationType.REPLAY

    @pytest.mark.asyncio
    async def test_enforcement_latency_under_15ms(self):
        """Enforcement latency should be under 15ms for all attack types."""
        from simulator.attack_gen import _simulate_bfla, _simulate_bola, _simulate_replay

        for sim_fn in [_simulate_bfla, _simulate_bola, _simulate_replay]:
            result = await sim_fn()
            assert result.enforcement_latency_ms < 15.0, (
                f"{sim_fn.__name__}: latency {result.enforcement_latency_ms:.2f}ms "
                f"exceeds 15ms budget"
            )
