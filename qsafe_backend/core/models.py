"""
Q-SAFE Core Data Models
=======================
All Pydantic v2 models for the Q-SAFE system.
These models define the API contracts between all layers.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Enumerations ─────────────────────────────────────────────────────────────


class ViolationType(str, Enum):
    """Classification of detected security violations."""

    BOLA = "BOLA"
    BFLA = "BFLA"
    RATE = "RATE"
    REPLAY = "REPLAY"
    SEQUENCE = "SEQUENCE"
    NONE = "NONE"


class EventStatus(str, Enum):
    """Enforcement verdict for a gateway event."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


class AttackType(str, Enum):
    """Supported attack simulation types."""

    BOLA = "bola"
    BFLA = "bfla"
    RATE_ABUSE = "rate_abuse"
    REPLAY = "replay"


# ── JWT / Auth Models ─────────────────────────────────────────────────────────


class TokenPayload(BaseModel):
    """Decoded JWT claims for a Q-SAFE session token."""

    sub: str = Field(description="Subject — the authenticated username")
    role: str = Field(description="User role: 'user' or 'admin'")
    session_id: str = Field(description="Unique session identifier (UUID4)")
    account_id: Optional[str] = Field(default=None, description="Owned bank account ID (if user role)")
    exp: int = Field(description="Token expiration unix timestamp")
    iat: int = Field(description="Token issued-at unix timestamp")


class TokenRequest(BaseModel):
    """Credentials for demo token issuance endpoint."""

    username: str = Field(description="Demo username: alice | bob | admin")
    password: str = Field(description="Demo password")


class TokenResponse(BaseModel):
    """Issued JWT token and metadata."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    session_id: str
    username: str
    role: str


# ── Policy Engine Models ──────────────────────────────────────────────────────


class OwnershipRule(str, Enum):
    """Ownership validation rules for object-level authorization."""

    NONE = "none"
    ACCOUNT_OWNER = "account_owner"
    USER_SELF = "user_self"


class EndpointDef(BaseModel):
    """Definition of a registered protected endpoint."""

    path_pattern: str = Field(description="URL path pattern (e.g., '/accounts/{account_id}')")
    endpoint_id: int = Field(description="Stable 64-bit integer ID for CCFH hashing")
    allowed_roles: List[str] = Field(description="Roles permitted to access this endpoint")
    ownership_rule: OwnershipRule = Field(
        default=OwnershipRule.NONE,
        description="Object-level ownership rule",
    )
    description: str = Field(default="", description="Human-readable endpoint description")
    method: str = Field(default="*", description="HTTP method or '*' for any")


class PolicyArtifact(BaseModel):
    """HMAC-signed policy artifact produced at startup."""

    version: str = Field(description="Policy artifact version timestamp")
    endpoints: List[Dict[str, Any]] = Field(description="Serialized endpoint registry")
    allowlists: Dict[str, List[int]] = Field(
        description="Role → list of valid context hashes"
    )
    hmac_signature: str = Field(description="HMAC-SHA256 hex digest for tamper detection")


# ── Telemetry / Event Models ──────────────────────────────────────────────────


class OracleAnalysis(BaseModel):
    """
    Structured threat analysis from the AI Oracle agent.
    Validated against this strict schema; malformed LLM output is discarded.
    """

    explanation: str = Field(description="Human-readable threat explanation")
    owasp_tag: str = Field(description="OWASP API Top 10 reference (e.g., 'API1:2023')")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID (e.g., 'T1078')")
    confidence: float = Field(ge=0.0, le=1.0, description="Oracle confidence score 0–1")

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: Any) -> Any:
        """Clamp confidence to [0.0, 1.0]."""
        if isinstance(v, (int, float)):
            return max(0.0, min(1.0, float(v)))
        return v


class SequenceStep(BaseModel):
    """One step in a session's CCFH sequence trace."""

    step: int = Field(description="Step index (0-based)")
    endpoint: str = Field(description="Endpoint path pattern")
    endpoint_id: int = Field(description="Stable endpoint ID")
    hash_after: str = Field(description="Rolling context hash after this step (hex, e.g. '0x8F9A2B1C')")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EventRecord(BaseModel):
    """
    Core telemetry event record — produced for every gateway request.
    This is the primary data model shared across enforcement, agents,
    telemetry API, and WebSocket push. Matches the frontend contract exactly.
    """

    # Identification
    event_id: str = Field(description="Unique event ID (UUID4 hex)")
    request_id: str = Field(description="Request-scoped correlation ID")
    timestamp: str = Field(description="ISO 8601 timestamp")

    # Request context
    endpoint: str = Field(description="Requested endpoint path")
    method: str = Field(description="HTTP method")
    user: str = Field(description="Authenticated username")
    role: str = Field(description="User role")
    session_id: str = Field(description="Session identifier")

    # CCFH hash state
    context_hash: str = Field(description="Context hash after update (hex, e.g. '0x8F9A2B1C')")
    expected_hash: Optional[str] = Field(default=None, description="Expected hash for this sequence position")

    # Enforcement verdict
    status: EventStatus = Field(description="'allowed' or 'blocked'")
    violation_type: Optional[ViolationType] = Field(default=None, description="Violation classification if blocked")

    # Performance
    enforcement_latency_ms: float = Field(description="Hot-path enforcement latency in milliseconds")

    # AI Oracle enrichment (populated asynchronously, off the hot path)
    ai_explanation: Optional[str] = Field(default=None)
    owasp_tag: Optional[str] = Field(default=None)
    mitre_technique: Optional[str] = Field(default=None)
    oracle_confidence: Optional[float] = Field(default=None)

    # Session risk
    risk_score: Optional[float] = Field(default=None, description="Session risk score 0–100 at time of event")

    # Additional metadata
    ip_address: Optional[str] = Field(default=None)
    user_agent: Optional[str] = Field(default=None)
    jwt_snippet: Optional[str] = Field(default=None, description="First 60 chars of raw JWT for display")


class MetricsResponse(BaseModel):
    """
    Executive dashboard metrics — matches frontend /telemetry/metrics contract exactly.
    """

    total_requests: int = Field(description="Total requests processed since startup")
    blocked_total: int = Field(description="Total blocked requests")
    blocked_bola: int = Field(description="Requests blocked due to BOLA")
    blocked_bfla: int = Field(description="Requests blocked due to BFLA")
    blocked_rate: int = Field(description="Requests blocked due to rate abuse")
    blocked_sequence: int = Field(description="Requests blocked due to sequence violation")
    active_sessions: int = Field(description="Number of currently active sessions")
    mean_enforcement_latency_ms: float = Field(description="Mean hot-path latency in ms")
    p99_enforcement_latency_ms: float = Field(description="p99 hot-path latency in ms")


class RiskScoreRecord(BaseModel):
    """Per-session risk score record from the behavioral profiler."""

    session_id: str
    username: str
    role: str
    risk_score: float = Field(ge=0.0, le=100.0)
    last_updated: str
    flagged_behaviors: List[str] = Field(default_factory=list)


# ── Simulator Models ──────────────────────────────────────────────────────────


class AttackRequest(BaseModel):
    """Request body for POST /simulator/attack."""

    type: AttackType = Field(description="Attack type to simulate")
    target_user: Optional[str] = Field(
        default=None,
        description="Optional override for target username (default: alice for BOLA/BFLA)",
    )


class AttackResponse(BaseModel):
    """Full attack simulation result including enforcement verdict and latency."""

    attack_type: str
    description: str
    event: EventRecord
    enforcement_verdict: str
    enforcement_latency_ms: float
    success: bool = Field(description="True if the gateway correctly BLOCKED the attack")


# ── Internal Enforcement Models ───────────────────────────────────────────────


class EnforcementVerdict(BaseModel):
    """
    Internal result of the hot-path enforcement pipeline.
    NOT exposed via API — used for internal routing only.
    """

    allowed: bool
    violation_type: Optional[ViolationType] = None
    violation_detail: Optional[str] = None
    context_hash: int = 0
    endpoint_id: Optional[int] = None
    latency_ms: float = 0.0
    session_id: str = ""


# ── AI Analyze-Threat (frontend compat) ───────────────────────────────────────


class AnalyzeThreatRequest(BaseModel):
    """Request body for POST /api/analyze-threat (frontend compatibility)."""

    requestLog: Dict[str, Any] = Field(description="Frontend ApiRequestLog object")


class AnalyzeThreatResponse(BaseModel):
    """Response for POST /api/analyze-threat."""

    success: bool
    analysis: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ── Quarantine ────────────────────────────────────────────────────────────────


class QuarantineResponse(BaseModel):
    """Response for POST /sessions/{session_id}/quarantine."""

    session_id: str
    quarantined: bool
    message: str
    timestamp: str
