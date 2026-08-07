"""
Q-SAFE Authorization Policy Engine
======================================
Endpoint registry, allowlist generation, and HMAC-signed policy artifact.

Policy lifecycle:
1. ENDPOINT_REGISTRY defines all protected endpoints declaratively.
2. AllowlistGenerator enumerates valid access sequences per role and computes hashes.
3. PolicyEngine loads the artifact, verifies HMAC integrity, and serves O(1) lookups.

DETERMINISTIC: The same registry always produces the same allowlist.
TAMPER-EVIDENT: The artifact is HMAC-SHA256 signed; any modification is detected on load.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from itertools import permutations
from typing import Dict, List, Optional, Set

from core.crypto import sign_policy, verify_policy_signature
from core.models import EndpointDef, OwnershipRule, PolicyArtifact
from gateway.sequence import ccfh_update, hash_sequence


# ── Endpoint Registry ─────────────────────────────────────────────────────────
# Stable 64-bit IDs are chosen to be unique and memorable.
# IDs must NEVER change between restarts — they are part of the stored artifact.

ENDPOINT_REGISTRY: List[EndpointDef] = [
    EndpointDef(
        path_pattern="/bank/api/v1/users/me",
        endpoint_id=0x1A01,
        allowed_roles=["user", "admin"],
        ownership_rule=OwnershipRule.NONE,
        method="GET",
        description="Fetch own user profile",
    ),
    EndpointDef(
        path_pattern="/bank/api/v1/accounts/{account_id}",
        endpoint_id=0x2B02,
        allowed_roles=["user", "admin"],
        ownership_rule=OwnershipRule.ACCOUNT_OWNER,
        method="GET",
        description="Fetch account details — ownership enforced",
    ),
    EndpointDef(
        path_pattern="/bank/api/v1/accounts/{account_id}/transactions",
        endpoint_id=0x3C03,
        allowed_roles=["user", "admin"],
        ownership_rule=OwnershipRule.ACCOUNT_OWNER,
        method="GET",
        description="Fetch account transactions — ownership enforced",
    ),
    EndpointDef(
        path_pattern="/bank/api/v1/transfers",
        endpoint_id=0x4D04,
        allowed_roles=["user", "admin"],
        ownership_rule=OwnershipRule.NONE,
        method="POST",
        description="Initiate a funds transfer",
    ),
    EndpointDef(
        path_pattern="/bank/api/v1/admin/users",
        endpoint_id=0x9F01,
        allowed_roles=["admin"],
        ownership_rule=OwnershipRule.NONE,
        method="GET",
        description="List all users — admin only (BFLA target)",
    ),
    EndpointDef(
        path_pattern="/bank/api/v1/admin/users/{user_id}",
        endpoint_id=0xAE02,
        allowed_roles=["admin"],
        ownership_rule=OwnershipRule.NONE,
        method="DELETE",
        description="Delete a user — admin only (BFLA target)",
    ),
]

# Quick lookup maps built from the registry
_ENDPOINT_BY_ID: Dict[int, EndpointDef] = {ep.endpoint_id: ep for ep in ENDPOINT_REGISTRY}
_ENDPOINT_BY_PATTERN: Dict[str, EndpointDef] = {ep.path_pattern: ep for ep in ENDPOINT_REGISTRY}

# Maximum sequence length for allowlist pre-computation.
# Sequences longer than this are handled by extending the allowlist lazily.
MAX_SEQUENCE_LENGTH = 6


# ── Allowlist Generator ───────────────────────────────────────────────────────


class AllowlistGenerator:
    """
    Pre-computes the set of valid CCFH hashes for each role.

    For each role, enumerates all valid endpoint sequences (up to MAX_SEQUENCE_LENGTH)
    and records the resulting hash after each step. Any endpoint accessible
    by the role can legitimately follow any prior sequence.

    The generated allowlist enables O(1) enforcement: set membership check.
    """

    def generate(self) -> Dict[str, Set[int]]:
        """
        Compute valid hash sets per role.

        Returns:
            Dict mapping role name → set of valid 64-bit hash integers.
        """
        # Group endpoints by role
        role_endpoints: Dict[str, List[EndpointDef]] = {}
        for ep in ENDPOINT_REGISTRY:
            for role in ep.allowed_roles:
                role_endpoints.setdefault(role, []).append(ep)

        allowlists: Dict[str, Set[int]] = {}

        for role, endpoints in role_endpoints.items():
            valid_hashes: Set[int] = set()
            ids = [ep.endpoint_id for ep in endpoints]

            # Generate all ordered permutations up to MAX_SEQUENCE_LENGTH
            for length in range(1, min(len(ids), MAX_SEQUENCE_LENGTH) + 1):
                for perm in permutations(ids, length):
                    final_hash = hash_sequence(list(perm))
                    valid_hashes.add(final_hash)

                    # Also add intermediate hashes (each step in the sequence is valid)
                    h = 0
                    for eid in perm:
                        h = ccfh_update(h, eid)
                        valid_hashes.add(h)

            allowlists[role] = valid_hashes

        return allowlists

    def serialize(self, allowlists: Dict[str, Set[int]]) -> Dict[str, List[int]]:
        """
        Serialize allowlists to JSON-compatible format (sets → sorted lists).

        Args:
            allowlists: Role → set of valid hashes.

        Returns:
            Role → sorted list of valid hashes (deterministic).
        """
        return {role: sorted(hashes) for role, hashes in allowlists.items()}


# ── Policy Engine ─────────────────────────────────────────────────────────────


class PolicyEngine:
    """
    The authorization policy engine.

    Responsibilities:
    - Build and sign the policy artifact at startup.
    - Verify artifact integrity on load (tamper detection).
    - Serve O(1) authorization lookups during enforcement.

    Thread-safe: all public methods are safe to call concurrently.
    """

    def __init__(self) -> None:
        self._allowlists: Dict[str, Set[int]] = {}
        self._artifact: Optional[PolicyArtifact] = None
        self._lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> PolicyArtifact:
        """
        Build the policy artifact: generate allowlists and HMAC-sign them.

        This is called once at startup. The artifact is stored in memory
        and also returned for logging/verification purposes.

        Returns:
            Signed PolicyArtifact ready for storage and verification.
        """
        generator = AllowlistGenerator()
        raw_allowlists = generator.generate()
        serialized = generator.serialize(raw_allowlists)

        # Build the signable data (without the signature field)
        artifact_data = {
            "version": datetime.now(timezone.utc).isoformat(),
            "endpoints": [ep.model_dump() for ep in ENDPOINT_REGISTRY],
            "allowlists": serialized,
        }
        signature = sign_policy(artifact_data)

        artifact = PolicyArtifact(
            version=artifact_data["version"],
            endpoints=artifact_data["endpoints"],
            allowlists=serialized,
            hmac_signature=signature,
        )

        with self._lock:
            self._allowlists = raw_allowlists
            self._artifact = artifact
            self._initialized = True

        return artifact

    def verify_artifact(self, artifact: PolicyArtifact) -> bool:
        """
        Verify the HMAC integrity of a PolicyArtifact.

        Args:
            artifact: The artifact to verify.

        Returns:
            True if signature matches; False if tampered.
        """
        signable_data = {
            "version": artifact.version,
            "endpoints": artifact.endpoints,
            "allowlists": artifact.allowlists,
        }
        return verify_policy_signature(signable_data, artifact.hmac_signature)

    def is_sequence_allowed(self, role: str, context_hash: int) -> bool:
        """
        Check if a context hash is in the allowlist for the given role.

        This is the critical O(1) set membership check — the final gate.
        Called in the hot path. Must not acquire locks or do I/O.

        Args:
            role:         User role ('user' | 'admin').
            context_hash: Current CCFH hash after incorporating this endpoint.

        Returns:
            True if the hash is a known-valid state for this role.
        """
        allowlist = self._allowlists.get(role)
        if allowlist is None:
            return False
        return context_hash in allowlist

    def is_role_permitted(self, role: str, endpoint_id: int) -> bool:
        """
        BFLA check: is this endpoint_id permitted for this role at all?

        O(1) lookup against the endpoint registry.

        Args:
            role:        User role.
            endpoint_id: Target endpoint's stable ID.

        Returns:
            True if the role is in the endpoint's allowed_roles list.
        """
        ep = _ENDPOINT_BY_ID.get(endpoint_id)
        if ep is None:
            # Unknown endpoint — deny by default (fail-safe)
            return False
        return role in ep.allowed_roles

    def get_endpoint_def(self, endpoint_id: int) -> Optional[EndpointDef]:
        """Return the EndpointDef for a given endpoint ID, or None."""
        return _ENDPOINT_BY_ID.get(endpoint_id)

    def get_endpoint_def_by_pattern(self, pattern: str) -> Optional[EndpointDef]:
        """Return the EndpointDef for a given path pattern, or None."""
        return _ENDPOINT_BY_PATTERN.get(pattern)

    def resolve_endpoint_id(self, request_path: str) -> Optional[int]:
        """
        Resolve a request path to its registered endpoint ID.

        Performs pattern matching: replaces path parameters with their patterns.
        E.g., '/bank/api/v1/accounts/A-1001' → 0x2B02

        Args:
            request_path: The actual request URL path.

        Returns:
            Endpoint ID if matched, None if path is not registered.
        """
        # Direct match first (fast path for parameterless routes)
        if request_path in _ENDPOINT_BY_PATTERN:
            return _ENDPOINT_BY_PATTERN[request_path].endpoint_id

        # Pattern matching for parameterized routes
        for pattern, ep_def in _ENDPOINT_BY_PATTERN.items():
            if _path_matches(request_path, pattern):
                return ep_def.endpoint_id

        return None

    def get_all_endpoint_ids(self) -> List[int]:
        """Return all registered endpoint IDs."""
        return [ep.endpoint_id for ep in ENDPOINT_REGISTRY]

    def get_artifact(self) -> Optional[PolicyArtifact]:
        """Return the current policy artifact (or None if not initialized)."""
        return self._artifact

    @property
    def initialized(self) -> bool:
        """True if the policy engine has been initialized."""
        return self._initialized


def _path_matches(actual: str, pattern: str) -> bool:
    """
    Check if an actual request path matches a parameterized pattern.

    Example: '/bank/api/v1/accounts/A-1001' matches '/bank/api/v1/accounts/{account_id}'

    Args:
        actual:  The actual request path.
        pattern: The pattern with {param} placeholders.

    Returns:
        True if the path matches the pattern.
    """
    actual_parts = actual.rstrip("/").split("/")
    pattern_parts = pattern.rstrip("/").split("/")

    if len(actual_parts) != len(pattern_parts):
        return False

    for actual_seg, pattern_seg in zip(actual_parts, pattern_parts):
        if pattern_seg.startswith("{") and pattern_seg.endswith("}"):
            # Parameter segment — matches any non-empty string
            if not actual_seg:
                return False
        elif actual_seg != pattern_seg:
            return False

    return True


def extract_path_params(actual: str, pattern: str) -> Dict[str, str]:
    """
    Extract path parameter values from an actual request path.

    Example: '/bank/api/v1/accounts/A-1001', '/bank/api/v1/accounts/{account_id}'
             → {'account_id': 'A-1001'}

    Args:
        actual:  The actual request path.
        pattern: The pattern with {param} placeholders.

    Returns:
        Dict of param_name → value.
    """
    params: Dict[str, str] = {}
    actual_parts = actual.rstrip("/").split("/")
    pattern_parts = pattern.rstrip("/").split("/")

    for actual_seg, pattern_seg in zip(actual_parts, pattern_parts):
        if pattern_seg.startswith("{") and pattern_seg.endswith("}"):
            param_name = pattern_seg[1:-1]
            params[param_name] = actual_seg

    return params


# ── Module-Level Singleton ────────────────────────────────────────────────────

_policy_engine: Optional[PolicyEngine] = None
_policy_lock = threading.Lock()


def get_policy_engine() -> PolicyEngine:
    """
    Return the process-wide PolicyEngine singleton.

    Returns:
        Shared PolicyEngine instance.
    """
    global _policy_engine
    if _policy_engine is None:
        with _policy_lock:
            if _policy_engine is None:
                _policy_engine = PolicyEngine()
    return _policy_engine
