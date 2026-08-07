"""
Q-SAFE BFLA (Broken Function Level Authorization) Detector
===========================================================
Detects role escalation — users calling endpoints above their privilege tier.

OWASP API5:2023 — Broken Function Level Authorization
MITRE ATT&CK   — T1134 (Access Token Manipulation / Privilege Escalation)

Design: Pure O(1) lookup — checks role against endpoint's allowed_roles list.
Called in the hot enforcement path before BOLA check.
"""

from __future__ import annotations

from typing import Optional

from gateway.policy import get_policy_engine


class BFLADetector:
    """
    Function-level authorization enforcement.

    Verifies that the requesting user's role is permitted to invoke the
    target endpoint at all — regardless of object ownership.

    Example violation: alice (role=user) calling DELETE /admin/users/bob
    """

    def check(self, role: str, endpoint_id: int) -> tuple[bool, Optional[str]]:
        """
        Check for a BFLA violation.

        Args:
            role:        User role from JWT ('user' | 'admin').
            endpoint_id: Resolved stable endpoint ID.

        Returns:
            Tuple of (is_violation: bool, detail: str | None).
            is_violation is True when a function-level violation is detected.
        """
        policy = get_policy_engine()

        if not policy.initialized:
            # Policy engine not ready — fail-safe: block
            return True, "Policy engine not initialized — request denied"

        ep_def = policy.get_endpoint_def(endpoint_id)
        if ep_def is None:
            # Unregistered endpoint — deny by default (zero-trust: no implicit allow)
            return True, f"Endpoint ID {endpoint_id:#x} is not in the policy registry"

        if role not in ep_def.allowed_roles:
            return (
                True,
                (
                    f"BFLA: Role '{role}' is not authorized for endpoint "
                    f"'{ep_def.path_pattern}' (allowed: {ep_def.allowed_roles})"
                ),
            )

        return False, None


# ── Module-Level Singleton ────────────────────────────────────────────────────

_bfla_detector: Optional[BFLADetector] = None


def get_bfla_detector() -> BFLADetector:
    """Return the process-wide BFLADetector singleton."""
    global _bfla_detector
    if _bfla_detector is None:
        _bfla_detector = BFLADetector()
    return _bfla_detector
