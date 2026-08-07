"""
Q-SAFE BOLA (Broken Object Level Authorization) Detector
==========================================================
Detects when a user accesses objects they do not own.

OWASP API1:2023 — Broken Object Level Authorization
MITRE ATT&CK   — T1078 (Valid Accounts)

Design: Pure synchronous function call — no I/O, no network, O(1).
Called in the hot enforcement path after BFLA check.
"""

from __future__ import annotations

from typing import Dict, Optional

from core.models import OwnershipRule, TokenPayload
from gateway.policy import ENDPOINT_REGISTRY, extract_path_params, _path_matches


class BOLADetector:
    """
    Object-level ownership enforcement.

    For endpoints marked with an OwnershipRule, validates that the requesting
    session actually owns the object being accessed. The gateway's mock banking
    API does NOT perform these checks internally — this is the sole enforcement point.
    """

    def check(
        self,
        token: TokenPayload,
        request_path: str,
        endpoint_id: int,
    ) -> tuple[bool, Optional[str]]:
        """
        Check for a BOLA violation.

        Args:
            token:        Decoded JWT payload for the requesting user.
            request_path: Actual request URL path (with concrete param values).
            endpoint_id:  Resolved stable endpoint ID.

        Returns:
            Tuple of (is_violation: bool, detail: str | None).
            is_violation is True when an ownership violation is detected.
        """
        # Find the endpoint definition for this ID
        ep_def = None
        for ep in ENDPOINT_REGISTRY:
            if ep.endpoint_id == endpoint_id:
                ep_def = ep
                break

        if ep_def is None:
            # Unknown endpoint — BFLA check handles this upstream
            return False, None

        if ep_def.ownership_rule == OwnershipRule.NONE:
            # No ownership enforcement required
            return False, None

        if ep_def.ownership_rule == OwnershipRule.ACCOUNT_OWNER:
            return self._check_account_ownership(token, request_path, ep_def.path_pattern)

        if ep_def.ownership_rule == OwnershipRule.USER_SELF:
            return self._check_user_self(token, request_path, ep_def.path_pattern)

        return False, None

    def _check_account_ownership(
        self,
        token: TokenPayload,
        request_path: str,
        pattern: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify that the account_id in the path belongs to the token's owner.

        Admins bypass this check (they can access any account).

        Args:
            token:        JWT payload.
            request_path: Actual URL path.
            pattern:      Endpoint path pattern.

        Returns:
            (True, detail) if BOLA violation; (False, None) if authorized.
        """
        if token.role == "admin":
            # Admins have cross-account access — not a BOLA violation
            return False, None

        params = extract_path_params(request_path, pattern)
        requested_account = params.get("account_id")

        if requested_account is None:
            # No account_id in path — nothing to check
            return False, None

        # The user's owned account is embedded in the JWT
        owned_account = token.account_id

        if owned_account is None:
            return (
                True,
                f"User '{token.sub}' has no registered account but requested access to '{requested_account}'",
            )

        if requested_account != owned_account:
            return (
                True,
                (
                    f"BOLA: User '{token.sub}' owns account '{owned_account}' "
                    f"but requested access to '{requested_account}'"
                ),
            )

        return False, None

    def _check_user_self(
        self,
        token: TokenPayload,
        request_path: str,
        pattern: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify that the user_id in the path matches the requesting user.

        Args:
            token:        JWT payload.
            request_path: Actual URL path.
            pattern:      Endpoint path pattern.

        Returns:
            (True, detail) if BOLA violation; (False, None) if authorized.
        """
        if token.role == "admin":
            return False, None

        params = extract_path_params(request_path, pattern)
        requested_user = params.get("user_id")

        if requested_user is None:
            return False, None

        if requested_user != token.sub:
            return (
                True,
                f"BOLA: User '{token.sub}' attempted to access data for user '{requested_user}'",
            )

        return False, None


# ── Module-Level Singleton ────────────────────────────────────────────────────

_bola_detector: Optional[BOLADetector] = None


def get_bola_detector() -> BOLADetector:
    """Return the process-wide BOLADetector singleton."""
    global _bola_detector
    if _bola_detector is None:
        _bola_detector = BOLADetector()
    return _bola_detector
