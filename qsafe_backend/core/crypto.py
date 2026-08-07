"""
Q-SAFE Cryptography Utilities
==============================
JWT issuance/verification and HMAC policy signing.
Uses PyJWT for JWT operations and hmac/hashlib for policy artifact integrity.

Security boundary: This module handles ALL cryptographic operations.
No other module should directly import jwt or hmac primitives.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from core.config import get_settings
from core.models import TokenPayload


class JWTError(Exception):
    """Raised when JWT validation fails."""


class PolicySignatureError(Exception):
    """Raised when policy artifact HMAC verification fails."""


def issue_jwt(
    sub: str,
    role: str,
    session_id: str,
    account_id: str | None = None,
) -> str:
    """
    Issue a signed HS256 JWT for a Q-SAFE session.

    Args:
        sub:        Subject (authenticated username).
        role:       User role ('user' | 'admin').
        session_id: Unique session UUID4.
        account_id: Owned bank account ID for user-role tokens.

    Returns:
        Signed JWT string.
    """
    settings = get_settings()
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": sub,
        "role": role,
        "session_id": session_id,
        "account_id": account_id,
        "iat": now,
        "exp": now + (settings.jwt_expire_minutes * 60),
    }
    token: str = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token


def verify_jwt(token: str) -> TokenPayload:
    """
    Verify a JWT and return its decoded claims as a typed model.

    Validates: signature, expiry, required claims (sub, role, session_id).

    Args:
        token: Raw JWT string from Authorization header.

    Returns:
        Decoded and validated TokenPayload.

    Raises:
        JWTError: If signature is invalid, token is expired, or claims are missing.
    """
    settings = get_settings()
    try:
        raw: Dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except ExpiredSignatureError as exc:
        raise JWTError("Token has expired") from exc
    except InvalidTokenError as exc:
        raise JWTError(f"Invalid token: {exc}") from exc

    # Validate required claims
    for claim in ("sub", "role", "session_id", "exp", "iat"):
        if claim not in raw:
            raise JWTError(f"Missing required claim: {claim}")

    return TokenPayload(
        sub=raw["sub"],
        role=raw["role"],
        session_id=raw["session_id"],
        account_id=raw.get("account_id"),
        exp=raw["exp"],
        iat=raw["iat"],
    )


def issue_expired_jwt(sub: str, role: str, session_id: str) -> str:
    """
    Issue a JWT that is already expired (for replay-attack simulation).

    Args:
        sub:        Subject username.
        role:       User role.
        session_id: Session UUID.

    Returns:
        Signed JWT string with exp set in the past.
    """
    settings = get_settings()
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": sub,
        "role": role,
        "session_id": session_id,
        "account_id": None,
        "iat": now - 7200,
        "exp": now - 3600,  # expired 1 hour ago
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def sign_policy(data: Dict[str, Any]) -> str:
    """
    Compute HMAC-SHA256 signature over a policy artifact dict.

    The data dict is serialized to canonical JSON (sorted keys, no whitespace)
    before signing to ensure determinism.

    Args:
        data: Policy artifact fields (excluding the signature field itself).

    Returns:
        Lowercase hex HMAC-SHA256 digest.
    """
    settings = get_settings()
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    digest = hmac.new(
        settings.secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def verify_policy_signature(data: Dict[str, Any], expected_sig: str) -> bool:
    """
    Verify the HMAC-SHA256 signature of a policy artifact.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        data:         Policy artifact fields (excluding signature).
        expected_sig: Previously computed HMAC hex digest.

    Returns:
        True if the signature is valid; False otherwise.
    """
    actual_sig = sign_policy(data)
    return hmac.compare_digest(actual_sig, expected_sig)


def generate_session_id() -> str:
    """
    Generate a cryptographically random session ID.

    Returns:
        UUID4 hex string (32 chars, no hyphens).
    """
    return uuid.uuid4().hex
