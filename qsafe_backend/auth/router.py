"""
Q-SAFE Auth Router
===================
Demo credential endpoint — issues JWTs for the three seed users.

POST /auth/token  body: {username, password}  → {access_token, ...}

This is the ONLY legitimate entry point for obtaining tokens.
All gateway enforcement relies on tokens issued here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from core.config import get_settings
from core.crypto import generate_session_id, issue_jwt
from core.models import TokenRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/token", response_model=TokenResponse)
async def issue_token(body: TokenRequest) -> TokenResponse:
    """
    Issue a JWT for a demo user.

    Validates credentials against the demo user list.
    Returns a signed JWT + session metadata.

    Args:
        body: TokenRequest with username and password.

    Returns:
        TokenResponse with access_token and metadata.

    Raises:
        401 if credentials are invalid.
    """
    settings = get_settings()
    credentials = settings.demo_credentials

    user_info = credentials.get(body.username)
    if user_info is None or user_info["password"] != body.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_id = generate_session_id()
    token = issue_jwt(
        sub=body.username,
        role=user_info["role"],
        session_id=session_id,
        account_id=user_info.get("account_id"),
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60,
        session_id=session_id,
        username=body.username,
        role=user_info["role"],
    )


@router.get("/sessions/{session_id}/status")
async def session_status(session_id: str) -> dict:
    """
    Check if a session is active or quarantined.

    Args:
        session_id: Session identifier.

    Returns:
        Dict with session status.
    """
    from telemetry.store import get_telemetry_store
    store = get_telemetry_store()
    quarantined = store.is_quarantined(session_id)
    return {
        "session_id": session_id,
        "status": "quarantined" if quarantined else "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
