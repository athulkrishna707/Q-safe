"""
Q-SAFE Mock Protected Banking API
=====================================
Intentionally naive banking API — missing all authorization checks.
The gateway is the ONLY thing preventing abuse.

DO NOT ADD AUTH CHECKS HERE — that defeats the demo purpose.
This API trusts the gateway completely. If a request reaches these
handlers, it passed all enforcement checks.

Endpoints:
  GET  /bank/api/v1/users/me
  GET  /bank/api/v1/accounts/{account_id}
  GET  /bank/api/v1/accounts/{account_id}/transactions
  POST /bank/api/v1/transfers
  GET  /bank/api/v1/admin/users
  DELETE /bank/api/v1/admin/users/{user_id}
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Request

router = APIRouter(prefix="/bank/api/v1", tags=["Banking API (Protected)"])

# ── Seed Data ─────────────────────────────────────────────────────────────────

SEED_USERS: Dict[str, Dict[str, Any]] = {
    "alice": {
        "user_id": "usr_alice_001",
        "username": "alice",
        "email": "alice@example-bank.com",
        "full_name": "Alice Thornton",
        "role": "user",
        "account_id": "A-1001",
        "kyc_verified": True,
        "created_at": "2024-01-15T10:30:00Z",
    },
    "bob": {
        "user_id": "usr_bob_002",
        "username": "bob",
        "email": "bob@example-bank.com",
        "full_name": "Bob Maverick",
        "role": "user",
        "account_id": "B-2002",
        "kyc_verified": True,
        "created_at": "2024-02-20T14:45:00Z",
    },
    "admin": {
        "user_id": "usr_admin_000",
        "username": "admin",
        "email": "admin@example-bank.com",
        "full_name": "System Administrator",
        "role": "admin",
        "account_id": None,
        "kyc_verified": True,
        "created_at": "2023-12-01T00:00:00Z",
    },
}

SEED_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "A-1001": {
        "account_id": "A-1001",
        "owner": "alice",
        "account_type": "CHECKING",
        "balance": 14_823.47,
        "currency": "USD",
        "iban": "US12 3456 7890 0001 0010 01",
        "status": "ACTIVE",
        "created_at": "2024-01-15T10:35:00Z",
    },
    "B-2002": {
        "account_id": "B-2002",
        "owner": "bob",
        "account_type": "SAVINGS",
        "balance": 52_119.88,
        "currency": "USD",
        "iban": "US98 7654 3210 0002 0020 02",
        "status": "ACTIVE",
        "created_at": "2024-02-20T14:50:00Z",
    },
}


def _generate_transactions(account_id: str, count: int = 10) -> List[Dict[str, Any]]:
    """Generate realistic-looking transaction history for an account."""
    descriptions = [
        "Coffee Shop", "Grocery Store", "Netflix", "Uber", "Amazon",
        "Electric Bill", "Rent Payment", "Gas Station", "Restaurant", "Gym Membership",
    ]
    transactions = []
    base_time = datetime.now(timezone.utc)
    for i in range(count):
        tx_time = base_time - timedelta(days=i * 3, hours=random.randint(0, 23))
        amount = round(random.uniform(-250.0, 500.0), 2)
        transactions.append({
            "tx_id": f"TX-{uuid.uuid4().hex[:8].upper()}",
            "account_id": account_id,
            "amount": amount,
            "type": "CREDIT" if amount > 0 else "DEBIT",
            "description": random.choice(descriptions),
            "timestamp": tx_time.isoformat(),
            "balance_after": round(random.uniform(1000.0, 60000.0), 2),
            "status": "SETTLED",
        })
    return sorted(transactions, key=lambda x: x["timestamp"], reverse=True)


# ── Endpoint Handlers ─────────────────────────────────────────────────────────


@router.get("/users/me")
async def get_my_profile(request: Request) -> Dict[str, Any]:
    """
    Return the authenticated user's profile.

    NOTE: No auth check here — the gateway validates the JWT.
    The token payload is available on request.state.token_payload.
    """
    token = getattr(request.state, "token_payload", None)
    username = token.sub if token else "unknown"
    user = SEED_USERS.get(username, {
        "user_id": f"usr_{username}",
        "username": username,
        "email": f"{username}@example-bank.com",
        "full_name": username.capitalize(),
        "role": token.role if token else "user",
        "account_id": token.account_id if token else None,
    })
    return {"status": "ok", "data": user}


@router.get("/accounts/{account_id}")
async def get_account(account_id: str, request: Request) -> Dict[str, Any]:
    """
    Return account details for the given account_id.

    INTENTIONALLY missing ownership check — Q-SAFE is the enforcement point.
    """
    account = SEED_ACCOUNTS.get(account_id)
    if not account:
        return {"status": "ok", "data": {
            "account_id": account_id,
            "balance": 0.0,
            "status": "NOT_FOUND",
            "message": "Account not found in demo seed data",
        }}
    return {"status": "ok", "data": account}


@router.get("/accounts/{account_id}/transactions")
async def get_transactions(account_id: str, request: Request) -> Dict[str, Any]:
    """
    Return transaction history for the given account_id.

    INTENTIONALLY missing ownership check — Q-SAFE is the enforcement point.
    """
    transactions = _generate_transactions(account_id, count=10)
    return {
        "status": "ok",
        "data": {
            "account_id": account_id,
            "transaction_count": len(transactions),
            "transactions": transactions,
        },
    }


@router.post("/transfers")
async def initiate_transfer(request: Request) -> Dict[str, Any]:
    """
    Initiate a funds transfer.

    INTENTIONALLY performs no validation — Q-SAFE is the enforcement point.
    """
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    tx_id = f"TX-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "ok",
        "data": {
            "tx_id": tx_id,
            "from_account": body.get("from_account", "UNKNOWN"),
            "to_account": body.get("to_account", "UNKNOWN"),
            "amount": body.get("amount", 0.0),
            "currency": body.get("currency", "USD"),
            "status": "PENDING",
            "initiated_at": datetime.now(timezone.utc).isoformat(),
            "estimated_settlement": (
                datetime.now(timezone.utc) + timedelta(hours=24)
            ).isoformat(),
        },
    }


@router.get("/admin/users")
async def list_all_users(request: Request) -> Dict[str, Any]:
    """
    List all users — admin-only endpoint.

    INTENTIONALLY missing role check — Q-SAFE is the enforcement point.
    This is the primary BFLA target in the demo.
    """
    return {
        "status": "ok",
        "data": {
            "total": len(SEED_USERS),
            "users": list(SEED_USERS.values()),
        },
    }


@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, request: Request) -> Dict[str, Any]:
    """
    Delete a user — admin-only endpoint.

    INTENTIONALLY missing role check — Q-SAFE is the enforcement point.
    This is the primary BFLA target in the demo (DELETE is more dramatic).
    """
    user_found = any(
        u.get("username") == user_id or u.get("user_id") == user_id
        for u in SEED_USERS.values()
    )
    return {
        "status": "ok",
        "data": {
            "deleted_user_id": user_id,
            "found": user_found,
            "message": f"User '{user_id}' deletion processed (demo — no actual deletion)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
