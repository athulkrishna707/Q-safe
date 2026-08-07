# Q-SAFE Backend

**Query-Sequence Authorization & Forensic Enforcement**
Zero-Trust API Security Gateway — Python Backend

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Q-SAFE Gateway Stack                      │
│                                                             │
│  ┌─────────────┐     ┌────────────────────────────────────┐ │
│  │  React UI   │     │     Python FastAPI Backend         │ │
│  │  Port 3000  │────▶│          Port 8000                 │ │
│  │  (Vite proxy│     │                                    │ │
│  │   rules)    │     │  ┌─────────────────────────────┐  │ │
│  └─────────────┘     │  │  EnforcementMiddleware       │  │ │
│                      │  │  (HOT PATH — synchronous)    │  │ │
│                      │  │  1. JWT verify               │  │ │
│                      │  │  2. Rate limit (O(1))        │  │ │
│                      │  │  3. Endpoint ID resolution   │  │ │
│                      │  │  4. BFLA check (O(1))        │  │ │
│                      │  │  5. BOLA check (O(1))        │  │ │
│                      │  │  6. Sequence hash + allowlist│  │ │
│                      │  │  7. ALLOW / BLOCK verdict    │  │ │
│                      │  └─────────────────────────────┘  │ │
│                      │          │           │            │ │
│                      │       ALLOW        BLOCK          │ │
│                      │          │           │            │ │
│                      │  ┌───────▼──┐  ┌────▼──────────┐ │ │
│                      │  │ Banking  │  │  403 + event  │ │ │
│                      │  │   API    │  │  queue push   │ │ │
│                      │  └──────────┘  └───────────────┘ │ │
│                      │                        │          │ │
│                      │  ┌─────────────────────▼────────┐ │ │
│                      │  │   Async Agent Pipeline        │ │ │
│                      │  │  ┌─────────────────────────┐ │ │ │
│                      │  │  │  ProfilerAgent (5s loop)│ │ │ │
│                      │  │  │  Risk scoring 0–100     │ │ │ │
│                      │  │  └─────────────────────────┘ │ │ │
│                      │  │  ┌─────────────────────────┐ │ │ │
│                      │  │  │  OracleAgent (async)    │ │ │ │
│                      │  │  │  AI threat explanations │ │ │ │
│                      │  │  └─────────────────────────┘ │ │ │
│                      │  └──────────────────────────────┘ │ │
│                      └────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Install Python dependencies

```bash
cd qsafe_backend
pip install -r requirements.txt
```

### 2. (Optional) Set your OpenRouter API key

```bash
# Create .env in qsafe_backend/ (or set env var)
echo "OPENROUTER_API_KEY=your_key_here" > .env
```

If no key is set, the AI Oracle uses deterministic template explanations — the demo fully works offline.

### 3. Start the Python backend

```bash
# From qsafe_backend/ directory
uvicorn main:app --reload --port 8000
```

You should see:
```
============================================================
  Q-SAFE STARTUP SELF-CHECK
============================================================

[SELF-CHECK 1] Valid sequence: users/me → accounts/{id}
  ✓ PASS: hash after step 1 = 0x0000000000001A01 → IN allowlist
  ✓ PASS: hash after step 2 = 0x0000000000035400 → IN allowlist

[SELF-CHECK 2] BFLA: user role → admin endpoint 0x9F01
  ✓ PASS: BFLA correctly BLOCKED — BFLA: Role 'user' is not authorized...

[SELF-CHECK 3] Policy artifact HMAC signature verification
  ✓ PASS: Policy artifact HMAC signature valid

============================================================
  ✅ ALL SELF-CHECKS PASSED — BOOT AUTHORIZED
============================================================

[Q-SAFE] 🛡️  Gateway is ONLINE. All systems operational.
```

### 4. Start the frontend (separate terminal)

```bash
# From Q-SAFE root directory
npm run dev
```

Frontend at: http://localhost:3000
Backend API: http://localhost:8000/docs

---

## curl Demo Script

```bash
# Set the backend URL
BACKEND="http://localhost:8000"

# ── STEP 1: Get alice's token ───────────────────────────────────────────────
echo "=== Getting alice's token ==="
ALICE_RESPONSE=$(curl -s -X POST "$BACKEND/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}')

echo "$ALICE_RESPONSE" | python -m json.tool

ALICE_TOKEN=$(echo "$ALICE_RESPONSE" | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Token: ${ALICE_TOKEN:0:50}..."

# ── STEP 2: Normal request — GET /users/me ──────────────────────────────────
echo ""
echo "=== Step 2: Normal request (should be ALLOWED) ==="
curl -s -X GET "$BACKEND/bank/api/v1/users/me" \
  -H "Authorization: Bearer $ALICE_TOKEN" | python -m json.tool

# ── STEP 3: BOLA attack — alice accessing bob's account ────────────────────
echo ""
echo "=== Step 3: BOLA Attack (should be BLOCKED 403) ==="
curl -s -X GET "$BACKEND/bank/api/v1/accounts/B-2002" \
  -H "Authorization: Bearer $ALICE_TOKEN" | python -m json.tool

# ── STEP 4: BFLA attack — alice calling admin endpoint ─────────────────────
echo ""
echo "=== Step 4: BFLA Attack (should be BLOCKED 403) ==="
# Get fresh token (old session may be revoked)
FRESH_TOKEN=$(curl -s -X POST "$BACKEND/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}' | \
  python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X DELETE "$BACKEND/bank/api/v1/admin/users/bob" \
  -H "Authorization: Bearer $FRESH_TOKEN" | python -m json.tool

# ── STEP 5: Use simulator endpoint ─────────────────────────────────────────
echo ""
echo "=== Step 5: Trigger BOLA via Simulator ==="
curl -s -X POST "$BACKEND/simulator/attack" \
  -H "Content-Type: application/json" \
  -d '{"type": "bola"}' | python -m json.tool

# ── STEP 6: Read telemetry events (see AI explanation) ─────────────────────
echo ""
echo "=== Step 6: Read Telemetry Events ==="
curl -s "$BACKEND/telemetry/events?limit=5" | python -m json.tool

# ── STEP 7: Check metrics ───────────────────────────────────────────────────
echo ""
echo "=== Step 7: Dashboard Metrics ==="
curl -s "$BACKEND/telemetry/metrics" | python -m json.tool

# ── STEP 8: Risk scores ─────────────────────────────────────────────────────
echo ""
echo "=== Step 8: Risk Scores ==="
curl -s "$BACKEND/telemetry/risk-scores" | python -m json.tool
```

---

## Running Tests

```bash
cd qsafe_backend
pytest tests/ -v
```

Expected output:
```
tests/test_enforcement.py::TestCCFHAlgorithm::test_hash_update_basic PASSED
tests/test_enforcement.py::TestCCFHAlgorithm::test_64bit_mask_applied PASSED
tests/test_enforcement.py::TestPolicyEngine::test_bfla_user_blocked_from_admin PASSED
tests/test_enforcement.py::TestPolicyEngine::test_policy_tamper_detection PASSED
tests/test_enforcement.py::TestBOLADetection::test_alice_accessing_bob_account_blocked PASSED
tests/test_enforcement.py::TestRateLimiting::test_exceeds_limit_blocked PASSED
tests/test_enforcement.py::TestJWTValidation::test_expired_jwt_raises PASSED
tests/test_enforcement.py::TestSimulatorEndToEnd::test_bfla_simulation_blocks PASSED
tests/test_enforcement.py::TestSimulatorEndToEnd::test_enforcement_latency_under_15ms PASSED
```

---

## API Reference

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/token` | Issue JWT for demo user |

### Protected Banking API (gateway-enforced)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/bank/api/v1/users/me` | Own user profile |
| GET | `/bank/api/v1/accounts/{account_id}` | Account details (ownership enforced) |
| GET | `/bank/api/v1/accounts/{account_id}/transactions` | Transactions (ownership enforced) |
| POST | `/bank/api/v1/transfers` | Initiate transfer |
| GET | `/bank/api/v1/admin/users` | List all users (admin only) |
| DELETE | `/bank/api/v1/admin/users/{user_id}` | Delete user (admin only) |

### Telemetry
| Method | Path | Description |
|--------|------|-------------|
| GET | `/telemetry/metrics` | Executive dashboard metrics |
| GET | `/telemetry/events?limit=50` | Recent event records |
| GET | `/telemetry/risk-scores` | Per-session risk scores |
| GET | `/sessions/{id}/sequence` | CCFH sequence trace |
| POST | `/sessions/{id}/quarantine` | Revoke session |
| WS | `/ws/events` | Live event stream |

### Simulator
| Method | Path | Description |
|--------|------|-------------|
| POST | `/simulator/attack` | Run attack simulation |

### AI Oracle
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze-threat` | AI re-analysis (frontend compat) |

---

## CCFH Algorithm

The Contextual Control Flow Hashing algorithm:

```python
hash = ((hash << 1) & 0xFFFFFFFFFFFFFFFF) ^ endpoint_id
```

- Every endpoint has a stable 64-bit ID (e.g., `0x1A01` for `/users/me`)
- Sessions maintain a rolling hash updated on each authorized access
- The policy engine pre-computes all valid hash states per role at startup
- Authorization requires O(1) set membership check: `hash in role_allowlist`

The 64-bit mask is mandatory — Python ints are unbounded, so register overflow semantics must be enforced explicitly.

---

## Demo Credentials

| Username | Password | Role | Account |
|----------|----------|------|---------|
| alice | alice123 | user | A-1001 |
| bob | bob123 | user | B-2002 |
| admin | admin123 | admin | — |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `qsafe-dev-secret-...` | JWT + HMAC signing key |
| `JWT_EXPIRE_MINUTES` | `60` | Token TTL |
| `OPENROUTER_API_KEY` | `None` | AI oracle API key (optional) |
| `OPENROUTER_MODEL` | `google/gemini-2.0-flash-exp:free` | Primary LLM |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window |
| `LOG_FILE_PATH` | `audit.jsonl` | Audit log file path |
| `SEED_TRAFFIC_EVENTS` | `30` | Events to seed on startup |
| `PORT` | `8000` | Server port |
