"""
Q-SAFE AI Threat-Hunting Oracle Agent
========================================
Autonomous background agent that provides AI-powered threat explanations
for blocked and high-risk events.

Integration: OpenRouter API (async httpx calls).
Primary model:  google/gemini-2.0-flash-exp:free
Fallback model: mistralai/mistral-7b-instruct:free
Local fallback: deterministic template explanations (zero dependencies).

DESIGN BOUNDARY:
  This agent is STRICTLY off the enforcement path. It NEVER makes blocking
  decisions. Its role is: explain, tag, hunt — never block.

  The enforcement path is deterministic. This agent enriches event records
  with AI analysis AFTER the verdict has already been emitted.

GRACEFUL DEGRADATION:
  If no API key: use template-based explanations. Demo ALWAYS works.
  If API returns malformed JSON: discard and use template fallback.
  If network fails: use template fallback.
  Agent NEVER stops running.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from core.config import get_settings
from core.logging import get_audit_logger
from core.models import EventRecord, EventStatus, OracleAnalysis, ViolationType

# ── OWASP / MITRE Classification Maps ────────────────────────────────────────

_OWASP_TAGS: Dict[str, str] = {
    ViolationType.BOLA.value: "API1:2023 — Broken Object Level Authorization",
    ViolationType.BFLA.value: "API5:2023 — Broken Function Level Authorization",
    ViolationType.RATE.value: "API4:2023 — Unrestricted Resource Consumption",
    ViolationType.REPLAY.value: "API2:2023 — Broken Authentication",
    ViolationType.SEQUENCE.value: "API1:2023 — Broken Object Level Authorization",
}

_MITRE_TAGS: Dict[str, str] = {
    ViolationType.BOLA.value: "T1078 — Valid Accounts",
    ViolationType.BFLA.value: "T1134 — Access Token Manipulation / Privilege Escalation",
    ViolationType.RATE.value: "T1498 — Network Denial of Service",
    ViolationType.REPLAY.value: "T1078 — Valid Accounts",
    ViolationType.SEQUENCE.value: "T1078 — Valid Accounts",
}

# ── Template Explanations (deterministic local fallback) ──────────────────────

_TEMPLATES: Dict[str, str] = {
    ViolationType.BOLA.value: (
        "The request attempted to access an object (e.g., bank account) belonging to a "
        "different user. The requesting session's JWT contains account ownership claims "
        "that do not match the requested resource identifier. Q-SAFE's object-level "
        "authorization layer detected the ownership mismatch and blocked the request "
        "before any data was disclosed to the attacker."
    ),
    ViolationType.BFLA.value: (
        "A low-privilege user attempted to invoke a function restricted to higher-privilege "
        "roles (e.g., a 'user' calling an 'admin'-only endpoint). This is a classic "
        "privilege escalation attempt. Q-SAFE's function-level authorization check confirmed "
        "that the JWT role claim does not appear in the endpoint's allowed_roles list, "
        "and the request was blocked before execution."
    ),
    ViolationType.RATE.value: (
        "The session exceeded the configured request rate limit within the sliding time "
        "window. Excessive request rates can indicate automated scraping, credential "
        "stuffing, or denial-of-service activity. Q-SAFE's sliding-window rate limiter "
        "detected the anomaly and blocked the request to protect downstream service availability."
    ),
    ViolationType.REPLAY.value: (
        "The presented JWT token failed signature or expiry validation. This indicates "
        "either a replayed expired token, a forged token with an invalid signature, or "
        "a token from a revoked session. Q-SAFE's cryptographic validation layer detected "
        "the anomaly and rejected the request at the authentication stage."
    ),
    ViolationType.SEQUENCE.value: (
        "The request produced a CCFH context hash that is not in the allowlist for the "
        "session's role. This means the API was accessed in an order that deviates from "
        "all known legitimate access sequences. Attackers often skip prerequisite steps "
        "(e.g., calling /admin/users directly without authenticating first). Q-SAFE's "
        "sequence integrity engine detected the deviation and blocked the request."
    ),
    "UNKNOWN": (
        "Q-SAFE's enforcement pipeline detected an anomalous request pattern and blocked "
        "the request. The violation does not match a known classification but exceeds "
        "the configured risk threshold."
    ),
}


class OracleAgent:
    """
    AI Threat-Hunting Oracle — autonomous async background agent.

    Consumes blocked events from the event queue (via a separate monitoring
    loop since the profiler_agent drains the same queue).

    Uses a dedicated internal queue for oracle processing to avoid competing
    with the profiler for queue events.
    """

    def __init__(self) -> None:
        self._oracle_queue: asyncio.Queue[EventRecord] = asyncio.Queue(maxsize=1000)
        self._logger = get_audit_logger()
        self._running = False
        self._settings = get_settings()
        self._http_client: Optional[httpx.AsyncClient] = None

    async def run(self) -> None:
        """
        Main oracle agent loop. Processes blocked/high-risk events indefinitely.
        """
        self._running = True
        self._http_client = httpx.AsyncClient(timeout=30.0)
        print("[OracleAgent] Started AI threat-hunting oracle.", flush=True)
        if not self._settings.openrouter_api_key:
            print(
                "[OracleAgent] No OPENROUTER_API_KEY set — using template-based explanations.",
                flush=True,
            )

        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(
                        self._oracle_queue.get(), timeout=5.0
                    )
                    await self._analyze_event(event)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    print("[OracleAgent] Cancelled — shutting down.", flush=True)
                    break
                except Exception as exc:  # noqa: BLE001
                    print(f"[OracleAgent] WARN: Unhandled error: {exc}", flush=True)
                    await asyncio.sleep(1.0)
        finally:
            if self._http_client:
                await self._http_client.aclose()

    async def submit(self, event: EventRecord) -> None:
        """
        Submit a blocked/high-risk event for oracle analysis.

        Called by the profiler or main event dispatcher — not the hot path.

        Args:
            event: The event to analyze.
        """
        try:
            self._oracle_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop under load — oracle is best-effort

    async def _analyze_event(self, event: EventRecord) -> None:
        """
        Analyze a single event and update it with AI-generated explanation.

        Args:
            event: Event record to enrich.
        """
        violation = (
            event.violation_type.value
            if event.violation_type
            else "UNKNOWN"
        )

        if self._settings.openrouter_api_key:
            analysis = await self._call_llm(event, violation)
        else:
            analysis = self._build_template_analysis(violation)

        # Update the telemetry store with the analysis
        try:
            from telemetry.store import get_telemetry_store
            store = get_telemetry_store()
            await store.update_event_analysis(
                event_id=event.event_id,
                analysis=analysis,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[OracleAgent] WARN: Could not update telemetry store: {exc}", flush=True)

        self._logger.log_agent_event(
            "oracle",
            "analysis_complete",
            {
                "event_id": event.event_id,
                "user": event.user,
                "violation": violation,
                "owasp_tag": analysis.owasp_tag,
                "confidence": analysis.confidence,
            },
        )

    async def _call_llm(self, event: EventRecord, violation: str) -> OracleAnalysis:
        """
        Call OpenRouter LLM API for threat analysis.

        Tries primary model first, falls back to secondary on error.
        Falls back to template if both fail.

        Args:
            event:     Event record to analyze.
            violation: Violation type string.

        Returns:
            OracleAnalysis with explanation, owasp_tag, mitre_technique, confidence.
        """
        prompt = self._build_prompt(event, violation)
        models = [
            self._settings.openrouter_model,
            self._settings.openrouter_fallback_model,
        ]

        for model in models:
            try:
                result = await self._llm_request(model, prompt)
                if result:
                    return result
            except Exception as exc:  # noqa: BLE001
                print(f"[OracleAgent] LLM call failed ({model}): {exc}", flush=True)

        # Both models failed — use template
        return self._build_template_analysis(violation)

    async def _llm_request(self, model: str, prompt: str) -> Optional[OracleAnalysis]:
        """
        Make a single OpenRouter API call and parse the structured response.

        Args:
            model:  Model identifier string.
            prompt: Security analyst prompt.

        Returns:
            Parsed OracleAnalysis or None if response is malformed.
        """
        assert self._http_client is not None

        headers = {
            "Authorization": f"Bearer {self._settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://qsafe.security",
            "X-Title": "Q-SAFE Threat Oracle",
        }

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert API security analyst. Analyze the provided "
                        "blocked API request and respond ONLY with a JSON object matching "
                        "this exact schema: "
                        '{"explanation": "string", "owasp_tag": "string", '
                        '"mitre_technique": "string", "confidence": float_0_to_1}'
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }

        response = await self._http_client.post(
            f"{self._settings.openrouter_base_url}/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        # Extract JSON from the response (LLM may wrap in markdown code blocks)
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if not json_match:
            return None

        raw_json = json.loads(json_match.group())

        # Validate against strict Pydantic schema — discard hallucinated output
        try:
            return OracleAnalysis.model_validate(raw_json)
        except Exception:
            return None

    def _build_prompt(self, event: EventRecord, violation: str) -> str:
        """
        Build the security analyst prompt for the LLM.

        Args:
            event:     Event record.
            violation: Violation type string.

        Returns:
            Prompt string.
        """
        return (
            f"Blocked API request details:\n"
            f"- User: {event.user} (role: {event.role})\n"
            f"- Endpoint: {event.method} {event.endpoint}\n"
            f"- Violation type: {violation}\n"
            f"- Context hash: {event.context_hash}\n"
            f"- Timestamp: {event.timestamp}\n\n"
            f"Provide: 1) A concise explanation of why this was blocked and what attack it represents. "
            f"2) The specific OWASP API Top 10 2023 tag (e.g., 'API1:2023 — Broken Object Level Authorization'). "
            f"3) The most relevant MITRE ATT&CK technique ID and name (e.g., 'T1078 — Valid Accounts'). "
            f"4) Your confidence score (0.0 to 1.0). "
            f"Respond ONLY with a JSON object."
        )

    def _build_template_analysis(self, violation: str) -> OracleAnalysis:
        """
        Build a deterministic template-based OracleAnalysis when no LLM is available.

        This ensures the demo always has meaningful threat explanations.

        Args:
            violation: Violation type string.

        Returns:
            OracleAnalysis with template content.
        """
        return OracleAnalysis(
            explanation=_TEMPLATES.get(violation, _TEMPLATES["UNKNOWN"]),
            owasp_tag=_OWASP_TAGS.get(violation, "OWASP API Security Top 10"),
            mitre_technique=_MITRE_TAGS.get(violation, "T1078 — Valid Accounts"),
            confidence=0.95,  # High confidence for rule-based classification
        )

    def stop(self) -> None:
        """Signal the agent to stop."""
        self._running = False
