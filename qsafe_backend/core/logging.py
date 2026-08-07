"""
Q-SAFE Structured Audit Logger
================================
Append-only JSONL audit logger for all gateway events.

Design principles:
- Every gateway verdict (ALLOW and BLOCK) is written — no omissions.
- Thread-safe file append via a dedicated lock.
- Non-blocking: caller gets a background thread write, never waits.
- JSON Lines format: one JSON object per line, newline-terminated.
- Never raises to the caller — logging failures must not impact enforcement.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import get_settings


class AuditLogger:
    """
    Append-only, thread-safe JSONL audit logger.

    Every log entry is a JSON object written as a single line to the
    configured log file. Entries are never modified or deleted.

    Usage::

        logger = AuditLogger()
        logger.log_event({"event": "...", "status": "allowed"})
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        settings = get_settings()
        self._path = Path(log_path or settings.log_file_path)
        self._lock = threading.Lock()
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, fields: Dict[str, Any]) -> None:
        """
        Append a structured JSON event to the audit log file.

        This method is non-raising: any IO error is printed to stderr
        but does NOT propagate to the caller.

        Args:
            fields: Arbitrary dict of event fields. A 'log_timestamp' and
                    'log_id' are automatically injected.
        """
        entry = {
            "log_id": uuid.uuid4().hex,
            "log_timestamp": time.time(),
            **fields,
        }
        line = json.dumps(entry, default=str) + "\n"
        try:
            with self._lock:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception as exc:  # noqa: BLE001
            # Logging must never crash the application
            print(f"[AuditLogger] WARN: Failed to write audit entry: {exc}", flush=True)

    def log_enforcement_event(
        self,
        *,
        request_id: str,
        session_id: str,
        user: str,
        role: str,
        endpoint: str,
        method: str,
        verdict: str,
        violation_type: Optional[str],
        latency_ms: float,
        context_hash: str,
        ip_address: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a gateway enforcement decision — the primary audit record type.

        Args:
            request_id:     Unique ID for this HTTP request.
            session_id:     Session identifier from JWT.
            user:           Authenticated username.
            role:           User role.
            endpoint:       Requested endpoint path.
            method:         HTTP method.
            verdict:        'allowed' or 'blocked'.
            violation_type: Violation classification or None.
            latency_ms:     Enforcement hot-path latency.
            context_hash:   CCFH context hash (hex string).
            ip_address:     Client IP address.
            extra:          Additional arbitrary fields.
        """
        fields: Dict[str, Any] = {
            "event_type": "enforcement",
            "request_id": request_id,
            "session_id": session_id,
            "user": user,
            "role": role,
            "endpoint": endpoint,
            "method": method,
            "verdict": verdict,
            "violation_type": violation_type,
            "latency_ms": latency_ms,
            "context_hash": context_hash,
            "ip_address": ip_address,
        }
        if extra:
            fields.update(extra)
        self.log_event(fields)

    def log_agent_event(
        self,
        agent_name: str,
        event_type: str,
        fields: Dict[str, Any],
    ) -> None:
        """
        Log an event emitted by one of the autonomous agents.

        Args:
            agent_name: 'profiler' | 'oracle'.
            event_type: Human-readable event category.
            fields:     Arbitrary event data.
        """
        self.log_event(
            {
                "event_type": f"agent.{agent_name}.{event_type}",
                **fields,
            }
        )

    def log_startup_event(self, event_type: str, result: str, detail: str = "") -> None:
        """
        Log a startup self-check or initialization event.

        Args:
            event_type: Category string (e.g., 'self_check', 'policy_load').
            result:     'PASS' | 'FAIL' | 'OK'.
            detail:     Optional human-readable detail.
        """
        self.log_event(
            {
                "event_type": f"startup.{event_type}",
                "result": result,
                "detail": detail,
            }
        )


# ── Module-Level Singleton ────────────────────────────────────────────────────

_audit_logger: Optional[AuditLogger] = None
_logger_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """
    Return the process-wide AuditLogger singleton.

    Thread-safe lazy initialization.

    Returns:
        Shared AuditLogger instance.
    """
    global _audit_logger
    if _audit_logger is None:
        with _logger_lock:
            if _audit_logger is None:
                _audit_logger = AuditLogger()
    return _audit_logger
