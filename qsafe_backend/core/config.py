"""
Q-SAFE Core Configuration
=========================
Environment-driven settings via pydantic-settings.
All values can be overridden via environment variables or a .env file.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ──────────────────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0", description="Bind host")
    port: int = Field(default=8000, description="Bind port")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"],
        description="Allowed CORS origins",
    )

    # ── JWT / Crypto ─────────────────────────────────────────────────────────
    secret_key: str = Field(
        default="qsafe-dev-secret-change-in-prod-32chars!!",
        description="HMAC secret for JWT signing and policy artifact HMAC",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_expire_minutes: int = Field(default=60, description="JWT TTL in minutes")

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str | None = Field(
        default=None,
        description="Redis connection URL. If unset, falls back to in-memory dict store.",
    )

    # ── AI / OpenRouter ──────────────────────────────────────────────────────
    openrouter_api_key: str | None = Field(
        default=None,
        description="OpenRouter API key. If unset, oracle uses template-based explanations.",
    )
    openrouter_model: str = Field(
        default="google/gemini-2.0-flash-exp:free",
        description="Primary LLM model for threat-hunting oracle",
    )
    openrouter_fallback_model: str = Field(
        default="mistralai/mistral-7b-instruct:free",
        description="Fallback LLM model if primary fails",
    )
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1",
        description="OpenRouter API base URL",
    )

    # ── Audit Logging ────────────────────────────────────────────────────────
    log_file_path: str = Field(
        default="audit.jsonl",
        description="Path to the append-only JSONL audit log file",
    )

    # ── Rate Limiting ────────────────────────────────────────────────────────
    rate_limit_requests: int = Field(default=100, description="Max requests per window")
    rate_limit_window_seconds: int = Field(default=60, description="Sliding window size in seconds")

    # ── Ambient Traffic ──────────────────────────────────────────────────────
    ambient_traffic_interval_seconds: float = Field(
        default=2.0, description="Interval between ambient benign traffic events"
    )
    seed_traffic_events: int = Field(
        default=30, description="Number of baseline events to seed on startup"
    )

    # ── Demo Credentials ─────────────────────────────────────────────────────
    demo_credentials: dict[str, dict] = Field(
        default={
            "alice": {"password": "alice123", "role": "user", "account_id": "A-1001"},
            "bob": {"password": "bob123", "role": "user", "account_id": "B-2002"},
            "admin": {"password": "admin123", "role": "admin", "account_id": None},
        },
        description="Demo user credentials and metadata",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str | List[str]) -> List[str]:
        """Accept comma-separated string or list for CORS origins."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
