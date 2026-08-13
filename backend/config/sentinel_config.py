"""
backend/config/sentinel_config.py
-----------------------------------
Sentinel Layer — Configuration Module

Centralises all Sentinel-specific configuration flags read from
environment variables.  Each setting has a sensible default so the
system works out-of-the-box without any `.env` changes.

Environment Variables
---------------------
  SENTINEL_ENABLED                    : Master switch for the legacy async
                                        generation loop in main.py.
  SENTINEL_AUTO_GEN_ENABLED           : Enable/disable APScheduler-based
                                        periodic playbook auto-generation.
  SENTINEL_AUTO_GEN_INTERVAL_MINUTES  : Interval in minutes between
                                        successive auto-generation runs.
  SENTINEL_LLM_ENABLED                : Enable AI-enhanced narrative
                                        summaries inside playbooks.
  SENTINEL_LLM_HOST                   : Ollama inference server URL.
  SENTINEL_LLM_MODEL                  : LLM model name pulled in Ollama.

Phase 5, Week 4 — Sentinel Auto-Generation Scheduler
"""

from __future__ import annotations

import os
import logging

logger = logging.getLogger("sentinel.config")


def _env_bool(key: str, default: bool = False) -> bool:
    """Read a boolean environment variable (true/false, 1/0, yes/no)."""
    val = os.getenv(key, "").strip().lower()
    if not val:
        return default
    return val in ("true", "1", "yes", "on")


def _env_int(key: str, default: int = 0) -> int:
    """Read an integer environment variable with a safe fallback."""
    val = os.getenv(key, "").strip()
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        logger.warning(
            "Invalid integer for %s=%r — using default %d", key, val, default
        )
        return default


# ---------------------------------------------------------------------------
# Sentinel Auto-Generation Scheduler Configuration
# ---------------------------------------------------------------------------

SENTINEL_AUTO_GEN_ENABLED: bool = _env_bool("SENTINEL_AUTO_GEN_ENABLED", default=False)
"""
When True, the SchedulerService will register an APScheduler interval job
that periodically triggers the Sentinel pipeline to scan for new campaign
clusters and auto-generate playbooks.

Default: False (opt-in via environment variable).
"""

SENTINEL_AUTO_GEN_INTERVAL_MINUTES: int = _env_int(
    "SENTINEL_AUTO_GEN_INTERVAL_MINUTES", default=30
)
"""
Interval (in minutes) between successive sentinel auto-generation runs.
Must be >= 1 minute; values below 1 are clamped to 1 to avoid CPU thrashing.

Default: 30 minutes.
"""
# Clamp to minimum of 1 minute
if SENTINEL_AUTO_GEN_INTERVAL_MINUTES < 1:
    logger.warning(
        "SENTINEL_AUTO_GEN_INTERVAL_MINUTES=%d is too low — clamping to 1",
        SENTINEL_AUTO_GEN_INTERVAL_MINUTES,
    )
    SENTINEL_AUTO_GEN_INTERVAL_MINUTES = 1


# ---------------------------------------------------------------------------
# General Sentinel Flags (re-exposed for central access)
# ---------------------------------------------------------------------------

SENTINEL_ENABLED: bool = _env_bool("SENTINEL_ENABLED", default=False)
"""Master switch for the legacy async sentinel generation loop in main.py."""

SENTINEL_LLM_ENABLED: bool = _env_bool("SENTINEL_LLM_ENABLED", default=False)
"""Enable AI-enhanced narrative summaries inside incident playbooks."""

SENTINEL_LLM_HOST: str = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434")
"""Ollama inference server base URL."""

SENTINEL_LLM_MODEL: str = os.getenv("SENTINEL_LLM_MODEL", "mistral")
"""LLM model name pulled inside Ollama."""


# ---------------------------------------------------------------------------
# Email Alert Notification Configuration
# ---------------------------------------------------------------------------

SENTINEL_EMAIL_ALERTS_ENABLED: bool = _env_bool("SENTINEL_EMAIL_ALERTS_ENABLED", default=False)
"""
When True, email notifications are sent for playbooks that meet or exceed
the configured severity threshold.

Default: False (opt-in via environment variable).
"""

SENTINEL_EMAIL_SMTP_HOST: str = os.getenv("SENTINEL_EMAIL_SMTP_HOST", "localhost")
"""SMTP server hostname for sending alert emails."""

SENTINEL_EMAIL_SMTP_PORT: int = _env_int("SENTINEL_EMAIL_SMTP_PORT", default=587)
"""SMTP server port (587 for STARTTLS, 465 for SSL, 25 for unencrypted)."""

SENTINEL_EMAIL_SMTP_USER: str = os.getenv("SENTINEL_EMAIL_SMTP_USER", "")
"""SMTP authentication username. Leave empty for unauthenticated relay."""

SENTINEL_EMAIL_SMTP_PASSWORD: str = os.getenv("SENTINEL_EMAIL_SMTP_PASSWORD", "")
"""SMTP authentication password."""

SENTINEL_EMAIL_SMTP_USE_TLS: bool = _env_bool("SENTINEL_EMAIL_SMTP_USE_TLS", default=True)
"""Enable STARTTLS encryption for SMTP connections."""

SENTINEL_EMAIL_FROM_ADDRESS: str = os.getenv(
    "SENTINEL_EMAIL_FROM_ADDRESS", "sentinel@phantomnet.local"
)
"""Sender (From) email address for alert notifications."""

_raw_recipients = os.getenv("SENTINEL_EMAIL_RECIPIENTS", "")
SENTINEL_EMAIL_RECIPIENTS: list = [
    r.strip() for r in _raw_recipients.split(",") if r.strip()
]
"""
Comma-separated list of recipient email addresses for alert notifications.
Example: admin@example.com,soc-team@example.com
"""

SENTINEL_EMAIL_SEVERITY_THRESHOLD: str = os.getenv(
    "SENTINEL_EMAIL_SEVERITY_THRESHOLD", "CRITICAL"
).upper()
"""
Minimum severity level to trigger email alerts.
Valid values: CRITICAL, HIGH, MEDIUM, LOW.
Default: CRITICAL (only the most critical playbooks trigger emails).
"""

SENTINEL_DASHBOARD_BASE_URL: str = os.getenv(
    "SENTINEL_DASHBOARD_BASE_URL", "http://localhost:3000"
)
"""Base URL for constructing dashboard deep links in alert emails."""

# ---------------------------------------------------------------------------
# Sentinel Lifecycle Retention Configuration
# ---------------------------------------------------------------------------

SENTINEL_RETENTION_CLEANUP_ENABLED: bool = _env_bool("SENTINEL_RETENTION_CLEANUP_ENABLED", default=False)
"""Enable background cleanup of rejected and archived playbooks."""

SENTINEL_RETENTION_CLEANUP_INTERVAL_HOURS: int = _env_int("SENTINEL_RETENTION_CLEANUP_INTERVAL_HOURS", default=24)
"""Interval in hours to run the cleanup job."""

SENTINEL_RETENTION_REJECTED_DAYS: int = _env_int("SENTINEL_RETENTION_REJECTED_DAYS", default=30)
"""Days to keep rejected playbooks before purging."""

SENTINEL_RETENTION_ARCHIVED_DAYS: int = _env_int("SENTINEL_RETENTION_ARCHIVED_DAYS", default=90)
"""Days to keep old non-latest superseded versions before purging."""

