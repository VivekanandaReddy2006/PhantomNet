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
