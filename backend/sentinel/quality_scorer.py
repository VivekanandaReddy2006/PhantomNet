"""
backend/sentinel/quality_scorer.py
-----------------------------------
PhantomNet Sentinel Layer — Playbook Quality Scoring Engine

Provides two scoring functions:

  calculate_quality_score(ioc_count, event_count, model_confidence,
                          multi_source_verified) -> float
      Internal pipeline scorer used by sentinel_service.py during playbook
      generation. Accepts raw numeric inputs.

  calculate_playbook_quality_score(playbook_data: dict) -> float
      Public dict-based scorer for REST API and test consumers.
      Accepts a dictionary representation of a SentinelPlaybook (or any
      subset of its fields) and returns a 0–100 quality score.

Score composition (100 points total):
  - Model confidence (up to 40 pts): confidence_score × 40
  - IOC count        (up to 20 pts): 5 pts per IOC, capped at 4 IOCs
  - Cluster volume   (up to 20 pts): proportional to event_count, cap 100 events
  - Multi-source     (up to 20 pts): presence of IOC + ML data verification

Extended scoring bonuses applied by calculate_playbook_quality_score():
  - Snort rule present            (+5 pts, up to max 100)
  - Sigma rule present            (+5 pts)
  - Technique ID mapped           (+5 pts)
  - LLM narrative generated       (+5 pts)
  - High threat score (>= 70)     (+5 pts)
  - src_ip present                (+3 pts)
  - severity CRITICAL/HIGH        (+2 pts)
"""

from typing import Any, Dict, Optional


def calculate_quality_score(
    ioc_count: int,
    event_count: int,
    model_confidence: float,
    multi_source_verified: bool,
) -> float:
    """
    Calculate a 0–100 quality score for a playbook.

    Used internally by sentinel_service.py during the pipeline's Step 2d.

    Args:
        ioc_count:            Number of unique IOCs involved.
        event_count:          Total volume of events in the cluster.
        model_confidence:     Confidence score from the model (0.0–1.0 or 0–100).
        multi_source_verified: True if verified across multiple sources (ML + Intel).

    Returns:
        Float quality score from 0.0 to 100.0.
    """
    # Normalize model confidence to 0–100 if expressed as 0.0–1.0
    if 0.0 < model_confidence <= 1.0:
        conf_score = model_confidence * 100.0
    else:
        conf_score = max(0.0, min(100.0, model_confidence))

    # Base score from model confidence (up to 40 points)
    score = conf_score * 0.40

    # IOC count contribution (up to 20 points, 5 points per IOC)
    score += min(20.0, ioc_count * 5.0)

    # Cluster volume contribution (up to 20 points, proportional, cap 100 events)
    score += min(20.0, (event_count / 100.0) * 20.0)

    # Multi-source verification bonus (20 points)
    if multi_source_verified:
        score += 20.0

    return round(max(0.0, min(100.0, score)), 2)


def calculate_playbook_quality_score(playbook_data: Dict[str, Any]) -> float:
    """
    Calculate a 0–100 quality score from a playbook data dictionary.

    Designed for REST API callers, test suites, and the admin dashboard.
    Accepts any dict containing a subset of SentinelPlaybook fields.

    Args:
        playbook_data: Dictionary with any of the following optional fields:
            - confidence_score  (float, 0.0–1.0 or 0–100)
            - threat_score      (float, 0–100)
            - ioc_count         (int)
            - event_count       (int)
            - snort_rule        (str)
            - sigma_rule        (str)
            - technique_id      (str)
            - llm_narrative     (str)
            - src_ip            (str)
            - severity          (str, e.g. "CRITICAL", "HIGH")

    Returns:
        Float quality score from 0.0 to 100.0.
    """
    if not isinstance(playbook_data, dict):
        return 0.0

    # ── Extract and normalize confidence score ────────────────────────────
    confidence_raw = playbook_data.get("confidence_score", 0.0)
    try:
        confidence_raw = float(confidence_raw)
    except (TypeError, ValueError):
        confidence_raw = 0.0

    if 0.0 < confidence_raw <= 1.0:
        conf_score = confidence_raw * 100.0
    else:
        conf_score = max(0.0, min(100.0, confidence_raw))

    # ── Extract threat score ──────────────────────────────────────────────
    threat_score_raw = playbook_data.get("threat_score", 0.0)
    try:
        threat_score = float(threat_score_raw)
    except (TypeError, ValueError):
        threat_score = 0.0

    # ── Extract IOC count ─────────────────────────────────────────────────
    ioc_count_raw = playbook_data.get("ioc_count", 0)
    try:
        ioc_count = max(0, int(ioc_count_raw))
    except (TypeError, ValueError):
        ioc_count = 0

    # ── Extract event count ───────────────────────────────────────────────
    event_count_raw = playbook_data.get("event_count", 0)
    try:
        event_count = max(0, int(event_count_raw))
    except (TypeError, ValueError):
        event_count = 0

    # ── Base quality score (same formula as calculate_quality_score) ──────
    score = conf_score * 0.40
    score += min(20.0, ioc_count * 5.0)
    score += min(20.0, (event_count / 100.0) * 20.0)

    # Multi-source bonus: consider threat_score as proxy for ML verification
    if threat_score > 0 and ioc_count > 0:
        score += 20.0
    elif threat_score > 0 or ioc_count > 0:
        score += 10.0

    # ── Extended attribute bonuses (up to 30 extra points) ───────────────
    bonus = 0.0

    # Snort rule present (+5)
    snort_rule = playbook_data.get("snort_rule") or ""
    if str(snort_rule).strip():
        bonus += 5.0

    # Sigma rule present (+5)
    sigma_rule = playbook_data.get("sigma_rule") or ""
    if str(sigma_rule).strip():
        bonus += 5.0

    # Technique ID mapped (+5)
    technique_id = playbook_data.get("technique_id") or ""
    if str(technique_id).strip():
        bonus += 5.0

    # LLM narrative generated (+5)
    llm_narrative = playbook_data.get("llm_narrative") or ""
    if str(llm_narrative).strip():
        bonus += 5.0

    # High threat score (+5)
    if threat_score >= 70.0:
        bonus += 5.0

    # Source IP present (+3)
    src_ip = playbook_data.get("src_ip") or ""
    if str(src_ip).strip():
        bonus += 3.0

    # High severity (+2)
    severity = str(playbook_data.get("severity") or "").strip().upper()
    if severity in ("CRITICAL", "HIGH"):
        bonus += 2.0

    score += bonus
    return round(max(0.0, min(100.0, score)), 2)
