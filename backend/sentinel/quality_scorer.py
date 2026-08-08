"""
backend/sentinel/quality_scorer.py
-----------------------------------
Calculates dynamic quality scores (0-100) for Sentinel incident playbooks based on
threat confidence, IOC density, rule completeness, and multi-source verification.
"""

from typing import Any, Dict, Optional


def calculate_playbook_quality_score(playbook_data: Dict[str, Any]) -> int:
    """
    Compute a deterministic quality score from 0 to 100 for a playbook.

    Scoring factors:
    - Base confidence score (up to 40 pts)
    - Threat score (up to 20 pts)
    - Presence of Snort & Sigma rules (15 pts)
    - Presence of MITRE technique mapping (10 pts)
    - Presence of AI narrative (10 pts)
    - Multi-source / multi-protocol indicators (5 pts)

    Args:
        playbook_data: Dict representation of a SentinelPlaybook model or generation payload.

    Returns:
        int: Quality score bounded between 0 and 100.
    """
    score = 0.0

    # 1. Confidence score (0.0 to 1.0 -> max 40 pts)
    conf = playbook_data.get("confidence_score")
    if conf is not None:
        score += float(conf) * 40.0
    else:
        score += 20.0  # Default midpoint if missing

    # 2. Threat score (0.0 to 100.0 -> max 20 pts)
    threat = playbook_data.get("threat_score")
    if threat is not None:
        score += (min(float(threat), 100.0) / 100.0) * 20.0

    # 3. Detection rules completeness (15 pts total)
    snort = playbook_data.get("snort_rule")
    sigma = playbook_data.get("sigma_rule")
    if snort and len(snort.strip()) > 10:
        score += 10.0
    if sigma and len(sigma.strip()) > 10:
        score += 5.0

    # 4. MITRE mapping (10 pts)
    tech_id = playbook_data.get("technique_id")
    if tech_id and tech_id != "T0000":
        score += 10.0

    # 5. AI narrative (10 pts)
    llm_narrative = playbook_data.get("llm_narrative")
    if llm_narrative and len(llm_narrative.strip()) > 20:
        score += 10.0

    # 6. Additional indicators / Source IP / Severity (5 pts)
    if playbook_data.get("src_ip"):
        score += 3.0
    if playbook_data.get("severity") in ("CRITICAL", "HIGH"):
        score += 2.0

    final_score = int(round(score))
    return max(0, min(100, final_score))
