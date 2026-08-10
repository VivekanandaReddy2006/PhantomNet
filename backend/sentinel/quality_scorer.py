"""
backend/sentinel/quality_scorer.py
-----------------------------------
PhantomNet Sentinel Layer — Playbook Quality Scoring Engine

Calculates a dynamic quality score (0-100) based on:
1. IOC count: Number of unique Indicators of Compromise
2. Cluster volume: Number of events in the campaign
3. Model confidence: ML threat score or confidence score
4. Multi-source verification: Whether the threat was verified by multiple sources (e.g., ML detection + Threat Intel IOCs)
"""

def calculate_quality_score(
    ioc_count: int,
    event_count: int,
    model_confidence: float,
    multi_source_verified: bool
) -> float:
    """
    Calculate a 0-100 quality score for a playbook.

    Args:
        ioc_count: Number of unique IOCs involved.
        event_count: Total volume of events in the cluster.
        model_confidence: The confidence score from the model (assumed 0.0 - 1.0, or 0-100).
        multi_source_verified: True if verified across multiple sources (e.g. ML + Intel).

    Returns:
        Float quality score from 0.0 to 100.0.
    """
    # Normalize model confidence to 0-100 if it is 0-1.0
    if model_confidence <= 1.0 and model_confidence > 0.0:
        conf_score = model_confidence * 100.0
    else:
        conf_score = max(0.0, min(100.0, model_confidence))

    # Base score derived heavily from model confidence (up to 40 points)
    score = conf_score * 0.40

    # IOC count (up to 20 points, 5 points per IOC)
    score += min(20.0, ioc_count * 5.0)

    # Cluster volume (up to 20 points, cap at 100 events)
    score += min(20.0, (event_count / 100.0) * 20.0)

    # Multi-source verification (20 points)
    if multi_source_verified:
        score += 20.0

    return round(max(0.0, min(100.0, score)), 2)
