"""
backend/sentinel/retention_service.py
---------------------------------------
Lifecycle retention & archive cleanup service for Sentinel playbooks.

Auto-archives or purges rejected and obsolete playbooks based on retention policies.
"""

from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from sentinel.models import SentinelPlaybook, SentinelAuditLog

logger = logging.getLogger("sentinel.retention_service")


def purge_expired_playbooks(
    db: Session,
    rejected_retention_days: int = 30,
    archived_retention_days: int = 90,
) -> Dict[str, int]:
    """
    Purge or archive playbooks exceeding retention limits.

    Args:
        db: Active SQLAlchemy database session.
        rejected_retention_days: Days to keep rejected playbooks before purge.
        archived_retention_days: Days to keep old non-latest versions before purge.

    Returns:
        Dict with counts of purged_rejected and purged_archived records.
    """
    now = datetime.utcnow()
    rejected_threshold = now - timedelta(days=rejected_retention_days)
    archived_threshold = now - timedelta(days=archived_retention_days)

    # 1. Purge old rejected playbooks
    expired_rejected = db.query(SentinelPlaybook).filter(
        SentinelPlaybook.status == "rejected",
        SentinelPlaybook.updated_at <= rejected_threshold,
    ).all()

    count_rejected = len(expired_rejected)
    for p in expired_rejected:
        audit = SentinelAuditLog(
            playbook_id=p.playbook_id,
            action="retention_purge",
            user="retention_service",
            details=f"Purged rejected playbook v{p.version} older than {rejected_retention_days} days.",
        )
        db.add(audit)
        db.delete(p)

    # 2. Purge old non-latest superseded versions
    expired_old_versions = db.query(SentinelPlaybook).filter(
        SentinelPlaybook.is_latest == False,
        SentinelPlaybook.updated_at <= archived_threshold,
    ).all()

    count_old_versions = len(expired_old_versions)
    for p in expired_old_versions:
        audit = SentinelAuditLog(
            playbook_id=p.playbook_id,
            action="retention_purge",
            user="retention_service",
            details=f"Purged superseded playbook version v{p.version} older than {archived_retention_days} days.",
        )
        db.add(audit)
        db.delete(p)

    db.commit()
    logger.info(f"Retention cleanup complete: {count_rejected} rejected, {count_old_versions} old versions purged.")
    return {
        "purged_rejected": count_rejected,
        "purged_old_versions": count_old_versions,
    }
