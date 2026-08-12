"""
backend/sentinel/audit_logger.py
---------------------------------
Audit logging helper for PhantomNet Sentinel analyst & system operations.

Provides structured recording of analyst actions (approve, reject, regenerate,
export, batch operations) and system processes into the ``sentinel_audit_logs`` table.
"""

from datetime import datetime
import json
import logging
from typing import Any, Dict, Optional, Union
from sqlalchemy.orm import Session

from sentinel.models import SentinelAuditLog

logger = logging.getLogger("sentinel.audit_logger")


def log_audit_event(
    db: Session,
    action: str,
    user: str = "system",
    playbook_id: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    commit: bool = False,
) -> SentinelAuditLog:
    """
    Record an audit log entry in the database.

    Args:
        db: SQLAlchemy Session.
        action: Audit action label (e.g. approve, reject, batch_approve, batch_reject, export, regenerate, generate).
        user: Username or service name initiating the action.
        playbook_id: Optional human-readable playbook identifier.
        details: Optional dictionary or string of event metadata.
        commit: Whether to commit immediately or defer to the caller's transaction.

    Returns:
        SentinelAuditLog instance.
    """
    if isinstance(details, (dict, list)):
        details_str = json.dumps(details)
    else:
        details_str = str(details) if details is not None else None

    log_entry = SentinelAuditLog(
        action=action,
        user=user,
        playbook_id=playbook_id,
        details=details_str,
        timestamp=datetime.utcnow(),
    )
    db.add(log_entry)

    if commit:
        try:
            db.commit()
            db.refresh(log_entry)
        except Exception as exc:
            db.rollback()
            logger.error("Failed to commit audit log entry: %s", exc)

    logger.info("Audit log recorded: action=%s user=%s playbook_id=%s", action, user, playbook_id)
    return log_entry
