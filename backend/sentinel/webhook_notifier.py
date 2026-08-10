"""
backend/sentinel/webhook_notifier.py
--------------------------------------
Asynchronous webhook dispatcher for sending CRITICAL severity incident notifications
to external SOC channels (Slack, Microsoft Teams, Splunk, custom webhooks).
"""

import logging
from typing import Any, Dict, Optional
import httpx

logger = logging.getLogger("sentinel.webhook_notifier")


async def dispatch_webhook_alert(
    webhook_url: str,
    playbook_data: Dict[str, Any],
    timeout: float = 10.0,
) -> bool:
    """
    Send an HTTP POST alert payload to a configured webhook URL.

    Args:
        webhook_url: Destination URL.
        playbook_data: Dict representation of the generated/approved CRITICAL playbook.
        timeout: Maximum HTTP timeout in seconds.

    Returns:
        bool: True if POST returned 2xx status code, False otherwise.
    """
    if not webhook_url or not webhook_url.startswith(("http://", "https://")):
        logger.warning(f"Invalid webhook URL provided: {webhook_url}")
        return False

    payload = {
        "event_type": "SENTINEL_CRITICAL_INCIDENT",
        "playbook_id": playbook_data.get("playbook_id"),
        "severity": playbook_data.get("severity", "CRITICAL"),
        "attack_type": playbook_data.get("attack_type"),
        "src_ip": playbook_data.get("src_ip"),
        "dst_port": playbook_data.get("dst_port"),
        "technique_id": playbook_data.get("technique_id"),
        "technique_name": playbook_data.get("technique_name"),
        "confidence_score": playbook_data.get("confidence_score"),
        "quality_score": playbook_data.get("quality_score"),
        "playbook_name": playbook_data.get("playbook_name"),
        "created_at": playbook_data.get("created_at"),
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json", "User-Agent": "PhantomNet-Sentinel/3.0"},
            )
            response.raise_for_status()
            logger.info(f"Webhook alert successfully delivered for {playbook_data.get('playbook_id')} to {webhook_url}")
            return True
    except Exception as exc:
        logger.error(f"Failed to deliver webhook alert to {webhook_url}: {exc}")
        return False
