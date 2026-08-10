"""
backend/api/rate_limiter.py
----------------------------
Rate limiting helper and FastAPI dependency for Sentinel generation endpoints.
Prevents API resource exhaustion by enforcing maximum calls per client per hour.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, Request, status

# In-memory sliding window store: ip -> list of request datetimes
_REQUEST_HISTORY: Dict[str, List[datetime]] = defaultdict(list)

MAX_GENERATIONS_PER_HOUR = 10
WINDOW_SECONDS = 3600


def check_rate_limit(request: Request, max_requests: int = MAX_GENERATIONS_PER_HOUR) -> None:
    """
    Check if the requesting client IP has exceeded max_requests within WINDOW_SECONDS.
    Raises HTTP 429 Too Many Requests if exceeded.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)

    # Filter out requests older than cutoff window
    history = [ts for ts in _REQUEST_HISTORY[client_ip] if ts > cutoff]

    if len(history) >= max_requests:
        retry_after = int((history[0] + timedelta(seconds=WINDOW_SECONDS) - now).total_seconds())
        headers = {"Retry-After": str(max(1, retry_after))}
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} generation requests per hour allowed.",
            headers=headers,
        )

    # Record current request
    history.append(now)
    _REQUEST_HISTORY[client_ip] = history


def reset_rate_limits() -> None:
    """Utility to clear rate limit cache (for unit testing)."""
    _REQUEST_HISTORY.clear()
