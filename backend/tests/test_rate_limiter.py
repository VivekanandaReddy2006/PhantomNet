import pytest
from fastapi import HTTPException, Request
from unittest.mock import MagicMock

from api.rate_limiter import (
    check_rate_limit, 
    reset_rate_limits, 
    get_rate_limit_status,
    MAX_GENERATIONS_PER_HOUR
)

@pytest.fixture(autouse=True)
def setup():
    reset_rate_limits()
    yield
    reset_rate_limits()

def get_mock_request(ip="192.168.1.100"):
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = ip
    return request

def test_rate_limit_allows_under_max():
    req = get_mock_request()
    for _ in range(MAX_GENERATIONS_PER_HOUR - 1):
        check_rate_limit(req)
        
    # Should not raise exception on the last allowed request
    check_rate_limit(req)
    
def test_rate_limit_blocks_over_max():
    req = get_mock_request()
    for _ in range(MAX_GENERATIONS_PER_HOUR):
        check_rate_limit(req)
        
    with pytest.raises(HTTPException) as exc:
        check_rate_limit(req)
        
    assert exc.value.status_code == 429
    assert "Rate limit exceeded" in str(exc.value.detail)
    assert "Retry-After" in exc.value.headers

def test_rate_limit_status():
    req1 = get_mock_request("10.0.0.1")
    req2 = get_mock_request("10.0.0.2")
    
    check_rate_limit(req1)
    check_rate_limit(req1)
    check_rate_limit(req2)
    
    status = get_rate_limit_status()
    assert status["active_ips_tracked"] == 2
    assert "10.0.0.1" in status["limits"]
    assert status["limits"]["10.0.0.1"]["count"] == 2
    assert status["limits"]["10.0.0.2"]["count"] == 1
    assert "reset_in_seconds" in status["limits"]["10.0.0.1"]
    assert status["limits"]["10.0.0.1"]["limit"] == MAX_GENERATIONS_PER_HOUR
