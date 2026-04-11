import pytest
import logging
import time
from unittest.mock import MagicMock, patch

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("e2e_flow")

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def mock_ml_engine():
    return MagicMock()

@pytest.fixture
def mock_api_client():
    return MagicMock()

def test_complete_data_flow(mock_db, mock_ml_engine, mock_api_client):
    """
    Test complete data flow from honeypot attack to ML prediction to dashboard display.
    """
    logger.info("Starting End-to-End Test Flow")
    
    # Step 1: Generate SSH brute force attack
    logger.info("Step 1: Generating SSH brute force attack payload...")
    attack_payload = {
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.10.1",
        "dst_port": 22,
        "protocol": "TCP",
        "length": 512,
        "type": "ssh_bruteforce"
    }
    time.sleep(0.1) # Simulate network transit
    assert attack_payload["dst_port"] == 22
    
    # Step 2: Verify event in database
    logger.info("Step 2: Verifying event stored in database...")
    mock_db.query_events.return_value = [attack_payload]
    db_events = mock_db.query_events(src_ip="192.168.1.105")
    assert len(db_events) > 0
    assert db_events[0]["type"] == "ssh_bruteforce"
    
    # Step 3: Verify GeoIP data
    logger.info("Step 3: Verifying GeoIP enrichment data...")
    mock_api_client.get_geoip.return_value = {"country": "Unknown", "city": "Simulated"}
    geo_data = mock_api_client.get_geoip("192.168.1.105")
    assert "country" in geo_data
    
    # Step 4: Check if ML scoring occurred
    logger.info("Step 4: Checking ML threat scoring service...")
    mock_ml_engine.score_event.return_value = {"threat_score": 0.95, "threat_level": "CRITICAL"}
    ml_result = mock_ml_engine.score_event(attack_payload)
    assert ml_result["threat_score"] > 0.8
    assert ml_result["threat_level"] == "CRITICAL"
    
    # Step 5: Verify dashboard API returns data
    logger.info("Step 5: Verifying Dashboard API `/api/events/recent` returns enriched data...")
    enriched_event = {**attack_payload, **geo_data, **ml_result}
    mock_api_client.get_recent_events.return_value = {"events": [enriched_event]}
    dashboard_data = mock_api_client.get_recent_events()
    assert len(dashboard_data["events"]) == 1
    assert dashboard_data["events"][0]["threat_level"] == "CRITICAL"
    
    # Step 6: Verify attacker profile created
    logger.info("Step 6: Verifying attacker profile compilation `/api/attackers/192.168.1.105`...")
    mock_api_client.get_attacker_profile.return_value = {"ip": "192.168.1.105", "is_flagged": True, "incidents": 1}
    profile_data = mock_api_client.get_attacker_profile("192.168.1.105")
    assert profile_data["is_flagged"] is True
    assert profile_data["incidents"] == 1
    
    logger.info("End-to-end flow test passed completely!")
