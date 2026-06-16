import pytest
import yaml
from sentinel.playbook_generator import PlaybookGenerator

def test_playbook_generator_initialization():
    generator = PlaybookGenerator()
    assert generator is not None
    assert generator.env is not None

def test_select_template():
    generator = PlaybookGenerator()
    
    assert generator._select_template("brute_force") == "brute_force_response.yaml.j2"
    assert generator._select_template("SSH_BRUTE_FORCE_DISTRIBUTED") == "brute_force_response.yaml.j2"
    assert generator._select_template("port_scan") == "port_scan_response.yaml.j2"
    assert generator._select_template("credential_reuse") == "credential_reuse_response.yaml.j2"
    assert generator._select_template("distributed_attack") == "distributed_attack_response.yaml.j2"
    
    # Check fallback
    assert generator._select_template("custom_pattern") == "custom_pattern_response.yaml.j2"

def test_generate_brute_force():
    generator = PlaybookGenerator()
    context = {
        "attack_pattern": "brute_force",
        "source_ip": "192.168.1.100",
        "failed_logins_threshold": 30,
        "timeframe": "10 minutes",
        "timeframe_seconds": "600s",
        "block_duration": "7200",
        "tarpit_delay_ms": 3000,
        "alert_level": "CRITICAL"
    }
    
    rendered = generator.generate(context)
    assert rendered is not None
    
    # Parse as YAML to verify syntax correctness
    data = yaml.safe_load(rendered)
    assert data["name"] == "Brute Force Response"
    assert "Triggered when failed logins exceed 30" in data["description"]
    
    # Check that variables were rendered correctly
    actions = data["actions"]
    assert actions[0]["name"] == "block_attacker_ip"
    assert actions[0]["params"]["ip"] == "192.168.1.100"
    assert actions[0]["params"]["duration"] == "7200"
    
    assert actions[1]["name"] == "tarpit_connection"
    assert actions[1]["params"]["delay_ms"] == 3000
    
    assert actions[2]["params"]["level"] == "CRITICAL"

def test_generate_port_scan():
    generator = PlaybookGenerator()
    context = {
        "attack_pattern": "port_scan",
        "source_ip": "10.0.0.5",
        "port_count_threshold": 100,
        "capture_duration": "600s"
    }
    
    rendered = generator.generate(context)
    data = yaml.safe_load(rendered)
    assert data["name"] == "Port Scan Response"
    
    actions = data["actions"]
    assert actions[0]["params"]["ip"] == "10.0.0.5"
    assert actions[0]["params"]["duration"] == "600s"
    assert actions[1]["params"]["count"] == 3  # Default value check

def test_generate_missing_pattern():
    generator = PlaybookGenerator()
    with pytest.raises(ValueError, match="context_data must contain an 'attack_pattern' key"):
        generator.generate({"source_ip": "1.1.1.1"})

def test_generate_template_not_found():
    generator = PlaybookGenerator()
    with pytest.raises(FileNotFoundError, match="Template 'unknown_pattern_response.yaml.j2' not found"):
        generator.generate({"attack_pattern": "unknown_pattern"})
