import os
import sys
import pytest
from datetime import datetime

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from sentinel.models import SentinelPlaybook
from database.models import IOC
from database.database import Base, engine, SessionLocal
from api.sentinel import router as sentinel_router

from fastapi import FastAPI
from fastapi.testclient import TestClient

app = FastAPI()
app.include_router(sentinel_router)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Clean prior test data
    db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id.like("PB-COMPARE-%")).delete(synchronize_session=False)
    db.query(IOC).filter(IOC.value.like("10.10.10.%")).delete(synchronize_session=False)
    db.commit()

    pb1 = SentinelPlaybook(
        playbook_id="PB-COMPARE-001",
        status="approved",
        tactic="Credential Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        dst_port=22,
        protocol="TCP",
        src_ip="10.10.10.1",
        attack_type="SSH_BRUTE_FORCE",
        threat_score=85.0,
        confidence_score=0.9,
        severity="HIGH",
        snort_rule="alert tcp any any -> any 22 (msg:\"SSH Brute\"; sid:100;)",
        sigma_rule="title: SSH Brute Force",
        playbook_name="SSH Brute Force Response",
        playbook_content="## Playbook: SSH Brute Force\nBlock source IP.",
        created_at=datetime(2026, 3, 15, 10, 0, 0),
        updated_at=datetime(2026, 3, 15, 10, 0, 0),
    )
    pb2 = SentinelPlaybook(
        playbook_id="PB-COMPARE-002",
        status="pending",
        tactic="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        dst_port=80,
        protocol="TCP",
        src_ip="10.10.10.2",
        attack_type="SQL_INJECTION",
        threat_score=92.0,
        confidence_score=0.75,
        severity="CRITICAL",
        snort_rule="alert tcp any any -> any 80 (msg:\"SQLi\"; sid:200;)",
        sigma_rule="title: SQL Injection",
        playbook_name="Web Exploit Detection",
        playbook_content="## Playbook: Web Exploit\nAnalyze HTTP payloads.",
        created_at=datetime(2026, 6, 20, 14, 30, 0),
        updated_at=datetime(2026, 6, 20, 14, 30, 0),
    )
    db.add_all([pb1, pb2])
    db.commit()
    db.refresh(pb1)
    db.refresh(pb2)

    # Add IOCs
    ioc1 = IOC(type="IP", value="10.10.10.1")
    ioc2 = IOC(type="IP", value="10.10.10.1") # Total 3 IOCs for pb1 (including src_ip itself)
    db.add_all([ioc1, ioc2])
    db.commit()
    
    yield
    
    db = SessionLocal()
    db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id.like("PB-COMPARE-%")).delete(synchronize_session=False)
    db.query(IOC).filter(IOC.value.like("10.10.10.%")).delete(synchronize_session=False)
    db.commit()
    db.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_compare_playbooks_success(client):
    db = SessionLocal()
    pb1 = db.query(SentinelPlaybook).filter_by(playbook_id="PB-COMPARE-001").first()
    pb2 = db.query(SentinelPlaybook).filter_by(playbook_id="PB-COMPARE-002").first()
    db.close()

    res = client.get(f"/api/sentinel/playbooks/compare?id1={pb1.id}&id2={pb2.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    
    diff = data["comparison"]["diff_summary"]
    assert diff["attack_type_match"] is False
    assert diff["technique_match"] is False
    assert diff["severity_match"] is False
    assert diff["confidence_diff"] == 0.15
    assert diff["snort_rules_identical"] is False
    assert diff["sigma_rules_identical"] is False
    assert diff["ioc_count_1"] == 3
    assert diff["ioc_count_2"] == 1
    assert diff["ioc_count_diff"] == 2


def test_compare_playbooks_identical(client):
    db = SessionLocal()
    pb1 = db.query(SentinelPlaybook).filter_by(playbook_id="PB-COMPARE-001").first()
    db.close()

    res = client.get(f"/api/sentinel/playbooks/compare?id1={pb1.id}&id2={pb1.id}")
    assert res.status_code == 200
    data = res.json()
    
    diff = data["comparison"]["diff_summary"]
    assert diff["attack_type_match"] is True
    assert diff["technique_match"] is True
    assert diff["severity_match"] is True
    assert diff["confidence_diff"] == 0.0
    assert diff["snort_rules_identical"] is True
    assert diff["sigma_rules_identical"] is True
    assert diff["ioc_count_diff"] == 0


def test_compare_playbooks_not_found(client):
    res = client.get("/api/sentinel/playbooks/compare?id1=999999&id2=999998")
    assert res.status_code == 404
    assert res.json()["detail"] == "One or both playbooks not found"
