"""
tests/test_week21_features.py
------------------------------
Unit and integration test suite for PhantomNet Week 21 features:
- CVE Mapping Engine
- Quality Scoring Engine
- Webhook Notifier
- Retention Cleanup Service
- API Rate Limiter
- Rule Deduplication
- Sentinel API Endpoints (Compare, Export ZIP, Timeline, Audit Logs, Templates)
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
# pyrefly: ignore [missing-import]
from database.database import Base, engine, get_db, SessionLocal
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook, SentinelAuditLog
# pyrefly: ignore [missing-import]
from sentinel.cve_mapper import get_cve_mappings
# pyrefly: ignore [missing-import]
from sentinel.quality_scorer import calculate_playbook_quality_score
# pyrefly: ignore [missing-import]
from sentinel.webhook_notifier import dispatch_webhook_alert
# pyrefly: ignore [missing-import]
from sentinel.retention_service import purge_expired_playbooks
# pyrefly: ignore [missing-import]
from sentinel.rule_generator import deduplicate_rules
# pyrefly: ignore [missing-import]
from api.rate_limiter import check_rate_limit, reset_rate_limits

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        try:
            from sqlalchemy import text
            conn.execute(text("ALTER TABLE sentinel_playbooks ADD COLUMN quality_score INTEGER DEFAULT 0"))
        except Exception:
            pass
    reset_rate_limits()
    yield


# ---------------------------------------------------------------------------
# 1. CVE Mapper Tests
# ---------------------------------------------------------------------------
def test_cve_mapper_by_attack_type():
    cves = get_cve_mappings(attack_type="HTTP_SQL_INJECTION")
    assert len(cves) > 0
    assert any(c["cve_id"] == "CVE-2023-34362" for c in cves)


def test_cve_mapper_by_technique_id():
    cves = get_cve_mappings(technique_id="T1110.001")
    assert len(cves) > 0
    assert any(c["cve_id"] == "CVE-2024-6387" for c in cves)


# ---------------------------------------------------------------------------
# 2. Quality Scorer Tests
# ---------------------------------------------------------------------------
def test_quality_scorer_complete_playbook():
    data = {
        "confidence_score": 0.95,
        "threat_score": 90.0,
        "snort_rule": 'alert tcp any any -> any 22 (msg:"Test Rule"; sid:1000001;)',
        "sigma_rule": "title: Test Rule\nlogsource:\n  category: network_traffic",
        "technique_id": "T1110.001",
        "llm_narrative": "This is an AI summary narrative describing a severe brute force attack.",
        "src_ip": "192.168.1.50",
        "severity": "CRITICAL",
    }
    score = calculate_playbook_quality_score(data)
    assert 80 <= score <= 100


def test_quality_scorer_minimal_playbook():
    data = {"confidence_score": 0.2, "threat_score": 10.0}
    score = calculate_playbook_quality_score(data)
    assert score < 50


# ---------------------------------------------------------------------------
# 3. Rule Deduplication Tests
# ---------------------------------------------------------------------------
def test_rule_deduplication():
    # 1. Identical Snort rules with DIFFERENT SIDs
    snort_1 = 'alert tcp 192.168.1.5 any -> $HOME_NET 22 (msg:"SSH Brute Force"; sid:1001;)'
    snort_2 = 'alert tcp 192.168.1.5 any -> $HOME_NET 22 (msg:"SSH Brute Force"; sid:1002;)'
    # 2. Snort rule targeting different port
    snort_3 = 'alert tcp 192.168.1.5 any -> $HOME_NET 80 (msg:"SQLi Test"; sid:1003;)'
    
    # 3. Identical Sigma rules with DIFFERENT titles
    sigma_1 = "title: 'Campaign CAMP-001 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '10.0.0.1'\n  condition: selection\nlevel: high\n"
    sigma_2 = "title: 'Campaign CAMP-002 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '10.0.0.1'\n  condition: selection\nlevel: high\n"
    # 4. Sigma rule targeting different ip
    sigma_3 = "title: 'Campaign CAMP-003 Detection'\nstatus: experimental\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    src_ip: '192.168.1.200'\n  condition: selection\nlevel: high\n"
    
    rules = [snort_1, snort_2, snort_3, sigma_1, sigma_2, sigma_3]
    
    deduped = deduplicate_rules(rules)
    
    # Expected: snort_1, snort_3, sigma_1, sigma_3 (4 unique rules)
    assert len(deduped) == 4
    
    # Check that the first occurrences are retained
    assert snort_1 in deduped
    assert snort_3 in deduped
    assert sigma_1 in deduped
    assert sigma_3 in deduped
    
    # Check that the duplicates are stripped
    assert snort_2 not in deduped
    assert sigma_2 not in deduped


# ---------------------------------------------------------------------------
# 4. Webhook Notifier Tests
# ---------------------------------------------------------------------------
def test_webhook_notifier_invalid_url():
    import asyncio
    res = asyncio.run(dispatch_webhook_alert("invalid-url", {"playbook_id": "PB-001"}))
    assert res is False



# ---------------------------------------------------------------------------
# 5. Retention Service Tests
# ---------------------------------------------------------------------------
def test_retention_service_purge():
    db = SessionLocal()
    try:
        # Create a test rejected playbook
        pb = SentinelPlaybook(
            playbook_id="PB-TEST-RETENTION-01",
            status="rejected",
            attack_type="TEST_ATTACK",
            confidence_score=0.1,
            severity="LOW",
        )
        db.add(pb)
        db.commit()

        # Run purge with 0 days retention to force cleanup
        res = purge_expired_playbooks(db, rejected_retention_days=0, archived_retention_days=0)
        assert res["purged_rejected"] >= 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 6. REST API Endpoints Tests
# ---------------------------------------------------------------------------
def test_compare_playbooks_api():
    import uuid
    uid = uuid.uuid4().hex[:6]
    db = SessionLocal()
    try:
        pb1 = SentinelPlaybook(
            playbook_id=f"PB-CMP1-{uid}",
            attack_type="SSH_AUTH_FAILURE",
            technique_id="T1110.001",
            confidence_score=0.8,
            severity="HIGH",
            status="approved",
        )
        pb2 = SentinelPlaybook(
            playbook_id=f"PB-CMP2-{uid}",
            attack_type="HTTP_SQL_INJECTION",
            technique_id="T1190",
            confidence_score=0.9,
            severity="CRITICAL",
            status="approved",
        )
        db.add_all([pb1, pb2])
        db.commit()
        id1, id2 = pb1.id, pb2.id
    finally:
        db.close()

    res = client.get(f"/api/sentinel/playbooks/compare?id1={id1}&id2={id2}")
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["status"] == "success"
    assert "comparison" in json_data
    assert json_data["comparison"]["diff_summary"]["attack_type_match"] is False


def test_export_all_rules_api():
    res = client.get("/api/sentinel/rules/export-all")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"


def test_campaign_timeline_api():
    res = client.get("/api/sentinel/campaigns/CMP-2026-001/timeline")
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["status"] == "success"
    assert "timeline" in json_data


def test_audit_logs_api():
    res = client.get("/api/sentinel/audit-logs")
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["status"] == "success"
    assert "logs" in json_data


def test_templates_api():
    res = client.get("/api/sentinel/templates")
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["status"] == "success"
    assert isinstance(json_data["templates"], list)


def test_template_preview_api():
    payload = {
        "template_name": "ssh_brute_force.j2",
        "context": {
            "playbook_id": "PB-TEST-PREVIEW",
            "src_ip": "10.0.0.1",
            "dst_port": 22,
            "attack_type": "SSH_AUTH_FAILURE",
            "technique_id": "T1110.001",
            "technique_name": "Password Guessing",
        },
    }
    res = client.post("/api/sentinel/templates/preview", json=payload)
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["status"] == "success"
    assert "rendered_content" in json_data


def test_export_playbook_audit_history():
    import uuid
    uid = uuid.uuid4().hex[:6]
    db = SessionLocal()
    try:
        pb = SentinelPlaybook(
            playbook_id=f"PB-AUDIT-{uid}",
            attack_type="HTTP_SQL_INJECTION",
            technique_id="T1190",
            confidence_score=0.95,
            severity="CRITICAL",
            status="approved",
        )
        db.add(pb)
        db.commit()
        pb_id = pb.id
    finally:
        db.close()

    # Perform export in JSON format
    res_export = client.post(f"/api/sentinel/playbooks/{pb_id}/export?format=json")
    assert res_export.status_code == 200

    # Perform export in PDF format
    res_pdf = client.post(f"/api/sentinel/playbooks/{pb_id}/export/pdf")
    assert res_pdf.status_code == 200

    # Fetch export history endpoint
    res_history = client.get(f"/api/sentinel/playbooks/{pb_id}/export-history")
    assert res_history.status_code == 200
    history_data = res_history.json()
    assert history_data["status"] == "success"
    assert history_data["total"] >= 2
    assert any("pdf" in str(log.get("details", "")).lower() for log in history_data["export_history"])
    assert any("json" in str(log.get("details", "")).lower() for log in history_data["export_history"])

    # Query filtered audit logs
    res_filtered = client.get(f"/api/sentinel/audit-logs?playbook_id={pb_id}&action=export")
    assert res_filtered.status_code == 200
    assert len(res_filtered.json()["logs"]) >= 2

