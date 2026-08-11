import sys
import os
import zipfile
import io
import pytest
from fastapi.testclient import TestClient
from datetime import datetime

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
# pyrefly: ignore [missing-import]
from database.database import Base, engine, SessionLocal

# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    
    # Ensure quality_score column exists for week21 features
    with engine.begin() as conn:
        try:
            from sqlalchemy import text
            conn.execute(text("ALTER TABLE sentinel_playbooks ADD COLUMN quality_score INTEGER DEFAULT 0"))
        except Exception:
            pass
            
    # Insert test data
    db = SessionLocal()
    try:
        # Clear existing playbooks for a clean test
        db.query(SentinelPlaybook).delete()
        db.commit()

        # Add 2 approved playbooks with rules
        pb1 = SentinelPlaybook(
            playbook_id="PB-TEST-EXP-001",
            status="approved",
            attack_type="TEST_ATTACK_1",
            snort_rule='alert tcp any any -> any 80 (msg:"Test Snort 1"; sid:1;)',
            sigma_rule='title: Test Sigma 1\nstatus: stable\nlogsource:\n  category: network_traffic',
            is_latest=True
        )
        pb2 = SentinelPlaybook(
            playbook_id="PB-TEST-EXP-002",
            status="approved",
            attack_type="TEST_ATTACK_2",
            snort_rule='alert tcp any any -> any 443 (msg:"Test Snort 2"; sid:2;)',
            sigma_rule='title: Test Sigma 2\nstatus: stable\nlogsource:\n  category: proxy',
            is_latest=True
        )
        # Add 1 unapproved playbook (should not be in export if approved exist, wait... 
        # API fetches approved. If none, fetches latest. We have approved, so it should only fetch approved)
        pb3 = SentinelPlaybook(
            playbook_id="PB-TEST-EXP-003",
            status="pending",
            attack_type="TEST_ATTACK_3",
            snort_rule='alert tcp any any -> any 22 (msg:"Test Snort 3"; sid:3;)',
            is_latest=True
        )
        
        db.add_all([pb1, pb2, pb3])
        db.commit()
    finally:
        db.close()
    
    yield


def test_export_all_rules_zip_structure_and_content():
    """
    Test that the /rules/export-all endpoint correctly generates a ZIP file
    containing Snort, Sigma, and README files, and that the contents are correct.
    """
    response = client.get("/api/sentinel/rules/export-all")
    
    # Check headers
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert "attachment; filename=phantomnet_rules_export.zip" in response.headers["content-disposition"]
    
    # Read the ZIP file from the response content
    zip_stream = io.BytesIO(response.content)
    with zipfile.ZipFile(zip_stream, "r") as zf:
        file_list = zf.namelist()
        
        # Verify required files exist in the ZIP
        assert "README.txt" in file_list
        assert "phantomnet_snort_rules.rules" in file_list
        assert "phantomnet_sigma_rules.yml" in file_list
        
        # Verify README content
        readme_content = zf.read("README.txt").decode("utf-8")
        assert "PhantomNet Sentinel Export" in readme_content
        assert "Total Playbooks: 2" in readme_content # pb3 is pending, so shouldn't be included
        
        # Verify Snort rules content
        snort_content = zf.read("phantomnet_snort_rules.rules").decode("utf-8")
        assert 'alert tcp any any -> any 80 (msg:"Test Snort 1"; sid:1;)' in snort_content
        assert 'alert tcp any any -> any 443 (msg:"Test Snort 2"; sid:2;)' in snort_content
        assert 'Test Snort 3' not in snort_content # Pending rule should not be present
        assert "# Playbook PB-TEST-EXP-001 (TEST_ATTACK_1)" in snort_content
        
        # Verify Sigma rules content
        sigma_content = zf.read("phantomnet_sigma_rules.yml").decode("utf-8")
        assert "title: Test Sigma 1" in sigma_content
        assert "title: Test Sigma 2" in sigma_content
        assert "---" in sigma_content # YAML document separator


def test_export_all_rules_fallback_to_latest():
    """
    Test that if no 'approved' playbooks exist, it falls back to 'is_latest=True'
    """
    # First, make all playbooks pending
    db = SessionLocal()
    try:
        db.query(SentinelPlaybook).update({"status": "pending"})
        db.commit()
    finally:
        db.close()
        
    response = client.get("/api/sentinel/rules/export-all")
    assert response.status_code == 200
    
    zip_stream = io.BytesIO(response.content)
    with zipfile.ZipFile(zip_stream, "r") as zf:
        # README should show 3 playbooks because all 3 have is_latest=True
        readme_content = zf.read("README.txt").decode("utf-8")
        assert "Total Playbooks: 3" in readme_content
        
        # Snort 3 should now be included
        snort_content = zf.read("phantomnet_snort_rules.rules").decode("utf-8")
        assert 'Test Snort 3' in snort_content
