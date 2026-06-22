"""
Verify SentinelService — Week 14 Day 1 — 12-point test suite.

Tests:
  1. Port-to-service mapping
  2. Default signature mapping
  3. Playbook ID format
  4. Instantiation with DB session
  5. Service inference
  6. generate_playbook callable
  7. Full pipeline returns SentinelPlaybook ORM object
  8. DB row persisted correctly
  9. result_dict attached with all artefacts
 10. IOC query integration
 11. create_and_run classmethod (session lifecycle)
 12. Multi-protocol campaign (HTTP)
"""
import sys
sys.path.insert(0, "backend")

from sentinel.sentinel_service import (
    SentinelService,
    _PORT_SERVICE_MAP,
    _SERVICE_DEFAULT_SIGNATURE,
    _generate_playbook_id,
)
from sentinel.models import SentinelPlaybook

# Ensure tables exist
from database.database import engine, SessionLocal
from database.models import Base
from sentinel.models import SentinelPlaybook as _SP  # noqa: F401
Base.metadata.create_all(bind=engine)


# Test 1: Port mapping
assert _PORT_SERVICE_MAP[2222] == "SSH"
assert _PORT_SERVICE_MAP[8080] == "HTTP"
assert _PORT_SERVICE_MAP[2121] == "FTP"
assert _PORT_SERVICE_MAP[2525] == "SMTP"
print("Test 1  PASS: Port-to-service mapping correct")

# Test 2: Default signatures
assert _SERVICE_DEFAULT_SIGNATURE["SSH"] == "SSH_AUTH_FAILURE"
assert _SERVICE_DEFAULT_SIGNATURE["HTTP"] == "HTTP_SCANNER_BEHAVIOR"
assert _SERVICE_DEFAULT_SIGNATURE["FTP"] == "FTP_DATA_EXFILTRATION"
assert _SERVICE_DEFAULT_SIGNATURE["SMTP"] == "SMTP_LARGE_PAYLOAD"
print("Test 2  PASS: Default signature mapping correct")

# Test 3: Playbook ID format
pb_id = _generate_playbook_id()
assert pb_id.startswith("PB-")
assert len(pb_id) == 25
print(f"Test 3  PASS: Playbook ID generated: {pb_id}")

# Test 4: Instantiation
db = SessionLocal()
svc = SentinelService(db)
assert svc.db is db
assert svc.sig_engine is not None
print("Test 4  PASS: SentinelService instantiated with DB session")

# Test 5: Service inference
assert svc._infer_service([2222]) == "SSH"
assert svc._infer_service([8080]) == "HTTP"
assert svc._infer_service([2121]) == "FTP"
assert svc._infer_service([2525]) == "SMTP"
assert svc._infer_service([9999]) == "UNKNOWN"
assert svc._infer_service([9999, 2222]) == "SSH"
print("Test 5  PASS: Service inference works correctly")

# Test 6: generate_playbook callable
assert callable(svc.generate_playbook)
print("Test 6  PASS: generate_playbook is callable")

# Test 7: Full pipeline returns SentinelPlaybook ORM object
result = svc.generate_playbook({
    "source_ips": ["10.0.0.99"],
    "target_ports": [2222],
    "protocols": ["TCP"],
    "event_count": 150,
    "campaign_id": "TEST-CAMP-001",
})
assert isinstance(result, SentinelPlaybook), \
    f"Expected SentinelPlaybook, got {type(result).__name__}"
assert result.playbook_id.startswith("PB-")
assert result.attack_type == "SSH_AUTH_FAILURE"
assert result.technique_id == "T1110.001"
assert result.tactic == "Credential Access"
assert result.status == "pending"
assert result.id > 0
pid = result.playbook_id
print(f"Test 7  PASS: Full pipeline returns SentinelPlaybook (playbook_id={pid})")

# Test 8: DB row persisted
row = db.query(SentinelPlaybook).filter_by(playbook_id=pid).first()
assert row is not None
assert row.technique_id == "T1110.001"
assert row.attack_type == "SSH_AUTH_FAILURE"
assert row.status == "pending"
assert row.snort_rule is not None and len(row.snort_rule) > 0
assert row.sigma_rule is not None and len(row.sigma_rule) > 0
assert row.playbook_content is not None and len(row.playbook_content) > 0
assert row.playbook_name is not None
print(f"Test 8  PASS: SentinelPlaybook DB row verified (id={row.id})")

# Test 9: result_dict attached with all artefacts
rd = result.result_dict
assert rd["playbook_id"] == pid
assert rd["campaign_id"] == "TEST-CAMP-001"
assert rd["service_type"] == "SSH"
assert rd["attack_type"] == "SSH_AUTH_FAILURE"
assert rd["technique"]["id"] == "T1110.001"
assert rd["technique"]["tactic"] == "Credential Access"
assert rd["snort_rule"]
assert rd["sigma_rule"]
assert rd["stix_bundle_json"]
assert rd["playbook_content"]
assert rd["playbook_name"]
assert rd["db_record_id"] > 0
assert "ioc_count" in rd
assert "ioc_threat_level" in rd
assert "matched_logs_count" in rd
assert "signatures_stored_count" in rd
assert "detected_signatures" in rd
print("Test 9  PASS: result_dict attached with all required artefacts")

# Test 10: IOC query integration
ioc_results = svc._query_iocs(["10.0.0.99"])
assert isinstance(ioc_results, list)
print(f"Test 10 PASS: IOC query integration works ({len(ioc_results)} IOCs found)")

# Cleanup test 7 row
db.delete(row)
db.commit()

# Test 11: create_and_run classmethod (session lifecycle)
playbook = SentinelService.create_and_run({
    "source_ips": ["192.168.1.50"],
    "target_ports": [8080],
    "protocols": ["TCP"],
    "event_count": 75,
    "campaign_id": "TEST-CAMP-002",
})
assert isinstance(playbook, SentinelPlaybook)
assert playbook.playbook_id.startswith("PB-")
assert playbook.technique_id is not None
assert playbook.id > 0
# Verify it was persisted (use a fresh session)
db2 = SessionLocal()
row2 = db2.query(SentinelPlaybook).filter_by(playbook_id=playbook.playbook_id).first()
assert row2 is not None
assert row2.status == "pending"
db2.delete(row2)
db2.commit()
db2.close()
print(f"Test 11 PASS: create_and_run lifecycle OK (playbook_id={playbook.playbook_id})")

# Test 12: Multi-protocol campaign (HTTP)
result_http = svc.generate_playbook({
    "source_ips": ["172.16.0.10"],
    "target_ports": [8080],
    "protocols": ["TCP"],
    "event_count": 200,
    "campaign_id": "TEST-CAMP-HTTP",
})
assert isinstance(result_http, SentinelPlaybook)
assert result_http.technique_id is not None
rd_http = result_http.result_dict
assert rd_http["service_type"] == "HTTP"
# Cleanup
db.delete(result_http)
db.commit()
print(f"Test 12 PASS: HTTP campaign pipeline OK (service=HTTP)")

db.close()

print()
print("=" * 55)
print("ALL 12 TESTS PASSED — SentinelService W14D1 verified!")
print("=" * 55)
