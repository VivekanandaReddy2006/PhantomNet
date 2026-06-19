"""Verify SentinelService — 8-point test suite."""
import sys
sys.path.insert(0, "backend")

from sentinel.sentinel_service import (
    SentinelService,
    _PORT_SERVICE_MAP,
    _SERVICE_DEFAULT_SIGNATURE,
    _generate_playbook_id,
)

# Ensure tables exist
from database.database import engine
from database.models import Base
from sentinel.models import SentinelPlaybook as _SP  # noqa: F401
Base.metadata.create_all(bind=engine)


# Test 1: Port mapping
assert _PORT_SERVICE_MAP[2222] == "SSH"
assert _PORT_SERVICE_MAP[8080] == "HTTP"
assert _PORT_SERVICE_MAP[2121] == "FTP"
assert _PORT_SERVICE_MAP[2525] == "SMTP"
print("Test 1 PASS: Port-to-service mapping correct")

# Test 2: Default signatures
assert _SERVICE_DEFAULT_SIGNATURE["SSH"] == "SSH_AUTH_FAILURE"
assert _SERVICE_DEFAULT_SIGNATURE["HTTP"] == "HTTP_SCANNER_BEHAVIOR"
assert _SERVICE_DEFAULT_SIGNATURE["FTP"] == "FTP_DATA_EXFILTRATION"
assert _SERVICE_DEFAULT_SIGNATURE["SMTP"] == "SMTP_LARGE_PAYLOAD"
print("Test 2 PASS: Default signature mapping correct")

# Test 3: Playbook ID format
pb_id = _generate_playbook_id()
assert pb_id.startswith("PB-")
assert len(pb_id) == 25
print(f"Test 3 PASS: Playbook ID generated: {pb_id}")

# Test 4: Instantiation
from database.database import SessionLocal
db = SessionLocal()
svc = SentinelService(db)
assert svc.db is db
assert svc.sig_engine is not None
print("Test 4 PASS: SentinelService instantiated with DB session")

# Test 5: Service inference
assert svc._infer_service([2222]) == "SSH"
assert svc._infer_service([8080]) == "HTTP"
assert svc._infer_service([2121]) == "FTP"
assert svc._infer_service([2525]) == "SMTP"
assert svc._infer_service([9999]) == "UNKNOWN"
assert svc._infer_service([9999, 2222]) == "SSH"
print("Test 5 PASS: Service inference works correctly")

# Test 6: generate_playbook callable
assert callable(svc.generate_playbook)
print("Test 6 PASS: generate_playbook is callable")

# Test 7: Full pipeline
result = svc.generate_playbook({
    "source_ips": ["10.0.0.99"],
    "target_ports": [2222],
    "protocols": ["TCP"],
    "event_count": 150,
    "campaign_id": "TEST-CAMP-001",
})
assert result["playbook_id"].startswith("PB-")
assert result["service_type"] == "SSH"
assert result["attack_type"] == "SSH_AUTH_FAILURE"
assert result["technique"]["id"] == "T1110.001"
assert result["technique"]["tactic"] == "Credential Access"
assert result["snort_rule"]
assert result["sigma_rule"]
assert result["stix_bundle_json"]
assert result["playbook_content"]
assert result["playbook_name"]
assert result["db_record_id"] > 0
pid = result["playbook_id"]
print(f"Test 7 PASS: Full pipeline OK (playbook_id={pid})")

# Test 8: DB row persisted
from sentinel.models import SentinelPlaybook
row = db.query(SentinelPlaybook).filter_by(playbook_id=pid).first()
assert row is not None
assert row.technique_id == "T1110.001"
assert row.attack_type == "SSH_AUTH_FAILURE"
assert row.status == "pending"
print(f"Test 8 PASS: SentinelPlaybook DB row verified (id={row.id})")

# Cleanup
db.delete(row)
db.commit()
db.close()

print()
print("=" * 50)
print("ALL 8 TESTS PASSED — SentinelService verified!")
print("=" * 50)
