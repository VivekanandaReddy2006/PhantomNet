"""
Verify Sentinel API — Week 14 Day 2 — 10-point test suite.

Tests:
  1. Router module imports correctly
  2. Router has correct prefix and tags
  3. All 5 route paths registered
  4. GET /playbooks returns paginated list
  5. GET /playbooks/{id} returns 404 for missing
  6. GET /stats returns correct structure
  7. GET /mitre/mapping returns all 12 techniques
  8. POST /generate creates a playbook
  9. Router registered in main.py import
 10. Router included in main.py app
"""
import sys
sys.path.insert(0, "backend")

# Ensure tables exist
from database.database import engine, SessionLocal
from database.models import Base
from sentinel.models import SentinelPlaybook as _SP  # noqa: F401
Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------
# Test 1: Module imports
# ------------------------------------------------------------------
from api.sentinel import router, list_playbooks, get_playbook, get_sentinel_stats, get_mitre_mappings, generate_playbook
print("Test 1  PASS: api.sentinel module imports correctly")

# ------------------------------------------------------------------
# Test 2: Router prefix & tags
# ------------------------------------------------------------------
assert router.prefix == "/api/sentinel", f"Expected prefix '/api/sentinel', got '{router.prefix}'"
assert "Sentinel" in router.tags, f"Expected 'Sentinel' in tags, got {router.tags}"
print("Test 2  PASS: Router prefix=/api/sentinel, tags=['Sentinel']")

# ------------------------------------------------------------------
# Test 3: All 5 route paths registered
# ------------------------------------------------------------------
route_paths = [r.path for r in router.routes]
expected_paths = [
    "/api/sentinel/playbooks",
    "/api/sentinel/playbooks/{playbook_id}",
    "/api/sentinel/stats",
    "/api/sentinel/mitre/mapping",
    "/api/sentinel/generate",
]
for ep in expected_paths:
    assert ep in route_paths, f"Missing route: {ep}"
print(f"Test 3  PASS: All 5 routes registered: {expected_paths}")

# ------------------------------------------------------------------
# Test 4: GET /playbooks works (via direct function call)
# ------------------------------------------------------------------
db = SessionLocal()
try:
    result = list_playbooks(limit=10, offset=0, status=None, attack_type=None, db=db)
    assert result["status"] == "success"
    assert "total" in result
    assert "playbooks" in result
    assert isinstance(result["playbooks"], list)
    assert "limit" in result
    assert "offset" in result
    print(f"Test 4  PASS: GET /playbooks returns paginated list (total={result['total']})")
finally:
    pass

# ------------------------------------------------------------------
# Test 5: GET /playbooks/{id} returns 404 for missing
# ------------------------------------------------------------------
from fastapi import HTTPException
try:
    get_playbook(playbook_id=999999, db=db)
    assert False, "Should have raised HTTPException"
except HTTPException as exc:
    assert exc.status_code == 404
    print("Test 5  PASS: GET /playbooks/999999 returns 404")

# ------------------------------------------------------------------
# Test 6: GET /stats returns correct structure
# ------------------------------------------------------------------
stats = get_sentinel_stats(db=db)
assert stats["status"] == "success"
assert "total_playbooks" in stats
assert "pending" in stats
assert "approved" in stats
assert "rejected" in stats
assert "avg_threat_score" in stats
assert "top_attack_types" in stats
print(f"Test 6  PASS: GET /stats returns correct structure (total={stats['total_playbooks']})")

# ------------------------------------------------------------------
# Test 7: GET /mitre/mapping returns all 12 techniques
# ------------------------------------------------------------------
mitre = get_mitre_mappings()
assert mitre["status"] == "success"
assert mitre["total"] == 12, f"Expected 12 techniques, got {mitre['total']}"
assert len(mitre["mappings"]) == 12
# Verify structure of first mapping
first = mitre["mappings"][0]
assert "technique_id" in first
assert "technique_name" in first
assert "tactic" in first
assert "severity" in first
assert "signature" in first
print(f"Test 7  PASS: GET /mitre/mapping returns all 12 techniques")

# ------------------------------------------------------------------
# Test 8: POST /generate creates a playbook
# ------------------------------------------------------------------
from api.sentinel import GenerateRequest
req = GenerateRequest(
    source_ips=["10.0.0.50"],
    target_ports=[2222],
    protocols=["TCP"],
    event_count=100,
    campaign_id="TEST-API-001",
)
gen_result = generate_playbook(request=req, db=db)
assert gen_result["status"] == "success"
assert gen_result["playbook_id"].startswith("PB-")
assert gen_result["service_type"] == "SSH"
assert gen_result["attack_type"] == "SSH_AUTH_FAILURE"
assert gen_result["db_record_id"] > 0
pb_id = gen_result["playbook_id"]
print(f"Test 8  PASS: POST /generate creates playbook (id={pb_id})")

# Cleanup generated playbook
row = db.query(_SP).filter_by(playbook_id=pb_id).first()
if row:
    db.delete(row)
    db.commit()

# ------------------------------------------------------------------
# Test 9: Router imported in main.py
# ------------------------------------------------------------------
import importlib
main_source = open("backend/main.py", "r", encoding="utf-8").read()
assert "from api.sentinel import router as sentinel_router" in main_source
print("Test 9  PASS: Router imported in main.py")

# ------------------------------------------------------------------
# Test 10: Router included in main.py
# ------------------------------------------------------------------
assert "app.include_router(sentinel_router)" in main_source
print("Test 10 PASS: Router included in main.py app")

db.close()

print()
print("=" * 55)
print("ALL 10 TESTS PASSED — Sentinel API W14D2 verified!")
print("=" * 55)
