import sys
import os
import json

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# pyrefly: ignore [missing-import]
from database.database import Base, engine, SessionLocal
# pyrefly: ignore [missing-import]
from sentinel.sentinel_service import SentinelService
import logging

logging.basicConfig(level=logging.INFO)

# Set up the DB
Base.metadata.create_all(bind=engine)
with engine.begin() as conn:
    try:
        from sqlalchemy import text
        conn.execute(text("ALTER TABLE sentinel_playbooks ADD COLUMN quality_score INTEGER DEFAULT 0"))
    except Exception:
        pass

def main():
    campaign_data = {
        "source_ips": ["192.168.1.100"],
        "target_ports": [22],
        "protocols": ["TCP"],
        "event_count": 50,
        "campaign_id": "CAMP-TEST-CVE"
    }

    print("Running generate_playbook...")
    playbook = SentinelService.create_and_run(campaign_data)
    
    print("\n\n--- RESULTS ---")
    print(f"Playbook ID: {playbook.playbook_id}")
    print(f"Attack Type: {playbook.attack_type}")
    
    result_dict = playbook.result_dict
    cve_ids = result_dict.get("cve_ids", [])
    print(f"Extracted CVE IDs: {cve_ids}")
    
    # Check STIX bundle for CVEs
    stix_json = result_dict.get("stix_bundle_json")
    stix_bundle = json.loads(stix_json)
    
    cves_in_stix = 0
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "cve":
                    cves_in_stix += 1
                    
    print(f"CVEs embedded in STIX AttackPattern: {cves_in_stix}")
    
    # Check if CVE text is in the playbook content
    if "CVE References" in playbook.playbook_content:
        print("CVE References section found in Playbook Content! ✓")
    else:
        print("CVE References section NOT found in Playbook Content! ✗")

if __name__ == "__main__":
    main()
