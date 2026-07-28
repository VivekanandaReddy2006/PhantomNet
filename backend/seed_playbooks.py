"""Seed realistic playbooks into the database for dashboard testing using SentinelService."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.database import SessionLocal
from sentinel.sentinel_service import SentinelService

db = SessionLocal()
svc = SentinelService(db)

campaigns = [
    {
        "source_ips": ["192.168.1.105"],
        "target_ports": [22],
        "protocols": ["TCP"],
        "event_count": 142,
        "campaign_id": "CAMP-01",
        "time_range": None
    },
    {
        "source_ips": ["10.0.1.15"],
        "target_ports": [445],
        "protocols": ["TCP"],
        "event_count": 87,
        "campaign_id": "CAMP-02",
        "time_range": None
    },
    {
        "source_ips": ["10.0.3.42"],
        "target_ports": [8080],
        "protocols": ["TCP"],
        "event_count": 53,
        "campaign_id": "CAMP-03",
        "time_range": None
    },
    {
        "source_ips": ["10.0.5.22"],
        "target_ports": [53],
        "protocols": ["UDP"],
        "event_count": 214,
        "campaign_id": "CAMP-04",
        "time_range": None
    }
]

print("Generating playbooks in database...")
for camp in campaigns:
    try:
        pb = svc.generate_playbook(camp)
        # Randomize status to get draft, approved, rejected
        res = pb.result_dict
        print(f"Generated playbook: {res['playbook_id']} (DB ID: {res['db_record_id']}) for {camp['source_ips']}")
    except Exception as e:
        print(f"Failed to generate: {e}")

db.close()
print("Done seeding playbooks.")
