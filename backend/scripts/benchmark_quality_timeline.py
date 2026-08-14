import os
import sys
import time
import logging
import random
from datetime import datetime, timedelta

# Ensure absolute path to the backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.database import SessionLocal, engine
from database.models import PacketLog
from sentinel.quality_scorer import calculate_playbook_quality_score
from api.sentinel import get_campaign_timeline

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("Benchmark")

def benchmark_quality_scoring():
    logger.info("="*50)
    logger.info(" BENCHMARKING QUALITY SCORING (1,000+ Records)")
    logger.info("="*50)
    
    # Simulate 1,000 playbook data dictionaries
    playbooks = []
    for i in range(1200):
        playbooks.append({
            "confidence_score": random.uniform(0.1, 1.0),
            "threat_score": random.uniform(0.0, 100.0),
            "ioc_count": random.randint(0, 10),
            "event_count": random.randint(10, 500),
            "snort_rule": "alert tcp any any -> any any (msg:\"Test\"; sid:1;)" if random.choice([True, False]) else "",
            "sigma_rule": "title: Test Sigma Rule" if random.choice([True, False]) else "",
            "technique_id": f"T{random.randint(1000, 1500)}",
            "llm_narrative": "Attack detected.",
            "src_ip": f"192.168.1.{i%255}",
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        })
        
    start_time = time.time()
    for pb in playbooks:
        calculate_playbook_quality_score(pb)
    end_time = time.time()
    
    logger.info(f"Processed {len(playbooks)} records in {end_time - start_time:.4f} seconds.")
    logger.info(f"Throughput: {len(playbooks) / (end_time - start_time):.2f} records/sec")

def benchmark_timeline_api():
    logger.info("\n" + "="*50)
    logger.info(" BENCHMARKING TIMELINE API (10,000+ Packet Logs)")
    logger.info("="*50)
    
    db = SessionLocal()
    
    try:
        # Clear existing logs for consistent benchmark
        db.query(PacketLog).delete()
        db.commit()
        
        logger.info("Seeding database with 10,000+ packet logs...")
        logs = []
        base_time = datetime.utcnow()
        for i in range(10500):
            # Spread over 24 hours
            log_time = base_time - timedelta(minutes=random.randint(0, 1440))
            logs.append(PacketLog(
                timestamp=log_time,
                src_ip=f"10.0.0.{random.randint(1, 255)}",
                dst_ip="192.168.1.100",
                src_port=random.randint(1024, 65535),
                dst_port=22 if random.random() < 0.8 else 80,
                protocol="TCP",
                length=random.randint(40, 1500)
            ))
            
            if len(logs) == 5000:
                db.bulk_save_objects(logs)
                db.commit()
                logs = []
                
        if logs:
            db.bulk_save_objects(logs)
            db.commit()
            
        logger.info("Database seeded successfully.")
        
        # Benchmark the timeline generation
        logger.info("Running get_campaign_timeline...")
        start_time = time.time()
        
        # Test hourly
        res_hourly = get_campaign_timeline(campaign_id="BENCHMARK-CAMP", interval="hourly", db=db)
        
        # Test daily
        res_daily = get_campaign_timeline(campaign_id="BENCHMARK-CAMP", interval="daily", db=db)
        
        end_time = time.time()
        
        logger.info(f"Timeline generation for 10,000+ logs took {end_time - start_time:.4f} seconds.")
        logger.info(f"Total events found (hourly): {res_hourly.get('total_events')}")
        logger.info(f"Hourly buckets: {len(res_hourly.get('timeline', []))}")
        logger.info(f"Daily buckets: {len(res_daily.get('timeline', []))}")
        
    finally:
        db.close()

if __name__ == "__main__":
    benchmark_quality_scoring()
    benchmark_timeline_api()
