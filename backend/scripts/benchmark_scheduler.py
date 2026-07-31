import os
import sys
import time
import threading
import psutil
import tracemalloc
import logging
from unittest.mock import patch, MagicMock

# Ensure absolute path to the backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.database import engine, SessionLocal
from database.models import PacketLog
from sentinel.sentinel_service import SentinelService
from services.scheduler_service import SchedulerService
from sentinel.playbook_generator import PlaybookGenerator

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("Benchmark")

# Reduce log noise from other modules
logging.getLogger("PhantomNet-DB").setLevel(logging.WARNING)
logging.getLogger("sentinel.service").setLevel(logging.WARNING)
logging.getLogger("services.scheduler_service").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)

def setup_mock_data(db):
    """Generate fake packet logs to be matched by the simulated campaign."""
    logger.info("Setting up synthetic packet logs...")
    from datetime import datetime
    for i in range(100):
        log = PacketLog(
            timestamp=datetime.utcnow(),
            src_ip=f"192.168.1.{i%10}",
            dst_ip="10.0.0.1",
            src_port=10000 + i,
            dst_port=22,
            protocol="TCP",
            length=60,
            anomaly_score=95.0,
            event="login_attempt"
        )
        db.add(log)
    db.commit()

def run_benchmark():
    db = SessionLocal()
    
    # 1. Prepare data
    db.query(PacketLog).filter(PacketLog.dst_port == 22).delete()
    db.commit()
    setup_mock_data(db)
    
    process = psutil.Process(os.getpid())
    
    # Enable tracemalloc for memory footprint analysis
    tracemalloc.start()
    
    logger.info("\n" + "="*50)
    logger.info(" BENCHMARKING SCHEDULER AUTO-GENERATION")
    logger.info("="*50)

    start_cpu = process.cpu_percent(interval=None)
    start_mem = process.memory_info().rss / 1024 / 1024
    start_time = time.time()
    
    logger.info(f"Initial Memory: {start_mem:.2f} MB")
    logger.info(f"DB Pool Before: {engine.pool.status()}")
    
    scheduler_service = SchedulerService()
    
    from sentinel.llm_service import LLMService
    real_generate_narrative = LLMService.generate_narrative
    
    def mock_generate(*args, **kwargs):
        # Simulate LLM latency and memory allocation
        time.sleep(0.5)
        dummy_str = "A" * 1024 * 1024 * 2 # 2MB dummy string
        return "Simulated LLM narrative..."
        
    LLMService.generate_narrative = mock_generate
    
    # Mock sending emails
    import sentinel.email_notifier
    real_trigger = sentinel.email_notifier.trigger_email_alert_async
    sentinel.email_notifier.trigger_email_alert_async = lambda *args, **kwargs: None
    
    # Patch clustering to return a large campaign
    with patch("ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns") as mock_cluster:
        mock_cluster.return_value = {
            "campaign_count": 1,
            "campaigns": [
                {
                    "campaign_id": "BENCHMARK-CAMP-001",
                    "unique_sources": [f"192.168.1.{i}" for i in range(10)],
                    "target_ports": [22],
                    "protocols": ["TCP"],
                    "event_count": 100
                }
            ]
        }
        
        # Execute cycle
        scheduler_service._execute_sentinel_cycle()
    
    # Snapshot memory mid-way (right after LLM template processing)
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')
    
    end_time = time.time()
    end_cpu = process.cpu_percent(interval=None)
    end_mem = process.memory_info().rss / 1024 / 1024
    
    logger.info(f"DB Pool After: {engine.pool.status()}")
    logger.info(f"Final Memory: {end_mem:.2f} MB (Delta: {end_mem - start_mem:+.2f} MB)")
    logger.info(f"CPU Utilization: {end_cpu}%")
    logger.info(f"Execution Time: {end_time - start_time:.2f} seconds")
    
    logger.info("\nTop 5 Memory Allocations during cycle:")
    for stat in top_stats[:5]:
        logger.info(f" - {stat}")

    # Restore original functions
    PlaybookGenerator.generate_llm_narrative = real_generate_narrative
    sentinel.email_notifier.trigger_email_alert_async = real_trigger
    db.close()
    
    tracemalloc.stop()

if __name__ == "__main__":
    run_benchmark()
