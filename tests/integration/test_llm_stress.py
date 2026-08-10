import asyncio
import time
import logging
import psutil
import os
import sys

# Set environment variables before imports to mock DB connection
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SENTINEL_LLM_ENABLED"] = "true"
os.environ["SENTINEL_LLM_HOST"] = "http://localhost:11434"

# Add the backend to sys path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../backend')))

from sentinel.llm_service import LLMService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("llm_stress_test")

async def trigger_llm(svc, context, i):
    logger.info(f"Triggering request {i}...")
    start_time = time.time()
    narrative = await svc.async_generate_narrative(context)
    duration = time.time() - start_time
    logger.info(f"Request {i} finished in {duration:.2f}s. Length: {len(narrative)}")
    return duration

async def main():
    # Using local mock server or Ollama instance if available
    svc = LLMService()
    svc.enabled = True
    
    context = {
        "attack_type": "Stress Test",
        "severity": "CRITICAL",
        "src_ip": "1.2.3.4",
        "dst_port": 80,
        "protocol": "TCP",
    }
    
    num_requests = 10
    
    cpu_start = psutil.cpu_percent(interval=1)
    mem_start = psutil.virtual_memory().percent
    logger.info(f"Initial CPU: {cpu_start}%, Mem: {mem_start}%")
    
    overall_start = time.time()
    
    tasks = [trigger_llm(svc, context, i) for i in range(num_requests)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    overall_time = time.time() - overall_start
    cpu_end = psutil.cpu_percent(interval=1)
    mem_end = psutil.virtual_memory().percent
    
    logger.info(f"Final CPU: {cpu_end}%, Mem: {mem_end}%")
    logger.info(f"Total time for {num_requests} requests: {overall_time:.2f}s")
    
    successes = [r for r in results if isinstance(r, float)]
    errors = [r for r in results if isinstance(r, Exception)]
    
    if successes:
        avg_time = sum(successes) / len(successes)
        logger.info(f"Average time per successful request: {avg_time:.2f}s")
    logger.info(f"Successful: {len(successes)}, Errors: {len(errors)}")

if __name__ == "__main__":
    asyncio.run(main())
