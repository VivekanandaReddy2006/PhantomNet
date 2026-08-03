import subprocess
import time
import psutil
import sys
import os

def main():
    print("Starting TAXII load test...")
    backend_dir = os.path.join(os.path.dirname(__file__), '..', 'backend')
    
    # Start the backend server
    print("Starting backend server...")
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=backend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(5)  # Wait for server to start
    
    if server_process.poll() is not None:
        print(f"Server failed to start. Return code: {server_process.returncode}")
        out, err = server_process.communicate()
        print(out.decode())
        print(err.decode())
        return

    # Find the actual uvicorn worker process (it might spawn a worker)
    server_pid = server_process.pid
    
    # Start Locust
    print("Starting Locust...")
    locust_file = os.path.join(os.path.dirname(__file__), 'locustfile.py')
    locust_process = subprocess.Popen(
        [sys.executable, "-m", "locust", "-f", locust_file, "--headless", "-u", "50", "-r", "10", "--run-time", "30s", "--host", "http://127.0.0.1:8000", "--csv=locust_report"],
        cwd=os.path.dirname(__file__),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    memory_measurements = []
    
    try:
        while locust_process.poll() is None:
            # Measure memory of server process and its children
            try:
                parent = psutil.Process(server_pid)
                children = parent.children(recursive=True)
                total_memory = parent.memory_info().rss
                for child in children:
                    total_memory += child.memory_info().rss
                memory_measurements.append(total_memory / (1024 * 1024)) # MB
            except psutil.NoSuchProcess:
                pass
            
            time.sleep(2)
    except KeyboardInterrupt:
        locust_process.terminate()

    print("Locust finished. Stopping server...")
    server_process.terminate()
    server_process.wait()
    
    avg_mem = sum(memory_measurements) / len(memory_measurements) if memory_measurements else 0
    max_mem = max(memory_measurements) if memory_measurements else 0
    
    print(f"--- Memory Profile ---")
    print(f"Average Memory Footprint: {avg_mem:.2f} MB")
    print(f"Peak Memory Footprint: {max_mem:.2f} MB")
    
    with open(os.path.join(os.path.dirname(__file__), 'memory_report.txt'), 'w') as f:
        f.write(f"Average Memory: {avg_mem:.2f} MB\n")
        f.write(f"Peak Memory: {max_mem:.2f} MB\n")

if __name__ == "__main__":
    main()
