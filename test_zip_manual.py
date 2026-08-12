import sys
import os
import zipfile
import io

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from fastapi.testclient import TestClient

def main():
    client = TestClient(app)
    response = client.get("/api/sentinel/rules/export-all")
    print(f"Status Code: {response.status_code}")
    print(f"Content-Type: {response.headers.get('content-type')}")
    
    if response.status_code == 200:
        zip_stream = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_stream, "r") as zf:
            print("Files in ZIP:")
            for name in zf.namelist():
                print(f" - {name}")
                print(f"Content of {name}:")
                content = zf.read(name).decode('utf-8', errors='ignore')
                print(content[:100] + ("..." if len(content) > 100 else ""))
                print("---")
                
if __name__ == "__main__":
    main()
