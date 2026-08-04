import json
import os
import sys
from fastapi.openapi.utils import get_openapi
import logging

try:
    # Need to prevent APScheduler from blocking exit
    os.environ["DISABLE_BACKGROUND_TASKS"] = "1"
    
    from main import app
    
    # Save OpenAPI JSON to the main docs folder
    json_path = os.path.join("..", "docs", "openapi.json")
    with open(json_path, "w") as f:
        json.dump(app.openapi(), f, indent=2)
        
    print(f"Exported {json_path} successfully.")
    
    # Generate simple Redoc HTML
    html_content = """<!DOCTYPE html>
<html>
  <head>
    <title>PhantomNet Sentinel API Documentation</title>
    <!-- needed for adaptive design -->
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
      body {
        margin: 0;
        padding: 0;
      }
    </style>
  </head>
  <body>
    <redoc spec-url='openapi.json'></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"> </script>
  </body>
</html>"""
    
    html_path = os.path.join("..", "docs", "api_docs.html")
    with open(html_path, "w") as f:
        f.write(html_content)
        
    print(f"Exported {html_path} successfully.")
    os._exit(0)
except Exception as e:
    logging.exception("Failed to export OpenAPI")
    print(f"Error: {e}")
    os._exit(1)
