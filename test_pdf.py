import os
import sys

# Add backend to path so we can import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

# pyrefly: ignore [missing-import]
from sentinel.pdf_exporter import generate_pdf

sample_markdown = """
# Playbook: Detect Port Scan

## Executive Summary
This playbook detects unauthorized port scanning activities and mitigates the threat by blocking the source IP.

## Analysis Steps
1. Review firewall logs.
2. Identify the source IP.

## MITRE ATT&CK
```json
{
  "tactic": "Discovery",
  "technique": "Network Service Discovery",
  "id": "T1046"
}
```

## Relevant Rules
| Rule Name | Severity | Action |
|-----------|----------|--------|
| Port Scan Block | High | Drop |
| Log Scan | Low | Alert |
"""

if __name__ == "__main__":
    try:
        pdf_bytes = generate_pdf(sample_markdown)
        with open("output_test.pdf", "wb") as f:
            f.write(pdf_bytes)
        print("Successfully generated output_test.pdf")
    except Exception as e:
        print(f"Error generating PDF: {e}")
