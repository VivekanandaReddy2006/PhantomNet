"""
tests/test_pdf_visual_quality.py
----------------------------------
Week 19, Day 4 — PDF Visual Quality & Rendering Test Suite

Tests
-----
  1.  Scenario: SSH Brute Force         — multi-page + long content
  2.  Scenario: Port Scan / Recon       — long Snort rule (code block)
  3.  Scenario: Ransomware C2           — multi-section with Sigma + LLM
  4.  Scenario: SQL Injection           — complex MITRE table + markdown table
  5.  Scenario: DDoS Amplification      — multi-page playbook with 200+ lines
  6.  Scenario: Zero-day Exploit        — long code block overflow stress test
  7.  Scenario: Sparse / None fields    — robustness with all-None metadata
  8.  Scenario: Critical severity       — CRITICAL badge + score bar at 95
  9.  PDF structure validation          — %PDF header, %%EOF, minimum size
  10. Header/footer presence            — page number token in PDF stream
  11. MITRE ATT&CK URL encoding         — special chars in URL don't crash
  12. Code block word-wrap              — 300-char single-line code block
  13. Markdown table rendering          — table with 5 cols, 10 rows
  14. Even/odd row alternation          — injected via _inject_row_classes
  15. Reportlab fallback rendering      — _render_reportlab produces valid PDF
  16. _MINIMAL_PDF integrity            — valid %PDF structure
  17. generate_pdf() legacy shim        — markdown-only path
  18. generate_pdf_from_playbook()      — ORM-dict full path
  19. Page count heuristic              — multi-page content > 1 page worth
  20. Validation report artifact        — writes PDF files to output/
"""

import io
import os
import re
import sys
import time
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Bootstrap paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))

OUTPUT_DIR = ROOT / "tests" / "pdf_outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Imports (after path bootstrap)
# ---------------------------------------------------------------------------
# pyrefly: ignore [missing-import]
from sentinel.pdf_exporter import (
    generate_pdf,
    generate_pdf_from_playbook,
    _MINIMAL_PDF,
    _build_html,
    _render_xhtml2pdf,
    _render_reportlab,
    _inject_row_classes,
    _score_bar_width_pt,
    _sanitize_for_pdf,
    _mitre_reference_html,
)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

PASS_TAG = f"{GREEN}[PASS]{RESET}"
FAIL_TAG = f"{RED}[FAIL]{RESET}"
SKIP_TAG = f"{YELLOW}[SKIP]{RESET}"
INFO_TAG = f"{CYAN}[INFO]{RESET}"

results: List[Dict] = []

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _assert(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        print(f"  {PASS_TAG} {label}")
        results.append({"name": label, "status": "PASS", "detail": detail})
    else:
        print(f"  {FAIL_TAG} {label}" + (f" — {detail}" if detail else ""))
        results.append({"name": label, "status": "FAIL", "detail": detail})


def _check_pdf_bytes(data: bytes, label: str) -> bool:
    """Validate basic PDF structure."""
    ok = (
        isinstance(data, bytes)
        and len(data) > 200
        and data[:4] == b"%PDF"
        and b"%%EOF" in data
    )
    _assert(ok, label, f"size={len(data)}, header={data[:4]!r}")
    return ok


def _save_pdf(data: bytes, filename: str) -> Path:
    """Save PDF to output directory for manual inspection."""
    path = OUTPUT_DIR / filename
    path.write_bytes(data)
    print(f"  {INFO_TAG} Saved >> {path}")
    return path


def _make_long_content(lines: int = 120) -> str:
    """Generate a long multi-section markdown playbook."""
    sections = []
    sections.append("# Incident Response Playbook\n\n## Executive Summary\n\n"
                    "This playbook describes the full incident response workflow "
                    "for a detected threat campaign.\n")
    for i in range(1, 6):
        sections.append(f"\n## Phase {i}: {'Identification Detection Containment Eradication Recovery'.split()[i-1]}\n")
        for j in range(1, lines // 5 + 1):
            sections.append(f"  {j}. Step {j}: Perform analysis task {j} in phase {i}. "
                            f"Review all log entries from source 10.0.0.{j % 254 + 1}.\n")
    sections.append("\n## IOC Reference Table\n\n"
                    "| Type | Value | Severity | First Seen |\n"
                    "|------|-------|----------|------------|\n")
    for i in range(1, 12):
        sections.append(f"| IP | 10.0.0.{i} | HIGH | 2026-07-{i:02d} |\n")
    sections.append("\n## Forensic Notes\n\n```\n")
    for i in range(1, 30):
        sections.append(f"# line {i}: tcpdump frame analysis result for packet sequence {i * 1000}\n")
    sections.append("```\n")
    return "".join(sections)


def _make_long_snort_rule() -> str:
    """Generate a realistic multi-line Snort rule with long strings."""
    return (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 '
        '(msg:"ET SCAN Potential SSH Scan OUTBOUND"; flow:established,to_server; '
        'content:"SSH-"; depth:4; '
        'threshold:type both,track by_src,count 5,seconds 120; '
        'classtype:attempted-recon; sid:2001219; rev:20; '
        'metadata:affected_product Any,attack_target Server,created_at 2010_07_30,'
        'cve CVE-2023-12345,deployment Perimeter,signature_severity Major,'
        'tag Scanning,updated_at 2026_07_30;)\n'
        'alert tcp any any -> any 22 (msg:"SSH Brute Force Login Attempt"; '
        'flow:established,to_server; content:"SSH-2.0"; depth:7; '
        'threshold:type threshold,track by_src,count 10,seconds 60; '
        'classtype:attempted-admin; sid:9001001; rev:3;)\n'
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"Suspicious outbound SSH tunnel established after brute force"; '
        'flow:established,from_server; content:"channel open"; '
        'pcre:"/^SSH-[12]/"; classtype:trojan-activity; sid:9001002; rev:1;)'
    )


def _make_sigma_rule() -> str:
    """Generate a realistic Sigma YAML rule."""
    return """title: SSH Brute Force Attack Detection
id: 8fef5e0a-a834-4f3c-a9b7-0c4e1f2d3e56
status: experimental
description: Detects multiple failed SSH authentication attempts from the same source IP
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://www.elastic.co/guide/en/siem/guide/current/ssh-brute-force.html
author: PhantomNet Sentinel Auto-Generator
date: 2026/07/30
tags:
    - attack.credential_access
    - attack.t1110.001
    - attack.brute_force
logsource:
    category: authentication
    product: linux
detection:
    selection:
        EventID: 4625
        LogonType: 10
        SubjectUserName|contains: '*'
    condition: selection | count() > 10 by SourceAddress within 60s
falsepositives:
    - Legitimate automated login tools with misconfigured credentials
    - Penetration testing activities
level: high
fields:
    - SourceAddress
    - TargetUserName
    - WorkstationName
    - LogonFailureReason"""


def _make_mitre_markdown_table() -> str:
    """Generate a markdown table resembling a MITRE ATT&CK reference."""
    rows = [
        ("T1110", "Brute Force", "Credential Access", "HIGH", "https://attack.mitre.org/T1110"),
        ("T1046", "Network Service Discovery", "Discovery", "MEDIUM", "https://attack.mitre.org/T1046"),
        ("T1059", "Command and Scripting Interpreter", "Execution", "HIGH", "https://attack.mitre.org/T1059"),
        ("T1078", "Valid Accounts", "Persistence", "CRITICAL", "https://attack.mitre.org/T1078"),
        ("T1021", "Remote Services", "Lateral Movement", "HIGH", "https://attack.mitre.org/T1021"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "HIGH", "https://attack.mitre.org/T1041"),
        ("T1486", "Data Encrypted for Impact", "Impact", "CRITICAL", "https://attack.mitre.org/T1486"),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", "CRITICAL", "https://attack.mitre.org/T1190"),
        ("T1203", "Exploitation for Client Execution", "Execution", "HIGH", "https://attack.mitre.org/T1203"),
        ("T1566", "Phishing", "Initial Access", "HIGH", "https://attack.mitre.org/T1566"),
    ]
    lines = [
        "## MITRE ATT&CK Reference Matrix\n\n",
        "| Technique ID | Technique Name | Tactic | Severity | Reference |\n",
        "|---|---|---|---|---|\n",
    ]
    for tid, name, tactic, sev, url in rows:
        lines.append(f"| {tid} | {name} | {tactic} | {sev} | {url} |\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# Playbook fixture factory
# ---------------------------------------------------------------------------

def _playbook(
    pb_id: str = "PB-TEST-0001",
    name: str = "Test Playbook",
    severity: str = "HIGH",
    score: float = 75.0,
    content: str = "# Test\n\nTest content.",
    snort: str = "",
    sigma: str = "",
    llm: str = "",
    mitre_url: str = "https://attack.mitre.org/techniques/T1110/001/",
    technique_id: str = "T1110.001",
    technique_name: str = "Brute Force: Password Guessing",
    tactic: str = "Credential Access",
    attack_type: str = "SSH_AUTH_FAILURE",
) -> dict:
    return {
        "playbook_id": pb_id,
        "playbook_name": name,
        "status": "approved",
        "severity": severity,
        "threat_score": score,
        "confidence_score": round(score / 100.0, 3),
        "src_ip": "192.168.1.100",
        "dst_port": 22,
        "protocol": "TCP",
        "attack_type": attack_type,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "mitre_url": mitre_url,
        "snort_rule": snort,
        "sigma_rule": sigma,
        "playbook_content": content,
        "llm_narrative": llm,
        "reviewed_by": "analyst1",
        "reviewed_at": datetime(2026, 7, 30, 12, 0, 0),
        "created_at": datetime(2026, 7, 30, 10, 0, 0),
        "version": 1,
        "template_name": "ssh_brute_force.j2",
    }


# ===========================================================================
# TEST SCENARIOS
# ===========================================================================

def test_scenario_1_ssh_brute_force():
    """Scenario 1: SSH Brute Force — multi-page, full metadata."""
    print(f"\n{BOLD}{CYAN}Scenario 1: SSH Brute Force (multi-page, full metadata){RESET}")
    pb = _playbook(
        pb_id="PB-SSH-0001",
        name="SSH Brute Force - Automated Credential Attack Response",
        severity="HIGH",
        score=87.3,
        content=_make_long_content(80),
        snort=_make_long_snort_rule(),
        sigma=_make_sigma_rule(),
        llm="## AI Analysis\n\nThis campaign exhibits classic brute force patterns targeting port 22.\n\n"
            "### Key Indicators\n- 450 login attempts in 60 seconds\n- Source: single IP rotating usernames",
    )
    t0 = time.perf_counter()
    pdf = generate_pdf_from_playbook(pb)
    elapsed = time.perf_counter() - t0
    _check_pdf_bytes(pdf, "SSH BF: valid PDF bytes")
    _assert(len(pdf) > 8000, "SSH BF: PDF size > 8KB (multi-page expected)", f"{len(pdf):,} bytes")
    _assert(elapsed < 30.0, f"SSH BF: generation time < 30s ({elapsed:.2f}s)")
    _save_pdf(pdf, "scenario1_ssh_brute_force.pdf")


def test_scenario_2_port_scan():
    """Scenario 2: Port Scan / Recon — long Snort rule code block."""
    print(f"\n{BOLD}{CYAN}Scenario 2: Port Scan / Recon (long code block){RESET}")
    long_snort = "\n".join([
        f'alert tcp any any -> $HOME_NET {p} (msg:"Port Scan port {p}"; '
        f'flags:S; threshold:type both,track by_src,count 5,seconds 10; '
        f'classtype:attempted-recon; sid:{9002000+p}; rev:1;)'
        for p in range(1, 41)
    ])
    pb = _playbook(
        pb_id="PB-SCAN-0002",
        name="Network Port Scan - Recon Campaign Response",
        severity="MEDIUM",
        score=52.0,
        content=(
            "# Port Scan Detection Response\n\n"
            "## Executive Summary\n"
            "Detected systematic port scanning from 192.168.1.100 across 40 ports.\n\n"
            "## Recommended Actions\n"
            "1. Block source IP at perimeter firewall\n"
            "2. Enable port scan detection rules on IDS\n"
            "3. Review network topology exposure\n"
        ),
        snort=long_snort,
        technique_id="T1046",
        technique_name="Network Service Scanning",
        tactic="Discovery",
        attack_type="PORT_SCAN",
    )
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "Port Scan: valid PDF bytes")
    _assert(len(pdf) > 5000, "Port Scan: PDF size > 5KB", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "scenario2_port_scan.pdf")


def test_scenario_3_ransomware():
    """Scenario 3: Ransomware C2 — Sigma + LLM narrative."""
    print(f"\n{BOLD}{CYAN}Scenario 3: Ransomware C2 (Sigma + LLM narrative){RESET}")
    pb = _playbook(
        pb_id="PB-RANSOM-0003",
        name="Ransomware C2 Communication - Emergency Response",
        severity="CRITICAL",
        score=96.5,
        content=(
            "# CRITICAL: Ransomware C2 Response\n\n"
            "## Executive Summary\n"
            "Active ransomware C2 communication detected. Immediate isolation required.\n\n"
            "## Immediate Containment (T+0 to T+15 min)\n"
            "1. IMMEDIATELY isolate all affected systems from network\n"
            "2. Preserve memory dumps before shutdown\n"
            "3. Activate incident response team\n"
            "4. Notify CISO and legal counsel\n\n"
            "## Forensic Preservation\n"
            "- Take full disk images of all affected systems\n"
            "- Capture network traffic pcaps\n"
            "- Document all IOCs: hashes, IPs, domains, registry keys\n\n"
            "## Eradication Steps\n"
            "1. Identify Patient Zero via EDR telemetry\n"
            "2. Remove malware persistence mechanisms\n"
            "3. Patch exploited vulnerability CVE-2026-XXXX\n\n"
            "## Recovery\n"
            "1. Restore from clean backups (verify integrity first)\n"
            "2. Rebuild affected systems from golden images\n"
            "3. Reset all credentials for affected accounts\n"
        ),
        sigma=_make_sigma_rule(),
        llm=(
            "## AI-Generated Threat Analysis\n\n"
            "This incident matches the behavioural profile of a **REvil/Sodinokibi** variant.\n\n"
            "### Confidence Assessment\n"
            "| Indicator | Match | Confidence |\n"
            "|---|---|---|\n"
            "| C2 traffic pattern | Yes | 94% |\n"
            "| File encryption sequence | Yes | 91% |\n"
            "| Lateral movement footprint | Partial | 72% |\n\n"
            "### Recommended MITRE Coverage\n"
            "Ensure your detection coverage includes T1486, T1489, T1490, T1491."
        ),
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        attack_type="RANSOMWARE_C2",
        mitre_url="https://attack.mitre.org/techniques/T1486/",
    )
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "Ransomware: valid PDF bytes")
    _assert(len(pdf) > 6000, "Ransomware: PDF size > 6KB", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "scenario3_ransomware_c2.pdf")


def test_scenario_4_sql_injection():
    """Scenario 4: SQL Injection — MITRE table + markdown table."""
    print(f"\n{BOLD}{CYAN}Scenario 4: SQL Injection (MITRE table + markdown table){RESET}")
    content = (
        "# SQL Injection Campaign Response\n\n"
        "## Executive Summary\n"
        "Automated SQL injection attack detected against the web application layer.\n\n"
        + _make_mitre_markdown_table() +
        "\n\n## Attack Pattern Analysis\n"
        "The attacker used UNION-based injection to enumerate database schemas.\n\n"
        "### Payload Examples\n"
        "```sql\n"
        "' OR '1'='1'; SELECT table_name FROM information_schema.tables; --\n"
        "'; INSERT INTO users(username,password) VALUES('admin','hacked'); --\n"
        "' UNION SELECT null,username,password FROM users --\n"
        "```\n\n"
        "### Affected Endpoints\n"
        "| Endpoint | Method | Parameter | Status |\n"
        "|---|---|---|---|\n"
        "| /api/users | GET | id | VULNERABLE |\n"
        "| /api/search | POST | query | VULNERABLE |\n"
        "| /login | POST | username | PATCHED |\n"
    )
    pb = _playbook(
        pb_id="PB-SQLI-0004",
        name="SQL Injection - Database Exfiltration Response",
        severity="HIGH",
        score=82.0,
        content=content,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        attack_type="SQL_INJECTION",
        mitre_url="https://attack.mitre.org/techniques/T1190/",
    )
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "SQL Injection: valid PDF bytes")
    _assert(len(pdf) > 5000, "SQL Injection: PDF size > 5KB", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "scenario4_sql_injection.pdf")


def test_scenario_5_ddos():
    """Scenario 5: DDoS — 200+ line multi-page stress test."""
    print(f"\n{BOLD}{CYAN}Scenario 5: DDoS Amplification (200+ line multi-page){RESET}")
    pb = _playbook(
        pb_id="PB-DDOS-0005",
        name="DDoS Amplification Attack - Network Resilience Response",
        severity="CRITICAL",
        score=91.0,
        content=_make_long_content(200),
        snort=(
            "alert udp any any -> $HOME_NET 53 "
            "(msg:\"DNS Amplification Attack\"; "
            "content:\"|00 00 ff 00 01|\"; "
            "threshold:type both,track by_src,count 100,seconds 10; "
            "classtype:attempted-dos; sid:9005001; rev:1;)"
        ),
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic="Impact",
        attack_type="DDOS_AMPLIFICATION",
    )
    t0 = time.perf_counter()
    pdf = generate_pdf_from_playbook(pb)
    elapsed = time.perf_counter() - t0
    _check_pdf_bytes(pdf, "DDoS: valid PDF bytes")
    _assert(len(pdf) > 10000, "DDoS: PDF size > 10KB (200+ line content)", f"{len(pdf):,} bytes")
    _assert(elapsed < 60.0, f"DDoS: generation time < 60s ({elapsed:.2f}s)")
    _save_pdf(pdf, "scenario5_ddos_amplification.pdf")


def test_scenario_6_overflow_stress():
    """Scenario 6: Code block overflow stress — 300-char single line."""
    print(f"\n{BOLD}{CYAN}Scenario 6: Code Block Overflow Stress (300-char line){RESET}")
    # A single code block line with 300 chars — should word-wrap not overflow
    long_line = "A" * 300
    long_snort = (
        f"alert tcp any any -> any any "
        f"(msg:\"{'X' * 250}\"; "
        f"content:\"|{'FF' * 20}|\"; "
        f"sid:9006001; rev:1;)"
    )
    content = (
        "# Overflow Stress Test\n\n"
        "## Long Code Block Test\n\n"
        "```\n"
        + long_line + "\n"
        + ("BCDEFGHIJKLMNOPQRSTUVWXYZ" * 12) + "\n"
        + "```\n\n"
        "## Normal content after block\n"
        "This should render correctly without overlap with the code block above.\n"
    )
    pb = _playbook(
        pb_id="PB-STRESS-0006",
        name="Overflow Stress Test Playbook",
        severity="MEDIUM",
        score=60.0,
        content=content,
        snort=long_snort,
    )
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "Overflow Stress: valid PDF bytes")
    _assert(len(pdf) > 3000, "Overflow Stress: PDF non-trivial size", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "scenario6_overflow_stress.pdf")


def test_scenario_7_sparse_none():
    """Scenario 7: All-None metadata — robustness check."""
    print(f"\n{BOLD}{CYAN}Scenario 7: Sparse / None Fields (robustness){RESET}")
    sparse = {
        "playbook_id": None, "playbook_name": None, "status": None,
        "severity": None, "threat_score": None, "confidence_score": None,
        "src_ip": None, "dst_port": None, "protocol": None,
        "attack_type": None, "technique_id": None, "technique_name": None,
        "tactic": None, "mitre_url": None, "snort_rule": None,
        "sigma_rule": None, "playbook_content": None, "llm_narrative": None,
        "reviewed_by": None, "reviewed_at": None, "created_at": None,
        "version": None, "template_name": None,
    }
    pdf = generate_pdf_from_playbook(sparse)
    _check_pdf_bytes(pdf, "Sparse/None: valid PDF bytes")
    _assert(len(pdf) > 1000, "Sparse/None: PDF non-empty", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "scenario7_sparse_none.pdf")


def test_scenario_8_critical_severity():
    """Scenario 8: CRITICAL severity — score bar at 95, red badge."""
    print(f"\n{BOLD}{CYAN}Scenario 8: CRITICAL Severity (score=95){RESET}")
    pb = _playbook(
        pb_id="PB-CRIT-0008",
        name="Zero-Day Exploit - CRITICAL Severity Response",
        severity="CRITICAL",
        score=95.0,
        content=(
            "# CRITICAL: Zero-Day Exploit Response\n\n"
            "## Immediate Actions\n"
            "This is a confirmed zero-day exploitation in production systems.\n\n"
            "Emergency isolation protocol activated.\n"
        ),
        technique_id="T1203",
        technique_name="Exploitation for Client Execution",
        tactic="Execution",
        attack_type="ZERO_DAY_EXPLOIT",
        mitre_url="https://attack.mitre.org/techniques/T1203/",
    )
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "CRITICAL: valid PDF bytes")
    _save_pdf(pdf, "scenario8_critical_severity.pdf")


# ===========================================================================
# UNIT TESTS — Rendering components
# ===========================================================================

def test_score_bar_width():
    """Test 9: score bar absolute pt width calculation."""
    print(f"\n{BOLD}{CYAN}Test 9: Score Bar Width (pt units){RESET}")
    _assert(_score_bar_width_pt(0)   == 0,   "score_bar: 0  >> 0pt")
    _assert(_score_bar_width_pt(50)  == 215, "score_bar: 50 >> 215pt",
            f"got {_score_bar_width_pt(50)}")
    _assert(_score_bar_width_pt(100) == 430, "score_bar: 100 >> 430pt",
            f"got {_score_bar_width_pt(100)}")
    _assert(_score_bar_width_pt(None) == 0,  "score_bar: None >> 0pt")
    _assert(_score_bar_width_pt(150) == 430, "score_bar: 150 clamped >> 430pt",
            f"got {_score_bar_width_pt(150)}")


def test_inject_row_classes():
    """Test 10: nth-child row class injection."""
    print(f"\n{BOLD}{CYAN}Test 10: Inject Row Classes (even/odd){RESET}")
    html = "<table><tr><td>R1</td></tr><tr><td>R2</td></tr><tr><td>R3</td></tr></table>"
    result = _inject_row_classes(html)
    _assert('class="odd-row"'  in result, "inject_rows: first row gets odd-row class")
    _assert('class="even-row"' in result, "inject_rows: second row gets even-row class")
    # Count occurrences
    odd_count  = result.count('class="odd-row"')
    even_count = result.count('class="even-row"')
    _assert(odd_count == 2,  f"inject_rows: 2 odd rows (got {odd_count})")
    _assert(even_count == 1, f"inject_rows: 1 even row (got {even_count})")


def test_sanitize_for_pdf():
    """Test 11: Emoji sanitization for xhtml2pdf."""
    print(f"\n{BOLD}{CYAN}Test 11: Emoji Sanitization{RESET}")
    text_with_emoji = "Hello \U0001F600 World \U0001F6E1 Shield"
    cleaned = _sanitize_for_pdf(text_with_emoji)
    _assert("\U0001F600" not in cleaned, "sanitize: U+1F600 emoji removed")
    _assert("\U0001F6E1" not in cleaned, "sanitize: U+1F6E1 emoji removed")
    _assert("Hello" in cleaned, "sanitize: ASCII text preserved")
    _assert("World" in cleaned, "sanitize: ASCII text preserved")


def test_mitre_reference_html():
    """Test 12: MITRE ATT&CK reference HTML generation."""
    print(f"\n{BOLD}{CYAN}Test 12: MITRE ATT&CK Reference HTML{RESET}")
    html = _mitre_reference_html(
        "T1110.001",
        "Brute Force: Password Guessing",
        "https://attack.mitre.org/techniques/T1110/001/",
    )
    _assert("T1110.001" in html,       "mitre_ref: technique ID present")
    _assert("Brute Force" in html,     "mitre_ref: technique name present")
    _assert("mitre-url" in html,       "mitre_ref: mitre-url CSS class present")
    _assert("attack.mitre.org" in html, "mitre_ref: URL present")
    _assert("underline" in html,       "mitre_ref: underline styling applied")

    # Without URL
    html_no_url = _mitre_reference_html("T1046", "Network Scan", "")
    _assert("mitre-url" not in html_no_url, "mitre_ref: no URL section when empty")


def test_code_block_word_wrap():
    """Test 13: Code block word-wrap in HTML output."""
    print(f"\n{BOLD}{CYAN}Test 13: Code Block Word-Wrap (300-char line){RESET}")
    long_code = "X" * 300
    pb = _playbook(content=f"# Test\n\n```\n{long_code}\n```\n")
    html = _build_html(pb)
    _assert("word-break: break-all" in html or "word-break:break-all" in html,
            "code block: word-break:break-all in CSS")
    _assert("overflow: hidden" in html or "overflow:hidden" in html,
            "code block: overflow:hidden in CSS")
    _assert("pre-wrap" in html, "code block: white-space:pre-wrap in CSS")


def test_table_layout_fixed():
    """Test 14: table-layout:fixed for MITRE and content tables."""
    print(f"\n{BOLD}{CYAN}Test 14: Table Layout Fixed{RESET}")
    pb = _playbook()
    html = _build_html(pb)
    _assert("table-layout: fixed" in html or "table-layout:fixed" in html,
            "html: table-layout:fixed in CSS")


def test_header_footer_no_overlap():
    """Test 15: Header frame top position > 0, body margin clears header."""
    print(f"\n{BOLD}{CYAN}Test 15: Header/Footer Frame Positioning{RESET}")
    pb = _playbook()
    html = _build_html(pb)
    # Check @page margin-top value — should be 3.2cm or larger
    margin_match = re.search(r'margin:\s*([\d.]+)cm\s+[\d.]+cm', html)
    _assert(margin_match is not None, "html: @page margin found")
    if margin_match:
        top_margin = float(margin_match.group(1))
        _assert(top_margin >= 3.0, f"html: top margin >= 3cm (got {top_margin}cm)")
    # Check header frame top position
    frame_match = re.search(r'top:\s*([\d.]+)pt', html)
    _assert(frame_match is not None, "html: header frame top found")
    if frame_match:
        top_pt = float(frame_match.group(1))
        _assert(top_pt >= 15, f"html: header frame top >= 15pt (got {top_pt}pt)")
    # Check footer frame
    footer_match = re.search(r'top:\s*([\d.]+)pt.*?footer', html, re.DOTALL)
    _assert("footer_frame" in html, "html: footer_frame defined")


def test_reportlab_fallback():
    """Test 16: reportlab fallback produces valid PDF."""
    print(f"\n{BOLD}{CYAN}Test 16: Reportlab Fallback Renderer{RESET}")
    pb = _playbook(
        pb_id="PB-RL-0016",
        name="Reportlab Fallback Test",
        snort=_make_long_snort_rule(),
        sigma=_make_sigma_rule(),
        llm="## AI note\nTest narrative.",
        content=_make_long_content(40),
    )
    pdf = _render_reportlab(pb)
    _check_pdf_bytes(pdf, "reportlab: valid PDF bytes")
    _assert(len(pdf) > 2000, "reportlab: PDF size > 2KB", f"{len(pdf):,} bytes")
    _save_pdf(pdf, "test16_reportlab_fallback.pdf")


def test_minimal_pdf_integrity():
    """Test 17: _MINIMAL_PDF structural validity."""
    print(f"\n{BOLD}{CYAN}Test 17: _MINIMAL_PDF Integrity{RESET}")
    _assert(_MINIMAL_PDF[:4] == b"%PDF",  "_MINIMAL_PDF: starts with %PDF")
    _assert(b"%%EOF" in _MINIMAL_PDF,     "_MINIMAL_PDF: contains %%EOF")
    _assert(len(_MINIMAL_PDF) > 400,      f"_MINIMAL_PDF: > 400 bytes ({len(_MINIMAL_PDF)})")
    _assert(b"/Catalog" in _MINIMAL_PDF,  "_MINIMAL_PDF: contains /Catalog")
    _assert(b"/Pages" in _MINIMAL_PDF,    "_MINIMAL_PDF: contains /Pages")
    _assert(b"/Page " in _MINIMAL_PDF or b"/Page\n" in _MINIMAL_PDF,
            "_MINIMAL_PDF: contains /Page object")


def test_generate_pdf_legacy_shim():
    """Test 18: generate_pdf() legacy shim."""
    print(f"\n{BOLD}{CYAN}Test 18: generate_pdf() Legacy Shim{RESET}")
    md = (
        "# Legacy Test\n\n## Section\nContent with **bold** and *italic* text.\n\n"
        "| Col A | Col B |\n|---|---|\n| R1 | V1 |\n| R2 | V2 |\n"
    )
    pdf = generate_pdf(md)
    _check_pdf_bytes(pdf, "legacy shim: valid PDF bytes")
    _assert(len(pdf) > 1000, "legacy shim: PDF non-trivial size", f"{len(pdf):,} bytes")


def test_generate_pdf_from_playbook_orm_style():
    """Test 19: generate_pdf_from_playbook with ORM-style object."""
    print(f"\n{BOLD}{CYAN}Test 19: generate_pdf_from_playbook() ORM-style dict{RESET}")

    class FakeORM:
        """Mimics a SQLAlchemy ORM object using attribute access."""
        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)

    orm_obj = FakeORM(_playbook(
        pb_id="PB-ORM-0019",
        name="ORM-Style Test Playbook",
        severity="CRITICAL",
        score=95.5,
        content="# ORM Test\n\nContent via attribute access.\n",
    ))
    pdf = generate_pdf_from_playbook(orm_obj)
    _check_pdf_bytes(pdf, "ORM-style: valid PDF bytes")


def test_page_count_heuristic():
    """Test 20: Long content produces larger PDF (multi-page heuristic)."""
    print(f"\n{BOLD}{CYAN}Test 20: Page Count Heuristic (multi-page > single-page){RESET}")
    short_pb = _playbook(content="# Short\n\nOne line.")
    long_pb  = _playbook(content=_make_long_content(200))

    short_pdf = generate_pdf_from_playbook(short_pb)
    long_pdf  = generate_pdf_from_playbook(long_pb)

    _assert(len(long_pdf) > len(short_pdf),
            "page count: multi-page PDF larger than single-page",
            f"long={len(long_pdf):,}  short={len(short_pdf):,}")


def test_special_chars_in_mitre_url():
    """Test 21: Special chars in MITRE URL don't crash the renderer."""
    print(f"\n{BOLD}{CYAN}Test 21: Special Characters in MITRE URL{RESET}")
    pb = _playbook(
        mitre_url="https://attack.mitre.org/techniques/T1110/001/?ref=phishing&type=brute&severity=HIGH",
    )
    try:
        pdf = generate_pdf_from_playbook(pb)
        _check_pdf_bytes(pdf, "special URL: valid PDF bytes")
    except Exception as e:
        _assert(False, f"special URL: should not raise — {e}")


def test_markdown_table_with_many_columns():
    """Test 22: Markdown table with 5 columns, 12 rows."""
    print(f"\n{BOLD}{CYAN}Test 22: Markdown Table (5-col, 12-row){RESET}")
    content = _make_mitre_markdown_table()
    pb = _playbook(content=content)
    pdf = generate_pdf_from_playbook(pb)
    _check_pdf_bytes(pdf, "MITRE table: valid PDF bytes")
    _assert(len(pdf) > 3000, "MITRE table: PDF > 3KB", f"{len(pdf):,} bytes")


def test_html_build_contains_required_sections():
    """Test 23: HTML output contains all required section markers."""
    print(f"\n{BOLD}{CYAN}Test 23: HTML Structure — Required Sections Present{RESET}")
    pb = _playbook(
        snort=_make_long_snort_rule(),
        sigma=_make_sigma_rule(),
        llm="## AI Analysis\nTest.",
    )
    html = _build_html(pb)
    _assert("[META]"   in html, "html: Metadata section marker present")
    _assert("[THREAT]" in html, "html: Threat Context section marker present")
    _assert("[MITRE]"  in html, "html: MITRE section marker present")
    _assert("[PLAYBOOK]" in html, "html: Playbook Content section marker present")
    _assert("[IDS]"    in html, "html: Snort IDS section marker present")
    _assert("[SIGMA]"  in html, "html: Sigma section marker present")
    _assert("[AI]"     in html, "html: LLM section marker present")
    _assert("header_content" in html, "html: page header frame present")
    _assert("footer_content" in html, "html: page footer frame present")
    _assert("pdf:pagenumber" in html,  "html: page number token present")
    _assert("pdf:pagecount" in html,   "html: page count token present")
    _assert("CONFIDENTIAL" in html,    "html: classification banner present")


# ===========================================================================
# VALIDATION REPORT
# ===========================================================================

def _print_report() -> None:
    total  = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    print(f"\n{'='*70}")
    print(f"{BOLD}Week 19 Day 4 — PDF Visual Quality Test Suite Results{RESET}")
    print(f"{'='*70}")
    print(f"  Total Tests : {total}")
    print(f"  {GREEN}Passed{RESET}      : {passed}")
    print(f"  {RED}Failed{RESET}      : {failed}")
    print(f"  Success Rate: {100.0 * passed / total:.1f}%" if total else "")

    if failed > 0:
        print(f"\n{RED}Failed Tests:{RESET}")
        for r in results:
            if r["status"] == "FAIL":
                print(f"  - {r['name']}" + (f" [{r['detail']}]" if r["detail"] else ""))

    print(f"\n{CYAN}PDF Outputs saved to:{RESET} {OUTPUT_DIR}")
    pdfs = sorted(OUTPUT_DIR.glob("*.pdf"))
    for p in pdfs:
        size_kb = p.stat().st_size / 1024
        print(f"  {p.name:50s} {size_kb:6.1f} KB")

    # Write machine-readable report
    report_path = OUTPUT_DIR / "validation_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"PhantomNet Sentinel — PDF Visual Quality Validation Report\n")
        f.write(f"Week 19, Day 4\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"Results: {passed}/{total} passed\n\n")
        f.write("Test Results\n" + "-"*50 + "\n")
        for r in results:
            status_str = "PASS" if r["status"] == "PASS" else "FAIL"
            f.write(f"[{status_str}] {r['name']}")
            if r["detail"]:
                f.write(f" — {r['detail']}")
            f.write("\n")
        f.write("\nPDF Files\n" + "-"*50 + "\n")
        for p in pdfs:
            f.write(f"{p.name}: {p.stat().st_size:,} bytes\n")
    print(f"\n{CYAN}Validation report written to:{RESET} {report_path}")
    print(f"{'='*70}\n")

    return failed


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}{'='*70}")
    print("PhantomNet Sentinel — Week 19 Day 4 PDF Visual Quality Test Suite")
    print(f"{'='*70}{RESET}\n")

    # Run all scenario tests
    test_scenario_1_ssh_brute_force()
    test_scenario_2_port_scan()
    test_scenario_3_ransomware()
    test_scenario_4_sql_injection()
    test_scenario_5_ddos()
    test_scenario_6_overflow_stress()
    test_scenario_7_sparse_none()
    test_scenario_8_critical_severity()

    # Run unit tests
    test_score_bar_width()
    test_inject_row_classes()
    test_sanitize_for_pdf()
    test_mitre_reference_html()
    test_code_block_word_wrap()
    test_table_layout_fixed()
    test_header_footer_no_overlap()
    test_reportlab_fallback()
    test_minimal_pdf_integrity()
    test_generate_pdf_legacy_shim()
    test_generate_pdf_from_playbook_orm_style()
    test_page_count_heuristic()
    test_special_chars_in_mitre_url()
    test_markdown_table_with_many_columns()
    test_html_build_contains_required_sections()

    failed = _print_report()
    sys.exit(0 if failed == 0 else 1)

