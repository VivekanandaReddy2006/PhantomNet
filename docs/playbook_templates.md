# PhantomNet Sentinel Playbook Templates Documentation

## Overview
The PhantomNet Sentinel layer dynamically compiles structured incident-response playbooks in Markdown format. This process is driven by the `PlaybookGenerator` module (`backend/sentinel/playbook_generator.py`), which uses the Jinja2 template engine to render variables and apply template inheritance.

All playbooks are structured into **7 standard sections** to provide a consistent incident-response framework for security analysts.

---

## Directory Structure
The playbook templates reside in:
`backend/sentinel/templates/`

The primary templates include:
*   `base_playbook.md.j2` — The parent template defining the layout, blocks, and default structure.
*   `brute_force.md.j2` — Incident playbook for SSH and credential brute-force attacks.
*   `sqli_attempt.md.j2` — Incident playbook for SQL Injection attempts.
*   `port_scan.md.j2` — Incident playbook for network reconnaissance and port scans.
*   `data_exfiltration.md.j2` — Incident playbook for FTP/unencrypted protocol exfiltration.
*   `brute_force_response.yaml.j2`, `port_scan_response.yaml.j2`, etc. — Legacy YAML-formatted response templates.

---

## Template Inheritance Model
Jinja2 template inheritance is used to reduce duplication. Child templates (such as `sqli_attempt.md.j2`) extend the parent template `base_playbook.md.j2` using:
```jinja2
{% extends "base_playbook.md.j2" %}
```

Child templates override specific layout regions called blocks (e.g., `{% block containment %}`) to inject attack-specific instructions while retaining the surrounding structural styling.

---

## The 7 Standard Sections

### 1. Header Block (`{% block header %}`)
Contains general metadata formatted as a Markdown table:
*   **Playbook ID**: Dynamic identifier (e.g., `PB-SQLI-001`).
*   **Severity**: Color-coded indicators based on severity (`🔴 CRITICAL`, `🟠 HIGH`, `🟡 MEDIUM`, `🟢 LOW`).
*   **Attack Pattern**: General category of the attack.
*   **Classification**: TLP level (`TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`).
*   **Timestamps & Versioning**: Generation time and software version.

### 2. Summary Block (`{% block summary %}`)
Provides a narrative overview of the campaign:
*   **Campaign Overview**: High-level explanation of the detected activity.
*   **Trigger Context**: Details on detection time, source/target IPs, and honeypot nodes.
*   **Affected Assets**: Target list of virtual machines or endpoints.
*   **Incident Priority**: Assessment of confidentiality, integrity, and availability impact.

### 3. IOC Table Block (`{% block ioc_table %}`)
Lists the collected indicators of compromise:
*   **Source IPs Table**: IP addresses, target ports, protocols, event counts, and threat intelligence standings.
*   **Forensic Hashes**: MD5/SHA256 file hashes captured from payload dropping.
*   **Domain & URL IOCs**: Hostnames and URLs queried during the campaign.

### 4. ATT&CK Mapping Block (`{% block attack_mapping %}`)
Correlates the incident with the MITRE ATT&CK framework:
*   Includes a structured table of Technique IDs, Tactic names, Sub-techniques, and descriptions.
*   Maps links directly to the official MITRE ATT&CK technique pages (e.g., `https://attack.mitre.org/techniques/T1190/`).

### 5. Containment Block (`{% block containment %}`)
Presents a phased checklist of containment actions:
*   **Phase 1 — Immediate Isolation**: Actions to block attacker traffic and restrict access (including shell command snippets for iptables, WAFs, or API endpoints).
*   **Phase 2 — Investigation**: Instructions for retrieving authentication/access logs and querying threat feeds.
*   **Phase 3 — Remediation & Hardening**: Long-term hardening steps (such as applying input sanitization, enabling MFA, or updating configurations).

### 6. Artifacts Block (`{% block artifacts %}`)
Identifies file pathways, log sources, and SIEM queries for search validation:
*   **Detection Rules**: Lists applicable Snort and Sigma rules.
*   **Log Sources**: Paths of access logs, database query logs, and network telemetry.
*   **SIEM Queries**: Ready-to-copy Splunk/Elasticsearch query strings matching the campaign patterns.
*   **Evidence Collection Paths**: PCAP and memory dump storage directories.

### 7. Appendix Block (`{% block appendix %}`)
Provides administrative wrap-up context:
*   **Escalation Contacts**: Table matching roles (SOC Lead, CISO, NetOps) with email/phone references.
*   **Rollback Procedures**: Steps to safely remove blocks or restore networks once verified clean.
*   **SLA Targets**: Time-to-detect, time-to-contain, and time-to-recover targets.
*   **Context Metadata**: Plain YAML block enclosing core parameters for easy machine parsing.

---

## Context Variables Reference
When invoking `PlaybookGenerator.generate(context)`, the `context` dictionary can populate the following parameters:

| Variable Name | Type | Description |
|:---|:---|:---|
| `title` | `str` | Playbook title displayed at the top |
| `playbook_id` | `str` | Unique playbook reference ID |
| `severity` | `str` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `classification` | `str` | TLP classification (default: `TLP:AMBER`) |
| `attack_pattern` | `str` | Attack category matching template mappings |
| `generated_at` | `str` | Timestamp of generation |
| `source_ip` | `str` | Primary attacker IP address |
| `target_ip` | `str` | Target system IP address |
| `target_url` | `str` | Target URL (HTTP SQLi or scan specific) |
| `db_engine` | `str` | Database type, e.g., `PostgreSQL` |
| `db_name` | `str` | Name of the database scheme targeted |
| `payload_sample` | `str` | Sample payload snippet observed |
| `iocs` | `list` | List of dicts representing IP/Port indicators |
| `ioc_hashes` | `list` | List of dicts with file hashes (`type`, `value`) |
| `ioc_domains` | `list` | List of domain indicators (`domain`, `resolved_ip`) |
| `ticket_system` | `str` | Target ticketing tracker name (default: `Jira`) |

---

## Adding a New Playbook Template

To add support for a new attack signature playbook:

1.  **Create the Child Template**:
    Write a new file under `backend/sentinel/templates/` (e.g., `custom_attack.md.j2`). Extend `base_playbook.md.j2` and override whichever blocks differ from the base:
    ```jinja2
    {% extends "base_playbook.md.j2" %}
    {% block containment %}
    ## 🚨 Containment Steps — Custom Attack
    - [ ] Stop custom service
    - [ ] Block source IP: `{{ source_ip }}`
    {% endblock %}
    ```

2.  **Register the Template Mapping**:
    Open `backend/sentinel/playbook_generator.py` and append your pattern-to-template mapping to the `_MD_PATTERN_MAP` list:
    ```python
    _MD_PATTERN_MAP: List[tuple] = [
        ...
        (
            ("custom_attack", "custom-attack", "signature_name"),
            "custom_attack.md.j2",
        ),
    ]
    ```

3.  **Provide Default ATT&CK Mappings**:
    Add the default MITRE ATT&CK techniques associated with this pattern inside `_DEFAULT_ATTACK_TECHNIQUES` for automatic fallback:
    ```python
    _DEFAULT_ATTACK_TECHNIQUES: Dict[str, List[Dict[str, str]]] = {
        ...
        "custom_attack": [
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}
        ]
    }
    ```
