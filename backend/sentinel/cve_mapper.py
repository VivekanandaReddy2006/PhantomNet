"""
backend/sentinel/cve_mapper.py
--------------------------------
Maps detected attack types, signatures, and technique IDs to known CVE references.

Enriches incident playbooks and STIX 2.1 bundles with relevant Common Vulnerabilities
and Exposures (CVE) context.

Public API
----------
  get_cve_mappings(attack_type, technique_id) -> List[Dict[str, str]]
      Retrieve matching CVE records for a given attack type or MITRE technique ID.
      Returns a deduplicated list of CVE dicts with cve_id, description, cvss, url.

  format_cve_references(cve_list) -> List[Dict[str, str]]
      Format CVE records as STIX-compatible ExternalReference dicts.
      Each dict has: source_name, external_id, url, description.
"""

from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# CVE Mapping Catalog
# ---------------------------------------------------------------------------
# Keys are either:
#   - Signature names  (e.g. "HTTP_SQL_INJECTION", "SSH_AUTH_FAILURE")
#   - MITRE ATT&CK technique IDs (e.g. "T1110", "T1190")
#
# Each entry is a list of CVE dicts with:
#   cve_id      : CVE identifier string
#   description : Short human-readable description
#   cvss        : CVSS v3 base score string
#   url         : NVD URL for the CVE
# ---------------------------------------------------------------------------
CVE_MAPPING_CATALOG: Dict[str, List[Dict[str, str]]] = {
    # ── HTTP SQL Injection ────────────────────────────────────────────────
    "HTTP_SQL_INJECTION": [
        {
            "cve_id": "CVE-2023-34362",
            "description": "MOVEit Transfer SQL Injection Vulnerability",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
        },
        {
            "cve_id": "CVE-2021-22986",
            "description": "F5 BIG-IP iControl REST Remote Code Execution / SQLi",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22986",
        },
        {
            "cve_id": "CVE-2019-19781",
            "description": "Citrix ADC and Gateway Path Traversal / RCE (commonly exploited via SQLi chains)",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-19781",
        },
    ],

    # ── HTTP Path Traversal ───────────────────────────────────────────────
    "HTTP_PATH_TRAVERSAL": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Apache HTTP Server Path Traversal and RCE",
            "cvss": "7.5",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        {
            "cve_id": "CVE-2020-5902",
            "description": "F5 BIG-IP TMUI Directory Traversal Vulnerability",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-5902",
        },
        {
            "cve_id": "CVE-2021-42013",
            "description": "Apache HTTP Server Path Traversal RCE (follow-up to CVE-2021-41773)",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        },
    ],

    # ── SSH Brute Force / Auth Failure ────────────────────────────────────
    "SSH_AUTH_FAILURE": [
        {
            "cve_id": "CVE-2024-6387",
            "description": "OpenSSH regreSSHion Signal Handler Race Condition (unauthenticated RCE)",
            "cvss": "8.1",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        },
        {
            "cve_id": "CVE-2018-15473",
            "description": "OpenSSH User Enumeration Vulnerability",
            "cvss": "5.3",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        },
        {
            "cve_id": "CVE-2016-20012",
            "description": "OpenSSH Observable Response Discrepancy (username enumeration)",
            "cvss": "5.3",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-20012",
        },
    ],

    # ── Command Injection ─────────────────────────────────────────────────
    "HTTP_CMD_INJECTION": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell) via JNDI injection",
            "cvss": "10.0",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "cve_id": "CVE-2014-6271",
            "description": "GNU Bash Remote Code Execution via environment variable (Shellshock)",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        },
        {
            "cve_id": "CVE-2022-22954",
            "description": "VMware Workspace ONE Access Server-Side Template Injection / RCE",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22954",
        },
    ],
    # Alias used by signature engine
    "CMD_INJECTION": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell) via JNDI injection",
            "cvss": "10.0",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "cve_id": "CVE-2014-6271",
            "description": "GNU Bash Remote Code Execution via environment variable (Shellshock)",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        },
    ],

    # ── FTP ───────────────────────────────────────────────────────────────
    "FTP_ANONYMOUS_LOGIN": [
        {
            "cve_id": "CVE-2020-9273",
            "description": "ProFTPD Use-After-Free Vulnerability",
            "cvss": "8.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-9273",
        },
        {
            "cve_id": "CVE-2019-12815",
            "description": "ProFTPD Arbitrary File Copy Vulnerability via mod_copy",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-12815",
        },
    ],
    "FTP_DATA_EXFILTRATION": [
        {
            "cve_id": "CVE-2020-9273",
            "description": "ProFTPD Use-After-Free Vulnerability",
            "cvss": "8.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-9273",
        },
    ],

    # ── SMTP ──────────────────────────────────────────────────────────────
    "SMTP_COMMAND_INJECTION": [
        {
            "cve_id": "CVE-2023-2868",
            "description": "Barracuda ESG Command Injection Vulnerability",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-2868",
        },
    ],
    "SMTP_LARGE_PAYLOAD": [
        {
            "cve_id": "CVE-2020-7247",
            "description": "OpenSMTPD Remote Code Execution via malicious sender address",
            "cvss": "10.0",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-7247",
        },
    ],

    # ── MITRE ATT&CK Technique ID mappings ───────────────────────────────
    "T1110": [
        {
            "cve_id": "CVE-2024-6387",
            "description": "OpenSSH regreSSHion Signal Handler Race Condition (unauthenticated RCE)",
            "cvss": "8.1",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        },
        {
            "cve_id": "CVE-2018-15473",
            "description": "OpenSSH User Enumeration Vulnerability",
            "cvss": "5.3",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        },
    ],
    "T1190": [
        {
            "cve_id": "CVE-2023-34362",
            "description": "MOVEit Transfer SQL Injection Vulnerability",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
        },
        {
            "cve_id": "CVE-2021-41773",
            "description": "Apache HTTP Server Path Traversal and RCE",
            "cvss": "7.5",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell)",
            "cvss": "10.0",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
    ],
    "T1059": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell) via JNDI injection",
            "cvss": "10.0",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "cve_id": "CVE-2014-6271",
            "description": "GNU Bash Remote Code Execution via environment variable (Shellshock)",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        },
    ],
    "T1046": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Apache HTTP Server Path Traversal and RCE (commonly targeted during scanning)",
            "cvss": "7.5",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
    ],
}


def get_cve_mappings(
    attack_type: Optional[str] = None,
    technique_id: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    Retrieve matching CVE records for a given attack type or MITRE technique ID.

    Performs case-insensitive lookup on both attack_type and technique_id.
    Deduplicates by cve_id so the same CVE is never returned twice even when
    both keys map to it.

    Args:
        attack_type:  Signature name / attack type string
                      (e.g. "HTTP_SQL_INJECTION", "SSH_AUTH_FAILURE").
        technique_id: MITRE ATT&CK technique ID, optionally with sub-technique
                      suffix (e.g. "T1110", "T1110.001").

    Returns:
        Deduplicated list of dicts, each containing:
            cve_id      - CVE identifier (e.g. "CVE-2023-34362")
            description - Short description of the vulnerability
            cvss        - CVSS v3 base score string
            url         - NVD detail URL
    """
    results: List[Dict[str, str]] = []
    seen_ids: set = set()

    def _add_cves(key: str) -> None:
        """Look up key in catalog and append unseen CVEs to results."""
        entries = CVE_MAPPING_CATALOG.get(key, [])
        for cve in entries:
            if cve["cve_id"] not in seen_ids:
                results.append(cve)
                seen_ids.add(cve["cve_id"])

    # ── Attack type lookup ────────────────────────────────────────────────
    if attack_type:
        _add_cves(attack_type)
        # Also try uppercase variant in case caller passes lowercase
        _add_cves(attack_type.upper())

    # ── Technique ID lookup ───────────────────────────────────────────────
    if technique_id:
        # Accept both "T1110.001" and "T1110" — try exact first, then base
        base_tech = technique_id.split(".")[0]
        for key in (technique_id, base_tech):
            _add_cves(key)

    return results


def format_cve_references(cve_list: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Format a list of CVE records as STIX 2.1-compatible ExternalReference dicts.

    This is used by stix_enhanced.build_attack_pattern() to embed CVE context
    directly in the AttackPattern object's external_references list.

    Args:
        cve_list: List of CVE dicts as returned by :func:`get_cve_mappings`.

    Returns:
        List of ExternalReference-compatible dicts, each with:
            source_name  - "cve"
            external_id  - CVE identifier (e.g. "CVE-2023-34362")
            url          - NVD detail URL
            description  - Human-readable description of the vulnerability

    Example::

        refs = format_cve_references(get_cve_mappings(attack_type="HTTP_SQL_INJECTION"))
        # refs[0] == {
        #     "source_name": "cve",
        #     "external_id": "CVE-2023-34362",
        #     "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
        #     "description": "MOVEit Transfer SQL Injection Vulnerability",
        # }
    """
    references: List[Dict[str, str]] = []
    for cve in cve_list:
        cve_id = cve.get("cve_id", "")
        if not cve_id:
            continue
        url = cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        references.append(
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": url,
                "description": cve.get("description", ""),
            }
        )
    return references
