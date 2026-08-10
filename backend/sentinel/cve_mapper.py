"""
backend/sentinel/cve_mapper.py
--------------------------------
Maps detected attack types, signatures, and technique IDs to known CVE references.

Enriches incident playbooks and STIX 2.1 bundles with relevant Common Vulnerabilities
and Exposures (CVE) context.
"""

from typing import List, Dict, Any, Optional

CVE_MAPPING_CATALOG: Dict[str, List[Dict[str, str]]] = {
    "HTTP_SQL_INJECTION": [
        {"cve_id": "CVE-2023-34362", "description": "MOVEit Transfer SQL Injection Vulnerability", "cvss": "9.8"},
        {"cve_id": "CVE-2021-22986", "description": "F5 BIG-IP iControl REST Remote Code Execution / SQLi", "cvss": "9.8"},
    ],
    "HTTP_PATH_TRAVERSAL": [
        {"cve_id": "CVE-2021-41773", "description": "Apache HTTP Server Path Traversal and RCE", "cvss": "7.5"},
        {"cve_id": "CVE-2020-5902", "description": "F5 BIG-IP TMUI Directory Traversal Vulnerability", "cvss": "9.8"},
    ],
    "SSH_AUTH_FAILURE": [
        {"cve_id": "CVE-2024-6387", "description": "OpenSSH regreSSHion Signal Handler Race Condition", "cvss": "8.1"},
        {"cve_id": "CVE-2018-15473", "description": "OpenSSH User Enumeration Vulnerability", "cvss": "5.3"},
    ],
    "FTP_ANONYMOUS_LOGIN": [
        {"cve_id": "CVE-2020-9273", "description": "ProFTPD Use-After-Free Vulnerability", "cvss": "8.8"},
    ],
    "SMTP_COMMAND_INJECTION": [
        {"cve_id": "CVE-2023-2868", "description": "Barracuda ESG Command Injection Vulnerability", "cvss": "9.8"},
    ],
    "T1110": [
        {"cve_id": "CVE-2024-6387", "description": "OpenSSH regreSSHion Signal Handler Race Condition", "cvss": "8.1"},
    ],
    "T1190": [
        {"cve_id": "CVE-2023-34362", "description": "MOVEit Transfer SQL Injection Vulnerability", "cvss": "9.8"},
        {"cve_id": "CVE-2021-41773", "description": "Apache HTTP Server Path Traversal and RCE", "cvss": "7.5"},
    ],
}


def get_cve_mappings(attack_type: Optional[str] = None, technique_id: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Retrieve matching CVE records for a given attack type or MITRE technique ID.

    Returns:
        List of dicts containing cve_id, description, and cvss.
    """
    results: List[Dict[str, str]] = []
    seen_ids = set()

    if attack_type and attack_type in CVE_MAPPING_CATALOG:
        for cve in CVE_MAPPING_CATALOG[attack_type]:
            if cve["cve_id"] not in seen_ids:
                results.append(cve)
                seen_ids.add(cve["cve_id"])

    if technique_id:
        # Check exact or prefix technique ID (e.g. T1110.001 -> T1110)
        base_tech = technique_id.split(".")[0]
        for key in (technique_id, base_tech):
            if key in CVE_MAPPING_CATALOG:
                for cve in CVE_MAPPING_CATALOG[key]:
                    if cve["cve_id"] not in seen_ids:
                        results.append(cve)
                        seen_ids.add(cve["cve_id"])

    return results
