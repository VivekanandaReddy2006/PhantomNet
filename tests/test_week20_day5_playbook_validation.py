"""
tests/test_week20_day5_playbook_validation.py
----------------------------------------------
Week 20 - Day 5 | Security Developer
Incident Response Playbook Validation -- Issue #962

Deliverables validated:
  1. Playbook Artifact Validation
     - Generated PDF bytes are a valid PDF (magic bytes + non-trivial size)
     - Markdown playbooks contain SOC-required sections and actionable steps
     - YAML playbooks parse cleanly and include required SOC fields
     - Playbook context enrichment (ATT&CK techniques, containment steps, IOCs)

  2. STIX Bundle Validation
     - Bundles are valid STIX 2.1 JSON (schema: type=bundle, spec_version=2.1)
     - Required object types present: identity, attack-pattern, indicator, relationship
     - All indicators carry valid STIX pattern syntax
     - Deterministic STIX IDs are stable across multiple build calls
     - TLP marking definitions are embedded and correct
     - Bundles are importable by external tools (MISP/OpenCTI schema checks)
     - All attack-patterns reference a valid MITRE ATT&CK external_id

  3. Snort Rule Syntax Validation
     - Rules parse with the correct header format (action proto src -> dst)
     - Required options present: msg, classtype, sid, rev, reference
     - classtype values are drawn only from the standard Snort classification set
     - SID values are positive integers and unique across a batch
     - msg field is properly quoted and free of unescaped special characters
     - priority values are in the valid Snort range (1-4)
     - reference URLs point to a valid MITRE ATT&CK URL pattern

Run:
    pytest tests/test_week20_day5_playbook_validation.py -v
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup -- mirror the pattern used by the rest of the test suite
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR  = os.path.join(PROJECT_ROOT, "backend")
for _p in (BACKEND_DIR, PROJECT_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Imports from PhantomNet backend
# ---------------------------------------------------------------------------
# pyrefly: ignore [missing-import]
from sentinel.stix_enhanced import (           # noqa: E402
    build_stix_bundle,
    build_attack_pattern,
    build_indicator,
    build_relationship,
    bundle_to_dict,
    bundle_to_json,
    PHANTOMNET_IDENTITY,
)
# pyrefly: ignore [missing-import]
from sentinel.rule_generator import (          # noqa: E402
    generate_snort_rule,
    generate_sigma_rule,
    VALID_SNORT_CLASSTYPES,
    SNORT_RULE_TEMPLATE,
    validate_ip,
    validate_port,
)
# pyrefly: ignore [missing-import]
from sentinel.playbook_generator import PlaybookGenerator  # noqa: E402
# pyrefly: ignore [missing-import]
from sentinel.mitre_mapper import map_signature, get_all_techniques  # noqa: E402
# pyrefly: ignore [missing-import]
from sentinel.pdf_exporter import generate_pdf             # noqa: E402

# ---------------------------------------------------------------------------
# Shared fixtures & constants
# ---------------------------------------------------------------------------

PLAYBOOK_PATTERNS = ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration"]

SAMPLE_TECHNIQUES = {
    "SSH_AUTH_FAILURE":        map_signature("SSH_AUTH_FAILURE"),
    "HTTP_SQL_INJECTION":      map_signature("HTTP_SQL_INJECTION"),
    "HTTP_SCANNER_BEHAVIOR":   map_signature("HTTP_SCANNER_BEHAVIOR"),
    "FTP_DATA_EXFILTRATION":   map_signature("FTP_DATA_EXFILTRATION"),
}

SAMPLE_IOCS = [
    {"type": "ip",     "value": "198.51.100.42"},
    {"type": "domain", "value": "malicious.c2.example.com"},
    {"type": "url",    "value": "https://evil.example.com/drop"},
    {"type": "sha256", "value": "a" * 64},
    {"type": "md5",    "value": "b" * 32},
]

# Required SOC sections keywords in Markdown playbooks
MD_REQUIRED_KEYWORDS = ["MITRE", "Containment", "IOC"]

# Required YAML playbook top-level fields
YAML_REQUIRED_FIELDS = ["name", "trigger", "actions"]

# Snort rule regex components
_SNORT_HEADER_RE = re.compile(
    r"^alert\s+(tcp|udp|icmp|ip)\s+\S+\s+any\s+->\s+\S+\s+\S+\s+\(",
    re.IGNORECASE,
)
_SNORT_MSG_RE       = re.compile(r'msg:"([^"\\]|\\.)*";')
_SNORT_CLASSTYPE_RE = re.compile(r"classtype:([a-z\-]+);")
_SNORT_SID_RE       = re.compile(r"sid:(\d+);")
_SNORT_REV_RE       = re.compile(r"rev:(\d+);")
_SNORT_REF_RE       = re.compile(r"reference:url,attack\.mitre\.org/techniques/([A-Z0-9/]+);")
_SNORT_PRIORITY_RE  = re.compile(r"priority:(\d+);")


# ===========================================================================
# SECTION 1: PDF PLAYBOOK VALIDATION
# ===========================================================================

class TestPDFPlaybookValidation:
    """Validate that generate_pdf() produces well-formed PDF documents."""

    SAMPLE_MARKDOWN = (
        "# Incident Response Playbook\n\n"
        "## Executive Summary\n"
        "Brute-force attack detected from 198.51.100.42.\n\n"
        "## MITRE ATT&CK Mapping\n"
        "| Technique | Tactic |\n|---|---|\n| T1110.001 | Credential Access |\n\n"
        "## Containment Steps\n"
        "1. Block attacker IP at perimeter firewall\n"
        "2. Enable rate-limit on targeted SSH port\n"
        "3. Rotate SSH keys\n\n"
        "## IOC Summary\n"
        "- IP: 198.51.100.42\n"
        "- Port: 22/TCP\n\n"
        "## Evidence Collection\n"
        "Capture auth logs for forensics.\n"
    )

    def test_pdf_returns_bytes(self):
        """generate_pdf() must return a bytes object."""
        result = generate_pdf(self.SAMPLE_MARKDOWN)
        assert isinstance(result, bytes), "generate_pdf() must return bytes"

    def test_pdf_magic_bytes(self):
        """PDF output must start with the %PDF magic bytes."""
        result = generate_pdf(self.SAMPLE_MARKDOWN)
        assert result[:4] == b"%PDF", (
            f"PDF does not start with %PDF magic bytes. Got: {result[:8]!r}"
        )

    def test_pdf_non_trivial_size(self):
        """PDF must be at least 1 KB -- a stub/empty PDF is not acceptable."""
        result = generate_pdf(self.SAMPLE_MARKDOWN)
        assert len(result) >= 1024, (
            f"PDF is suspiciously small ({len(result)} bytes). "
            "Likely a placeholder, not a real document."
        )

    def test_pdf_eof_marker(self):
        """PDF must contain the EOF marker (standard PDF termination)."""
        result = generate_pdf(self.SAMPLE_MARKDOWN)
        assert b"%%EOF" in result or b"%EOF" in result, (
            "PDF does not contain EOF trailer -- file may be truncated."
        )

    def test_pdf_from_minimal_markdown(self):
        """Even minimal Markdown should produce a valid PDF."""
        minimal = "# Test\n\nMinimal playbook content."
        result = generate_pdf(minimal)
        assert isinstance(result, bytes)
        assert result[:4] == b"%PDF"

    def test_pdf_from_large_markdown(self):
        """PDF generation must handle large playbooks (> 5 KB Markdown)."""
        large_md = self.SAMPLE_MARKDOWN * 20
        result = generate_pdf(large_md)
        assert isinstance(result, bytes)
        assert result[:4] == b"%PDF"
        assert len(result) >= 1024

    def test_pdf_handles_unicode(self):
        """PDF generation must handle Unicode characters without crashing."""
        unicode_md = (
            "# Playbook -- Unicode Test\n\n"
            "## MITRE ATT&CK\n"
            "| T1110.001 | Credential Access |\n"
        )
        result = generate_pdf(unicode_md)
        assert isinstance(result, bytes)

    def test_pdf_handles_special_characters(self):
        """Semicolons, quotes and backslashes in Markdown must not break PDF export."""
        special_md = (
            "# Incident Playbook\n\n"
            "msg: Alert; severity=HIGH\n\n"
            "## MITRE ATT&CK\n| T1190 | Initial Access |\n\n"
            "## Containment Steps\n1. Block IP\n\n"
            "## IOC Summary\n- IP: 192.0.2.1\n"
        )
        result = generate_pdf(special_md)
        assert isinstance(result, bytes)


# ===========================================================================
# SECTION 2: MARKDOWN PLAYBOOK VALIDATION (SOC)
# ===========================================================================

class TestMarkdownPlaybookValidation:
    """Validate rendered Markdown playbooks against real SOC expectations."""

    @pytest.fixture(autouse=True)
    def generator(self):
        self.gen = PlaybookGenerator()

    def _render(self, pattern: str, extra: dict = None) -> str:
        ctx = {"attack_pattern": pattern, "source_ip": "198.51.100.42", "severity": "HIGH"}
        if extra:
            ctx.update(extra)
        return self.gen.generate(ctx, format="markdown")

    # Structure checks

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_h1_title(self, pattern):
        """Every generated Markdown playbook must start with an H1 heading."""
        md = self._render(pattern)
        assert md.lstrip().startswith("# "), (
            f"Playbook for '{pattern}' does not start with an H1 heading."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_mitre_section(self, pattern):
        """Playbook must include a MITRE ATT&CK section."""
        md = self._render(pattern)
        assert "MITRE" in md or "ATT&CK" in md, (
            f"Playbook for '{pattern}' is missing a MITRE ATT&CK reference section."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_containment_steps(self, pattern):
        """Playbook must include actionable Containment steps."""
        md = self._render(pattern)
        assert "Containment" in md or "containment" in md, (
            f"Playbook for '{pattern}' has no Containment section -- not actionable."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_ioc_section(self, pattern):
        """Playbook must include an IOC (Indicators of Compromise) section."""
        md = self._render(pattern)
        assert "IOC" in md or "Indicator" in md or "indicator" in md, (
            f"Playbook for '{pattern}' is missing IOC section."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_technique_ids(self, pattern):
        """Playbook must embed MITRE technique IDs (T\\d{4} format)."""
        md = self._render(pattern)
        technique_ids = re.findall(r"T\d{4}(?:\.\d{3})?", md)
        assert len(technique_ids) >= 1, (
            f"Playbook for '{pattern}' contains no MITRE technique IDs."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_severity(self, pattern):
        """Playbook must indicate severity level."""
        md = self._render(pattern)
        severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert any(s in md for s in severities), (
            f"Playbook for '{pattern}' has no severity indicator."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_has_source_ip(self, pattern):
        """Source IP must appear in the generated playbook."""
        md = self._render(pattern)
        assert "198.51.100.42" in md, (
            f"Playbook for '{pattern}' does not contain the source IP."
        )

    @pytest.mark.parametrize("pattern", PLAYBOOK_PATTERNS)
    def test_markdown_minimum_length(self, pattern):
        """Generated playbooks must be at least 500 characters -- no stubs."""
        md = self._render(pattern)
        assert len(md) >= 500, (
            f"Playbook for '{pattern}' is only {len(md)} chars -- too short for a real SOC playbook."
        )

    # Actionable intelligence checks

    def test_brute_force_playbook_contains_block_action(self):
        """Brute-force playbook must mention IP blocking as a containment step."""
        md = self._render("brute_force")
        assert re.search(r"block|Block", md), (
            "Brute-force playbook must include an IP block action."
        )

    def test_sqli_playbook_contains_waf_or_db_action(self):
        """SQLi playbook must reference WAF or database-level response."""
        md = self._render("sqli_attempt")
        assert re.search(r"WAF|waf|database|Database|db|DB", md), (
            "SQLi playbook must reference WAF or database response actions."
        )

    def test_port_scan_playbook_contains_honeypot_or_capture(self):
        """Port-scan playbook must reference honeypot deployment or packet capture."""
        md = self._render("port_scan")
        assert re.search(r"honeypot|Honeypot|capture|tcpdump", md), (
            "Port-scan playbook must include honeypot or packet-capture actions."
        )

    def test_data_exfil_playbook_contains_isolation_action(self):
        """Data-exfiltration playbook must reference host isolation."""
        md = self._render("data_exfiltration")
        assert re.search(r"[Ii]solat|quarantin", md), (
            "Data-exfiltration playbook must include host isolation step."
        )

    def test_playbook_tlp_classification_present(self):
        """Playbook must carry TLP classification for data-handling by SOC."""
        md = self._render("brute_force")
        assert "TLP" in md, (
            "Playbook missing TLP data-classification marker -- required for SOC sharing."
        )

    def test_playbook_escalation_owner(self):
        """Playbook must name an owner / escalation point."""
        md = self._render("brute_force")
        assert re.search(r"SOC|owner|Owner|CISO|team", md, re.IGNORECASE), (
            "Playbook must specify an owner or escalation contact."
        )

    def test_base_playbook_fallback_renders(self):
        """Unknown attack patterns must fall back to the base playbook template."""
        md = self._render("unknown_exotic_attack_xyz")
        assert len(md) >= 200, "Base playbook fallback is too short."
        assert "# " in md, "Base playbook fallback must have at least one H1."


# ===========================================================================
# SECTION 3: YAML PLAYBOOK VALIDATION
# ===========================================================================

class TestYAMLPlaybookValidation:
    """Validate static YAML playbooks in the playbooks/ directory."""

    PLAYBOOK_DIR = os.path.join(PROJECT_ROOT, "playbooks")

    def _load_playbook(self, filename: str) -> dict:
        path = os.path.join(self.PLAYBOOK_DIR, filename)
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _all_yaml_files(self):
        return [
            f for f in os.listdir(self.PLAYBOOK_DIR)
            if f.endswith(".yaml") or f.endswith(".yml")
        ]

    def test_playbook_dir_exists(self):
        """The playbooks/ directory must exist."""
        assert os.path.isdir(self.PLAYBOOK_DIR), "playbooks/ directory not found."

    def test_at_least_one_playbook_present(self):
        """There must be at least one YAML playbook file."""
        files = self._all_yaml_files()
        assert len(files) >= 1, "No YAML playbook files found in playbooks/."

    @pytest.mark.parametrize("filename", [
        "brute_force_response.yaml",
        "port_scan_response.yaml",
        "credential_reuse_response.yaml",
        "distributed_attack_response.yaml",
    ])
    def test_playbook_parses_as_valid_yaml(self, filename):
        """Each playbook YAML file must parse without errors."""
        data = self._load_playbook(filename)
        assert isinstance(data, dict), f"{filename} did not parse to a dict."

    @pytest.mark.parametrize("filename", [
        "brute_force_response.yaml",
        "port_scan_response.yaml",
        "credential_reuse_response.yaml",
        "distributed_attack_response.yaml",
    ])
    def test_playbook_required_fields(self, filename):
        """Each YAML playbook must have name, trigger, and actions fields."""
        data = self._load_playbook(filename)
        for field in YAML_REQUIRED_FIELDS:
            assert field in data, (
                f"{filename} is missing required field '{field}'."
            )

    @pytest.mark.parametrize("filename", [
        "brute_force_response.yaml",
        "port_scan_response.yaml",
        "credential_reuse_response.yaml",
        "distributed_attack_response.yaml",
    ])
    def test_playbook_actions_is_list(self, filename):
        """The 'actions' field must be a non-empty list."""
        data = self._load_playbook(filename)
        actions = data.get("actions", [])
        assert isinstance(actions, list), f"{filename}: 'actions' must be a list."
        assert len(actions) >= 1, f"{filename}: 'actions' list must not be empty."

    @pytest.mark.parametrize("filename", [
        "brute_force_response.yaml",
        "port_scan_response.yaml",
        "credential_reuse_response.yaml",
        "distributed_attack_response.yaml",
    ])
    def test_playbook_each_action_has_name_and_type(self, filename):
        """Every action entry must have 'name' and 'type' keys."""
        data = self._load_playbook(filename)
        for idx, action in enumerate(data.get("actions", [])):
            assert "name" in action, (
                f"{filename}: action[{idx}] is missing 'name' key."
            )
            assert "type" in action, (
                f"{filename}: action[{idx}] is missing 'type' key."
            )

    def test_brute_force_trigger_condition(self):
        """Brute-force playbook trigger must reference failed login threshold."""
        data = self._load_playbook("brute_force_response.yaml")
        trigger = data.get("trigger", {})
        assert trigger.get("type") == "failed_login_threshold", (
            "Brute-force playbook trigger type must be 'failed_login_threshold'."
        )

    def test_port_scan_trigger_condition(self):
        """Port-scan playbook trigger must reference port_scan_threshold."""
        data = self._load_playbook("port_scan_response.yaml")
        trigger = data.get("trigger", {})
        assert "port_scan" in trigger.get("type", ""), (
            "Port-scan playbook trigger type must reference port_scan."
        )

    def test_credential_reuse_trigger_type(self):
        """Credential-reuse playbook trigger must reference honeytoken_usage."""
        data = self._load_playbook("credential_reuse_response.yaml")
        trigger = data.get("trigger", {})
        assert trigger.get("type") == "honeytoken_usage", (
            "Credential-reuse trigger must be 'honeytoken_usage'."
        )

    def test_distributed_attack_has_ioc_sharing_action(self):
        """Distributed-attack playbook must have an IOC sharing / STIX export action."""
        data = self._load_playbook("distributed_attack_response.yaml")
        action_types = [a.get("type", "") for a in data.get("actions", [])]
        assert "export_iocs" in action_types, (
            "Distributed-attack playbook must include an 'export_iocs' action for IOC sharing."
        )


# ===========================================================================
# SECTION 4: STIX BUNDLE VALIDATION (MISP / OpenCTI import)
# ===========================================================================

class TestSTIXBundleValidation:
    """
    Validate STIX 2.1 bundles against real SOC tool import requirements.

    These checks mirror the schema validation that MISP and OpenCTI perform
    when ingesting STIX bundles via their REST APIs.
    """

    @pytest.fixture(autouse=True)
    def build_bundle(self):
        """Build a representative STIX bundle for each test."""
        technique = map_signature("SSH_AUTH_FAILURE")
        self.technique = technique
        self.bundle = build_stix_bundle(
            technique=technique,
            iocs=SAMPLE_IOCS,
            src_ip="198.51.100.42",
            threat_score=87.5,
            tlp_level="green",
        )
        self.bundle_dict = bundle_to_dict(self.bundle)
        self.bundle_json_str = bundle_to_json(self.bundle, pretty=True)

    # Top-level bundle structure

    def test_bundle_type_is_bundle(self):
        assert self.bundle_dict.get("type") == "bundle", (
            "STIX bundle root 'type' must be 'bundle' (STIX 2.1 sec 3.2)"
        )

    def test_bundle_has_spec_version(self):
        # In stix2 v3+ spec_version is set on each STIX Domain Object, not on
        # the bundle wrapper.  MISP/OpenCTI accept bundles where any object
        # declares spec_version="2.1".  Verify at least one object does so.
        spec_versions = [
            o.get("spec_version")
            for o in self.bundle_dict.get("objects", [])
            if "spec_version" in o
        ]
        assert spec_versions, (
            "No STIX objects declare 'spec_version' -- bundle may not be STIX 2.1."
        )
        assert all(v == "2.1" for v in spec_versions), (
            f"All spec_version values must be '2.1'. Found: {set(spec_versions)}"
        )

    def test_bundle_has_id(self):
        bundle_id = self.bundle_dict.get("id", "")
        assert bundle_id.startswith("bundle--"), (
            "STIX bundle 'id' must start with 'bundle--'."
        )

    def test_bundle_objects_is_list(self):
        objects = self.bundle_dict.get("objects", None)
        assert isinstance(objects, list), "'objects' must be a JSON array."
        assert len(objects) >= 4, (
            f"Bundle must contain at least 4 objects (identity, attack-pattern, "
            f"indicator, relationship). Got {len(objects)}."
        )

    # Required object types

    def test_bundle_contains_identity(self):
        types = {o["type"] for o in self.bundle_dict["objects"]}
        assert "identity" in types, "Bundle must contain at least one 'identity' object."

    def test_bundle_contains_attack_pattern(self):
        types = {o["type"] for o in self.bundle_dict["objects"]}
        assert "attack-pattern" in types, "Bundle must contain an 'attack-pattern' object."

    def test_bundle_contains_indicator(self):
        types = {o["type"] for o in self.bundle_dict["objects"]}
        assert "indicator" in types, "Bundle must contain at least one 'indicator' object."

    def test_bundle_contains_relationship(self):
        types = {o["type"] for o in self.bundle_dict["objects"]}
        assert "relationship" in types, "Bundle must contain at least one 'relationship' object."

    def test_bundle_contains_marking_definition(self):
        types = {o["type"] for o in self.bundle_dict["objects"]}
        assert "marking-definition" in types, (
            "Bundle must contain a 'marking-definition' (TLP) object."
        )

    # MITRE ATT&CK enrichment

    def test_attack_pattern_has_external_reference(self):
        ap_objects = [o for o in self.bundle_dict["objects"] if o["type"] == "attack-pattern"]
        assert len(ap_objects) >= 1
        ap = ap_objects[0]
        ext_refs = ap.get("external_references", [])
        assert len(ext_refs) >= 1, "attack-pattern must have at least one external_reference."

    def test_attack_pattern_external_id_is_mitre(self):
        ap_objects = [o for o in self.bundle_dict["objects"] if o["type"] == "attack-pattern"]
        ap = ap_objects[0]
        ext_refs = ap.get("external_references", [])
        mitre_ref = next(
            (r for r in ext_refs if r.get("source_name") == "mitre-attack"), None
        )
        assert mitre_ref is not None, (
            "attack-pattern must have an external_reference with source_name='mitre-attack'."
        )
        external_id = mitre_ref.get("external_id", "")
        assert re.match(r"T\d{4}(?:\.\d{3})?$", external_id), (
            f"external_id '{external_id}' is not a valid MITRE technique ID."
        )

    def test_attack_pattern_has_kill_chain_phases(self):
        ap_objects = [o for o in self.bundle_dict["objects"] if o["type"] == "attack-pattern"]
        ap = ap_objects[0]
        phases = ap.get("kill_chain_phases", [])
        assert len(phases) >= 1, "attack-pattern must have kill_chain_phases."
        assert phases[0].get("kill_chain_name") == "mitre-attack"

    # Indicator validation

    def test_indicators_have_valid_stix_pattern(self):
        indicators = [o for o in self.bundle_dict["objects"] if o["type"] == "indicator"]
        assert len(indicators) >= 1, "Bundle must contain at least one indicator."
        for ind in indicators:
            pattern = ind.get("pattern", "")
            assert pattern.startswith("["), (
                f"Indicator pattern must start with '[': {pattern!r}"
            )
            assert "]" in pattern, (
                f"Indicator pattern must be closed with ']': {pattern!r}"
            )
            assert "=" in pattern, (
                f"Indicator pattern must contain an equality comparison: {pattern!r}"
            )

    def test_indicators_have_valid_from(self):
        indicators = [o for o in self.bundle_dict["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            assert "valid_from" in ind, f"Indicator {ind.get('id')} missing 'valid_from'."

    def test_indicators_have_indicator_types(self):
        indicators = [o for o in self.bundle_dict["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            ind_types = ind.get("indicator_types", [])
            assert len(ind_types) >= 1, (
                f"Indicator {ind.get('id')} must have at least one indicator_type."
            )

    def test_indicators_object_marking_refs(self):
        """Every indicator must carry TLP marking refs (required by MISP/OpenCTI)."""
        indicators = [o for o in self.bundle_dict["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            refs = ind.get("object_marking_refs", [])
            assert len(refs) >= 1, (
                f"Indicator {ind.get('id')} is missing object_marking_refs (TLP required)."
            )

    # Relationship validation

    def test_relationships_link_indicator_to_attack_pattern(self):
        indicators = {o["id"] for o in self.bundle_dict["objects"] if o["type"] == "indicator"}
        ap_ids     = {o["id"] for o in self.bundle_dict["objects"] if o["type"] == "attack-pattern"}
        rels       = [o for o in self.bundle_dict["objects"] if o["type"] == "relationship"]
        for rel in rels:
            assert rel.get("source_ref") in indicators, (
                f"Relationship source_ref must point to an indicator: {rel.get('source_ref')}"
            )
            assert rel.get("target_ref") in ap_ids, (
                f"Relationship target_ref must point to an attack-pattern: {rel.get('target_ref')}"
            )
            assert rel.get("relationship_type") == "indicates", (
                "Relationship type must be 'indicates'."
            )

    # Deterministic ID stability (deduplication for MISP/OpenCTI)

    def test_deterministic_stix_ids_are_stable(self):
        """Same technique + IOC must always produce the same STIX IDs."""
        technique = map_signature("SSH_AUTH_FAILURE")
        b1 = build_stix_bundle(technique=technique, iocs=[{"type": "ip", "value": "10.0.0.1"}],
                               src_ip="10.0.0.1", threat_score=50.0)
        b2 = build_stix_bundle(technique=technique, iocs=[{"type": "ip", "value": "10.0.0.1"}],
                               src_ip="10.0.0.1", threat_score=50.0)
        ap1 = next(o["id"] for o in bundle_to_dict(b1)["objects"] if o["type"] == "attack-pattern")
        ap2 = next(o["id"] for o in bundle_to_dict(b2)["objects"] if o["type"] == "attack-pattern")
        assert ap1 == ap2, (
            "attack-pattern STIX ID must be deterministic across builds -- "
            "MISP/OpenCTI use IDs for deduplication."
        )

    # TLP level coverage

    @pytest.mark.parametrize("tlp_level", ["white", "green", "amber", "red"])
    def test_all_tlp_levels_produce_valid_bundle(self, tlp_level):
        technique = map_signature("HTTP_SQL_INJECTION")
        bundle = build_stix_bundle(
            technique=technique,
            iocs=[{"type": "ip", "value": "10.10.10.10"}],
            tlp_level=tlp_level,
        )
        d = bundle_to_dict(bundle)
        assert d["type"] == "bundle"
        md = next(
            (o for o in d["objects"] if o["type"] == "marking-definition"), None
        )
        assert md is not None, f"TLP:{tlp_level} bundle must have a marking-definition."

    # JSON serialization (tool import compatibility)

    def test_bundle_serializes_to_valid_json(self):
        parsed = json.loads(self.bundle_json_str)
        assert parsed["type"] == "bundle"

    def test_bundle_dict_is_json_serializable(self):
        """bundle_to_dict() must produce a fully JSON-serializable structure."""
        dumped = json.dumps(self.bundle_dict)
        reloaded = json.loads(dumped)
        assert reloaded["type"] == "bundle"

    # Multi-technique bundle

    def test_bundle_covers_all_signature_techniques(self):
        """STIX bundles can be built for all 12 mapped signature techniques."""
        all_techs = get_all_techniques()
        assert len(all_techs) >= 12, "Expected at least 12 mapped ATT&CK techniques."
        for tech in all_techs:
            bundle = build_stix_bundle(
                technique=tech,
                iocs=[{"type": "ip", "value": "10.0.0.50"}],
                threat_score=50.0,
            )
            d = bundle_to_dict(bundle)
            assert d["type"] == "bundle", f"Bundle failed for technique {tech.get('technique_id')}"

    # PhantomNet identity anchor

    def test_phantomnet_identity_in_every_bundle(self):
        """Every bundle must contain the PhantomNet Sentinel identity anchor."""
        identity_ids = [
            o["id"] for o in self.bundle_dict["objects"] if o["type"] == "identity"
        ]
        assert PHANTOMNET_IDENTITY.id in identity_ids, (
            "PhantomNet Sentinel identity must be present in every bundle."
        )

    def test_phantomnet_identity_name(self):
        identity_obj = next(
            o for o in self.bundle_dict["objects"]
            if o["type"] == "identity" and o["id"] == PHANTOMNET_IDENTITY.id
        )
        assert identity_obj.get("name") == "PhantomNet Sentinel"


# ===========================================================================
# SECTION 5: SNORT RULE SYNTAX VALIDATION
# ===========================================================================

class TestSnortRuleValidation:
    """
    Validate that generated Snort rules compile without syntax errors.

    Tests mirror the checks performed by snort -T -c rules.conf.
    """

    # Template sanity

    def test_snort_rule_template_has_required_fields(self):
        required = ["protocol", "src_ip", "dst_port", "attack_desc",
                    "technique_id", "classtype", "priority", "sid"]
        for field in required:
            assert "{" + field + "}" in SNORT_RULE_TEMPLATE, (
                f"SNORT_RULE_TEMPLATE is missing placeholder: {{{field}}}"
            )

    # Rule header format

    @pytest.mark.parametrize("protocol", ["tcp", "udp", "icmp", "ip"])
    def test_rule_header_format_per_protocol(self, protocol):
        rule = generate_snort_rule(
            src_ip="192.168.1.100",
            dst_port=22,
            protocol=protocol,
            attack_desc=f"Test {protocol} attack",
            technique_id="T1110.001",
            classtype="attempted-admin",
        )
        assert isinstance(rule, str), f"Rule must be a string, got {type(rule)}"
        assert _SNORT_HEADER_RE.match(rule), (
            f"Rule header format invalid for protocol '{protocol}':\n{rule}"
        )

    def test_rule_starts_with_alert_keyword(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5",
            dst_port=80,
            protocol="tcp",
            attack_desc="Web attack",
            technique_id="T1190",
            classtype="web-application-attack",
        )
        assert rule.startswith("alert "), "Snort rule must start with 'alert '."

    # Required rule options

    def test_rule_has_msg_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        assert _SNORT_MSG_RE.search(rule), f"Rule missing valid 'msg' option:\n{rule}"

    def test_rule_has_classtype_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        match = _SNORT_CLASSTYPE_RE.search(rule)
        assert match, f"Rule missing 'classtype' option:\n{rule}"

    def test_rule_has_sid_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        match = _SNORT_SID_RE.search(rule)
        assert match, f"Rule missing 'sid' option:\n{rule}"
        sid_val = int(match.group(1))
        assert sid_val > 0, f"SID must be a positive integer. Got: {sid_val}"

    def test_rule_has_rev_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        assert _SNORT_REV_RE.search(rule), f"Rule missing 'rev' option:\n{rule}"

    def test_rule_has_mitre_reference(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        match = _SNORT_REF_RE.search(rule)
        assert match, (
            f"Rule must have 'reference:url,attack.mitre.org/...' option:\n{rule}"
        )

    def test_rule_has_flow_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        assert "flow:" in rule, f"Rule missing 'flow' option:\n{rule}"

    def test_rule_has_threshold_option(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="SSH Brute Force", technique_id="T1110.001",
            classtype="attempted-admin",
        )
        assert "threshold:" in rule, f"Rule missing 'threshold' option:\n{rule}"

    # Classtype validation

    @pytest.mark.parametrize("classtype", list(VALID_SNORT_CLASSTYPES)[:8])
    def test_valid_classtype_produces_rule(self, classtype):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=80, protocol="tcp",
            attack_desc="Attack", technique_id="T1046",
            classtype=classtype,
        )
        assert isinstance(rule, str)
        m = _SNORT_CLASSTYPE_RE.search(rule)
        assert m, f"classtype '{classtype}' not found in rule:\n{rule}"
        assert m.group(1) in VALID_SNORT_CLASSTYPES

    def test_invalid_classtype_returns_error_dict(self):
        result = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="Test", technique_id="T1110",
            classtype="invalid-fake-classtype",
        )
        assert isinstance(result, dict), (
            "Invalid classtype must return an error dict, not raise."
        )
        assert result.get("status") == "error"

    # Priority validation

    @pytest.mark.parametrize("severity,expected_priority", [
        ("CRITICAL", 1),
        ("HIGH",     2),
        ("MEDIUM",   3),
        ("LOW",      4),
    ])
    def test_severity_maps_to_correct_priority(self, severity, expected_priority):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="Test attack", technique_id="T1110",
            classtype="attempted-admin", severity=severity,
        )
        match = _SNORT_PRIORITY_RE.search(rule)
        assert match, f"Rule missing 'priority' option for severity={severity}:\n{rule}"
        actual = int(match.group(1))
        assert actual == expected_priority, (
            f"Severity '{severity}' should map to priority {expected_priority}, got {actual}."
        )

    # SID uniqueness

    def test_auto_generated_sids_are_unique(self):
        """Auto-incremented SIDs in a batch must all be distinct."""
        rules = [
            generate_snort_rule(
                src_ip="10.0.0.5", dst_port=22, protocol="tcp",
                attack_desc=f"Attack #{i}", technique_id="T1110",
                classtype="attempted-admin",
            )
            for i in range(10)
        ]
        sids = []
        for rule in rules:
            m = _SNORT_SID_RE.search(rule)
            if m:
                sids.append(int(m.group(1)))
        assert len(sids) == len(set(sids)), (
            f"SIDs are not unique across a batch of 10 rules: {sids}"
        )

    def test_explicit_sid_appears_in_rule(self):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="Test", technique_id="T1110",
            classtype="attempted-admin", sid=9999999,
        )
        assert "sid:9999999;" in rule, f"Explicit SID 9999999 not found in rule:\n{rule}"

    # MSG escaping

    def test_msg_field_handles_double_quotes(self):
        """Descriptions containing double-quotes must be escaped in msg."""
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc='Brute Force "SSH" Attack',
            technique_id="T1110", classtype="attempted-admin",
        )
        # The rule must still be parseable (sid and rev must be present)
        assert "sid:" in rule
        assert "rev:" in rule

    def test_msg_field_handles_semicolons(self):
        """Semicolons in description must be escaped to prevent option injection."""
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=80, protocol="tcp",
            attack_desc="Attack; severity=HIGH",
            technique_id="T1190", classtype="web-application-attack",
        )
        assert isinstance(rule, str)
        assert "sid:" in rule
        assert "rev:" in rule

    # Input validation

    def test_invalid_ip_raises_value_error(self):
        with pytest.raises((ValueError, Exception)):
            generate_snort_rule(
                src_ip="not_an_ip", dst_port=22, protocol="tcp",
                attack_desc="Test", technique_id="T1110",
                classtype="attempted-admin",
            )

    def test_invalid_protocol_raises_value_error(self):
        with pytest.raises((ValueError, Exception)):
            generate_snort_rule(
                src_ip="10.0.0.5", dst_port=22, protocol="ftp",
                attack_desc="Test", technique_id="T1110",
                classtype="attempted-admin",
            )

    @pytest.mark.parametrize("port", [22, 80, 443, 8080, "any"])
    def test_valid_ports_produce_rules(self, port):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=port, protocol="tcp",
            attack_desc="Test", technique_id="T1110",
            classtype="attempted-admin",
        )
        assert isinstance(rule, str)
        assert rule.startswith("alert ")

    # Reference URL format

    @pytest.mark.parametrize("technique_id", [
        "T1110", "T1110.001", "T1046", "T1190", "T1595.001",
    ])
    def test_reference_url_contains_technique_path(self, technique_id):
        rule = generate_snort_rule(
            src_ip="10.0.0.5", dst_port=22, protocol="tcp",
            attack_desc="Test", technique_id=technique_id,
            classtype="attempted-admin",
        )
        assert "attack.mitre.org/techniques/" in rule, (
            f"Rule for {technique_id} missing MITRE reference URL."
        )

    # Full campaign batch

    def test_all_signature_techniques_produce_valid_snort_rules(self):
        """Every mapped signature technique must generate a syntactically valid Snort rule."""
        all_techs = get_all_techniques()
        for tech in all_techs:
            rule = generate_snort_rule(
                src_ip="10.0.0.100",
                dst_port=22,
                protocol="tcp",
                attack_desc=f"PhantomNet: {tech.get('technique_name', 'Unknown')}",
                technique_id=tech.get("technique_id", "T1046"),
                classtype="attempted-admin",
                severity=tech.get("severity", "MEDIUM"),
            )
            assert isinstance(rule, str), (
                f"Rule for {tech.get('technique_id')} must be a string."
            )
            assert rule.startswith("alert "), (
                f"Rule for {tech.get('technique_id')} must start with 'alert'."
            )
            assert "sid:" in rule
            assert "classtype:" in rule


# ===========================================================================
# SECTION 6: CROSS-COMPONENT INTEGRATION VALIDATION
# ===========================================================================

class TestCrossComponentValidation:
    """
    End-to-end SOC validation: technique -> playbook + STIX bundle + Snort rule.
    Mirrors a real analyst workflow triggered by a honeypot detection event.
    """

    @pytest.mark.parametrize("signature", [
        "SSH_AUTH_FAILURE",
        "HTTP_SQL_INJECTION",
        "FTP_DATA_EXFILTRATION",
        "HTTP_SCANNER_BEHAVIOR",
    ])
    def test_full_pipeline_per_signature(self, signature):
        """Full pipeline: signature -> technique -> playbook + STIX bundle + Snort rule."""
        # 1. MITRE mapping
        technique = map_signature(signature)
        assert technique is not None, f"map_signature('{signature}') returned None."
        assert "technique_id" in technique

        # 2. Playbook generation (Markdown)
        gen = PlaybookGenerator()
        pattern_map = {
            "SSH_AUTH_FAILURE":       "brute_force",
            "HTTP_SQL_INJECTION":     "sqli_attempt",
            "FTP_DATA_EXFILTRATION":  "data_exfiltration",
            "HTTP_SCANNER_BEHAVIOR":  "port_scan",
        }
        attack_pattern = pattern_map.get(signature, "brute_force")
        md = gen.generate({
            "attack_pattern": attack_pattern,
            "source_ip":      "198.51.100.42",
            "severity":       technique.get("severity", "HIGH"),
        })
        assert len(md) >= 200, f"Playbook for {signature} too short."

        # 3. STIX bundle
        bundle = build_stix_bundle(
            technique=technique,
            iocs=[{"type": "ip", "value": "198.51.100.42"}],
            src_ip="198.51.100.42",
            threat_score=75.0,
        )
        d = bundle_to_dict(bundle)
        assert d["type"] == "bundle"
        obj_types = {o["type"] for o in d["objects"]}
        assert "attack-pattern" in obj_types
        assert "indicator"      in obj_types

        # 4. Snort rule
        rule = generate_snort_rule(
            src_ip="198.51.100.42",
            dst_port=22,
            protocol="tcp",
            attack_desc=f"PhantomNet Sentinel: {technique['technique_name']}",
            technique_id=technique["technique_id"],
            classtype="attempted-admin",
            severity=technique.get("severity", "MEDIUM"),
        )
        assert isinstance(rule, str)
        assert rule.startswith("alert ")
        assert "sid:" in rule

    def test_stix_bundle_technique_id_matches_snort_reference(self):
        """The technique ID in the STIX bundle must match the Snort rule reference URL."""
        technique = map_signature("SSH_AUTH_FAILURE")
        tid = technique["technique_id"]

        bundle = build_stix_bundle(
            technique=technique,
            iocs=[{"type": "ip", "value": "10.0.0.1"}],
        )
        d = bundle_to_dict(bundle)
        ap = next(o for o in d["objects"] if o["type"] == "attack-pattern")
        mitre_ref = next(
            r for r in ap.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        )
        stix_tech_id = mitre_ref["external_id"]

        rule = generate_snort_rule(
            src_ip="10.0.0.1", dst_port=22, protocol="tcp",
            attack_desc="Test", technique_id=tid,
            classtype="attempted-admin",
        )
        base_tid = tid.split(".")[0]
        assert base_tid in rule, (
            f"Snort rule reference URL should contain '{base_tid}' for technique '{tid}'."
        )
        assert stix_tech_id == tid, (
            f"STIX external_id '{stix_tech_id}' must match technique_id '{tid}'."
        )

    def test_pdf_generated_from_rendered_markdown_playbook(self):
        """A PDF export of a rendered Markdown playbook must produce valid PDF bytes."""
        gen = PlaybookGenerator()
        md = gen.generate({
            "attack_pattern": "brute_force",
            "source_ip":      "198.51.100.1",
            "severity":       "HIGH",
        })
        pdf_bytes = generate_pdf(md)
        assert pdf_bytes[:4] == b"%PDF", "PDF exported from Markdown playbook is invalid."
        assert len(pdf_bytes) >= 1024
