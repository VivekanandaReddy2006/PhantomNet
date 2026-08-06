"""
scripts/verify_mitre_v14.py
----------------------------
PhantomNet Sentinel — MITRE ATT&CK v14 Mapping Verification Script

Week 20 Day 3 — Security Developer Deliverable

Verifies all 12 Sentinel attack scenarios against MITRE ATT&CK v14:
  1. All required schema keys present in every technique entry
  2. Technique IDs follow correct format (T-number)
  3. Tactic IDs are valid ATT&CK enterprise tactic IDs
  4. Severity values are one of CRITICAL / HIGH / MEDIUM / LOW
  5. URLs reference attack.mitre.org
  6. STIX ExternalReference objects contain correct external_id + source_name
  7. JSON mapping file exists and has 12 entries, all v14_verified=True

Usage:
    python scripts/verify_mitre_v14.py
"""

from __future__ import annotations

import json
import os
import sys

# ── path bootstrap ────────────────────────────────────────────────────────────
_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── imports ───────────────────────────────────────────────────────────────────
from sentinel.mitre_mapper import (
    get_all_mappings,
    map_signature,
    ATTACK_VERSION,
    ATTACK_SPEC_VERSION,
)
import stix2

# ── constants ─────────────────────────────────────────────────────────────────
REQUIRED_FULL_KEYS = {
    "technique_id", "technique_name", "tactic",
    "tactic_id", "description", "url", "severity",
}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_TACTIC_IDS = {
    "TA0001", "TA0002", "TA0006", "TA0007",
    "TA0008", "TA0010", "TA0011", "TA0040", "TA0043",
}
JSON_MAPPING_PATH = os.path.join(_BACKEND, "data", "mitre_attack_v14_mappings.json")
EXPECTED_SCENARIO_COUNT = 12

errors:  list[str] = []
passed:  int = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        msg = f"  [FAIL] {label}"
        if detail:
            msg += f"  → {detail}"
        print(msg)
        errors.append(f"{label}: {detail}" if detail else label)


# =============================================================================
# Section 1 — Schema validation for all 12 entries
# =============================================================================
print("=" * 70)
print(f"ATT&CK Framework Version : {ATTACK_VERSION}")
print(f"STIX Spec Version        : {ATTACK_SPEC_VERSION}")
print("=" * 70)
print()
print("SECTION 1 — Full schema validation (all 12 scenarios)")
print("-" * 70)

mappings = get_all_mappings()
check("Mapping table has exactly 12 entries", len(mappings) == EXPECTED_SCENARIO_COUNT,
      f"got {len(mappings)}")

for sig, tech in mappings.items():
    missing = REQUIRED_FULL_KEYS - set(tech.keys())
    check(f"{sig}: has all required schema keys", not missing,
          f"missing {missing}" if missing else "")

    tid = tech.get("technique_id", "")
    check(f"{sig}: technique_id format valid ({tid})",
          tid.startswith("T") and len(tid) >= 5)

    tac_id = tech.get("tactic_id", "")
    check(f"{sig}: tactic_id is a known ATT&CK enterprise tactic ({tac_id})",
          tac_id in VALID_TACTIC_IDS)

    sev = tech.get("severity", "")
    check(f"{sig}: severity value valid ({sev})", sev in VALID_SEVERITIES)

    url = tech.get("url", "")
    check(f"{sig}: URL references attack.mitre.org",
          "attack.mitre.org" in url and tid.split(".")[0].lower() in url.lower(),
          url)


# =============================================================================
# Section 2 — STIX ExternalReference validation for all 12 techniques
# =============================================================================
print()
print("SECTION 2 — STIX 2.1 ExternalReference validation")
print("-" * 70)

for sig in mappings:
    tech = map_signature(sig)
    try:
        ap = stix2.AttackPattern(
            name=tech["technique_name"],
            description=tech.get("description", ""),
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=tech["technique_id"],
                    url=tech["url"],
                )
            ],
            kill_chain_phases=[
                stix2.KillChainPhase(
                    kill_chain_name="mitre-attack",
                    phase_name=tech["tactic"].lower().replace(" ", "-"),
                )
            ],
        )
        ext_ref = ap.external_references[0]
        check(f"{sig}: STIX AttackPattern constructs without error", True)
        check(f"{sig}: external_id == technique_id",
              ext_ref.external_id == tech["technique_id"],
              f"got {ext_ref.external_id}")
        check(f"{sig}: source_name == 'mitre-attack'",
              ext_ref.source_name == "mitre-attack")
    except Exception as exc:
        check(f"{sig}: STIX AttackPattern construction", False, str(exc))


# =============================================================================
# Section 3 — JSON mapping file verification
# =============================================================================
print()
print("SECTION 3 — JSON mapping file (backend/data/mitre_attack_v14_mappings.json)")
print("-" * 70)

check("JSON mapping file exists", os.path.isfile(JSON_MAPPING_PATH), JSON_MAPPING_PATH)

if os.path.isfile(JSON_MAPPING_PATH):
    with open(JSON_MAPPING_PATH, encoding="utf-8") as fh:
        jdata = json.load(fh)

    meta = jdata.get("_metadata", {})
    check("JSON _metadata.attack_version == '14.1'",
          meta.get("attack_version") == "14.1",
          str(meta.get("attack_version")))
    check("JSON _metadata.attack_spec_version == '2.1.0'",
          meta.get("attack_spec_version") == "2.1.0",
          str(meta.get("attack_spec_version")))
    check("JSON _metadata.stix_spec_version == '2.1'",
          meta.get("stix_spec_version") == "2.1",
          str(meta.get("stix_spec_version")))

    scenarios = jdata.get("mappings", [])
    check(f"JSON has {EXPECTED_SCENARIO_COUNT} scenario entries",
          len(scenarios) == EXPECTED_SCENARIO_COUNT, str(len(scenarios)))
    check("All scenarios have v14_verified == True",
          all(s.get("v14_verified") is True for s in scenarios))
    check("All scenarios have stix_external_reference",
          all("stix_external_reference" in s for s in scenarios))
    check("All scenarios have kill_chain_phase",
          all("kill_chain_phase" in s for s in scenarios))

    for s in scenarios:
        ext = s.get("stix_external_reference", {})
        tid = s.get("technique_id", "")
        check(f"Scenario {s['scenario_id']:>2} ({s['signature']}): "
              f"external_id matches technique_id",
              ext.get("external_id") == tid,
              f"ext_id={ext.get('external_id')!r} vs tid={tid!r}")
        check(f"Scenario {s['scenario_id']:>2} ({s['signature']}): "
              f"source_name == 'mitre-attack'",
              ext.get("source_name") == "mitre-attack")


# =============================================================================
# Summary
# =============================================================================
print()
print("=" * 70)
total = passed + len(errors)
print(f"RESULT: {passed}/{total} checks PASSED  |  {len(errors)} FAILED")
print("=" * 70)
if errors:
    print("\nFAILED checks:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("All ATT&CK v14 mapping checks PASSED.")
    sys.exit(0)
