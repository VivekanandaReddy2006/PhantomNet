import React from "react";
import { FaCrosshairs } from "react-icons/fa";
import "../../Styles/components/MitreTag.css";

/**
 * MITRE ATT&CK tactic → CSS class + display label mapping.
 * Each tactic gets a unique color defined in MitreTag.css.
 */
const TACTIC_MAP = {
  "credential-access":      { label: "Credential Access",      css: "tactic-credential-access" },
  "initial-access":         { label: "Initial Access",          css: "tactic-initial-access" },
  "execution":              { label: "Execution",               css: "tactic-execution" },
  "persistence":            { label: "Persistence",             css: "tactic-persistence" },
  "discovery":              { label: "Discovery",               css: "tactic-discovery" },
  "lateral-movement":       { label: "Lateral Movement",        css: "tactic-lateral-movement" },
  "command-and-control":    { label: "Command and Control",     css: "tactic-command-and-control" },
  "exfiltration":           { label: "Exfiltration",            css: "tactic-exfiltration" },
  "defense-evasion":        { label: "Defense Evasion",         css: "tactic-defense-evasion" },
  "privilege-escalation":   { label: "Privilege Escalation",    css: "tactic-privilege-escalation" },
  "impact":                 { label: "Impact",                  css: "tactic-impact" },
  "collection":             { label: "Collection",              css: "tactic-collection" },
  "resource-development":   { label: "Resource Development",    css: "tactic-resource-development" },
  "reconnaissance":         { label: "Reconnaissance",          css: "tactic-reconnaissance" },
};

/**
 * Builds the official MITRE ATT&CK URL for a technique ID.
 * Handles sub-techniques (e.g. T1059.001 → /techniques/T1059/001).
 */
const buildMitreUrl = (techniqueId) => {
  const base = "https://attack.mitre.org/techniques/";
  const parts = techniqueId.split(".");
  if (parts.length === 2) {
    return `${base}${parts[0]}/${parts[1]}/`;
  }
  return `${base}${techniqueId}/`;
};

/**
 * MitreTag — A clickable badge displaying a MITRE ATT&CK technique ID,
 * color-coded by tactic category, with a tooltip showing the full technique name.
 *
 * @param {string}  techniqueId   – Technique ID, e.g. "T1110.001"
 * @param {string}  techniqueName – Full name, e.g. "Password Spraying"
 * @param {string}  tactic        – Tactic slug, e.g. "credential-access"
 */
const MitreTag = ({
  techniqueId = "T0000",
  techniqueName = "Unknown Technique",
  tactic = "discovery",
}) => {
  const tacticInfo = TACTIC_MAP[tactic] || {
    label: "Unknown",
    css: "tactic-discovery",
  };

  return (
    <div className="mitre-tag-wrapper">
      {/* Tooltip */}
      <div className="mitre-tooltip">
        <div className="mitre-tooltip-name">{techniqueName}</div>
        <div className="mitre-tooltip-tactic">{tacticInfo.label}</div>
      </div>

      {/* Badge */}
      <a
        className={`mitre-tag ${tacticInfo.css}`}
        href={buildMitreUrl(techniqueId)}
        target="_blank"
        rel="noopener noreferrer"
        title={`${techniqueId} – ${techniqueName}`}
      >
        <span className="tactic-dot"></span>
        <FaCrosshairs className="mitre-tag-icon" />
        <span>{techniqueId}</span>
      </a>
    </div>
  );
};

export default MitreTag;
