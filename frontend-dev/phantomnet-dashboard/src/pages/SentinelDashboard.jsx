import React from "react";
import { FaShieldAlt, FaTerminal } from "react-icons/fa";
import PlaybookCard from "../components/sentinel/PlaybookCard";
import MitreTag from "../components/sentinel/MitreTag";
import RulePreview from "../components/sentinel/RulePreview";
import "../Styles/pages/SentinelDashboard.css";

/* Sample playbooks to preview PlaybookCard variants */
const samplePlaybooks = [
  {
    title: "Credential Dumping Response",
    severity: "critical",
    technique: "T1003.001",
    status: "approved",
    date: "2026-06-18",
    eventCount: 142,
  },
  {
    title: "Lateral Movement via SMB",
    severity: "high",
    technique: "T1021.002",
    status: "approved",
    date: "2026-06-17",
    eventCount: 87,
  },
  {
    title: "Suspicious PowerShell Execution",
    severity: "high",
    technique: "T1059.001",
    status: "draft",
    date: "2026-06-17",
    eventCount: 53,
  },
  {
    title: "DNS Tunneling Detection",
    severity: "medium",
    technique: "T1071.004",
    status: "approved",
    date: "2026-06-16",
    eventCount: 214,
  },
  {
    title: "Unusual Outbound Traffic",
    severity: "medium",
    technique: "T1048.003",
    status: "draft",
    date: "2026-06-16",
    eventCount: 31,
  },
  {
    title: "Benign Scheduled Task",
    severity: "low",
    technique: "T1053.005",
    status: "rejected",
    date: "2026-06-15",
    eventCount: 12,
  },
];

/* Sample MITRE techniques to showcase MitreTag variants */
const sampleTechniques = [
  { techniqueId: "T1110.001", techniqueName: "Password Guessing",         tactic: "credential-access" },
  { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment",  tactic: "initial-access" },
  { techniqueId: "T1059.001", techniqueName: "PowerShell",                tactic: "execution" },
  { techniqueId: "T1053.005", techniqueName: "Scheduled Task",            tactic: "persistence" },
  { techniqueId: "T1083",     techniqueName: "File and Directory Discovery", tactic: "discovery" },
  { techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares",  tactic: "lateral-movement" },
  { techniqueId: "T1071.004", techniqueName: "DNS",                       tactic: "command-and-control" },
  { techniqueId: "T1048.003", techniqueName: "Exfiltration Over C2",      tactic: "exfiltration" },
  { techniqueId: "T1070.004", techniqueName: "File Deletion",             tactic: "defense-evasion" },
  { techniqueId: "T1068",     techniqueName: "Exploitation for Privilege Escalation", tactic: "privilege-escalation" },
  { techniqueId: "T1486",     techniqueName: "Data Encrypted for Impact", tactic: "impact" },
  { techniqueId: "T1119",     techniqueName: "Automated Collection",      tactic: "collection" },
];

/* Sample detection rules */
const sampleSnortRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT Possible SMB Brute Force"; flow:to_server,established; content:"|ff|SMB"; depth:4; content:"|73 00 00 00|"; distance:0; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2024001; rev:3;)

# Secondary detection for lateral movement
alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"INTERNAL Lateral Movement via DCOM"; flow:to_server,established; content:"|05|"; depth:1; content:"|0b|"; distance:1; within:1; classtype:attempted-admin; sid:2024002; rev:1;)`;

const sampleSigmaRule = `title: Suspicious PowerShell Download Cradle
id: 3b6ab547-1c3b-4a85-bf71-3246a1e8e1d5
status: experimental
description: Detects suspicious PowerShell download cradle patterns
author: PhantomNet Sentinel
date: 2026/06/18
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - 'downloadstring'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001`;

const SentinelDashboard = () => {
  return (
    <div className="sentinel-wrapper">
      {/* Header */}
      <div className="sentinel-header">
        <div className="sentinel-badge hud-font">SENTINEL_ENGINE_V1.0</div>
        <h1 className="sentinel-title">Sentinel Dashboard</h1>
        <p className="sentinel-subtitle">
          AUTONOMOUS THREAT DETECTION &amp; RESPONSE COMMAND CENTER
        </p>
      </div>

      {/* Live Status Bar */}
      <div className="sentinel-status-bar">
        <div className="status-item">
          <span className="status-dot-live"></span>
          <span className="status-label">ENGINE STATUS:</span>
          <span>ONLINE</span>
        </div>
        <div className="status-item">
          <span className="status-label">UPTIME:</span>
          <span>—</span>
        </div>
        <div className="status-item">
          <span className="status-label">RULES LOADED:</span>
          <span>{samplePlaybooks.length}</span>
        </div>
        <div className="status-item">
          <span className="status-label">LAST SCAN:</span>
          <span>—</span>
        </div>
      </div>

      {/* MITRE ATT&CK Techniques */}
      <div className="sentinel-content" style={{ marginBottom: "2rem" }}>
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">ATT&amp;CK Coverage</h2>
          <span className="sentinel-section-count hud-font">
            {sampleTechniques.length} TECHNIQUES
          </span>
        </div>
        <div className="sentinel-mitre-grid">
          {sampleTechniques.map((t, idx) => (
            <MitreTag key={idx} {...t} />
          ))}
        </div>
      </div>

      {/* Rule Preview */}
      <div className="sentinel-content" style={{ marginBottom: "2rem" }}>
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">Detection Rules</h2>
          <span className="sentinel-section-count hud-font">SNORT / SIGMA</span>
        </div>
        <RulePreview snortRule={sampleSnortRule} sigmaRule={sampleSigmaRule} />
      </div>

      {/* Playbook Cards Grid */}
      <div className="sentinel-content">
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">Generated Playbooks</h2>
          <span className="sentinel-section-count hud-font">
            {samplePlaybooks.length} PLAYBOOKS
          </span>
        </div>
        <div className="sentinel-playbook-grid">
          {samplePlaybooks.map((pb, idx) => (
            <PlaybookCard key={idx} {...pb} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default SentinelDashboard;

