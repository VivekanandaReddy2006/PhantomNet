import React, { useState } from "react";
import { FaShieldAlt, FaTerminal } from "react-icons/fa";
import PlaybookCard from "../components/sentinel/PlaybookCard";
import MitreTag from "../components/sentinel/MitreTag";
import RulePreview from "../components/sentinel/RulePreview";
import PlaybookViewer from "../components/sentinel/PlaybookViewer";
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

/* Rich details for PlaybookViewer modal */
const playbookDetails = {
  "T1003.001": {
    markdownContent: `# OS Credential Dumping: LSASS Memory

## Incident Response Workflow
1. **Host Isolation**: Immediately isolate the compromised endpoint from the network.
2. **Memory Analysis**: Capture and analyze physical memory (if possible) to extract process lineage.
3. **Password Reset**: Enforce credential revocation and password reset for all compromised/associated accounts.
4. **Credential Rotation**: Force rotation of Active Directory krbtgt account keys.

## Mitigation Guidance
- Enable Windows LSA Protection (\`RunAsPPL\`).
- Implement Credential Guard on supported Windows editions.
- Restrict Debug Privileges (\`SeDebugPrivilege\`) via Group Policy.`,
    snortRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT Possible LSASS Dump over SMB"; flow:to_server,established; content:"|ff|SMB"; depth:4; content:"lsass"; nocase; sid:2024003; rev:1;)`,
    sigmaRule: `title: LSASS Memory Dumping via Procdump
id: ffa81d86-063a-4a87-bf71-3246a1e8e1d5
status: stable
description: Detects procdump writing to lsass memory
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'procdump'
      - 'lsass'
  condition: selection
level: critical`
  },
  "T1021.002": {
    markdownContent: `# Lateral Movement: SMB/Windows Admin Shares

## Incident Response Workflow
1. **Network Containment**: Block outbound SMB traffic (Port 445/139) from the source host.
2. **Access Control Audit**: Verify which credentials were used to authenticate via SMB.
3. **Session Revocation**: Revoke all active SMB and user sessions on the target machine.
4. **Log Review**: Review Event ID 4624 (Successful Logon) and 4625 (Failed Logon) with Logon Type 3.

## Mitigation Guidance
- Restrict Local Admin account reuse across machines (use LAPS).
- Block lateral SMB connection between endpoints using Host Firewalls.
- Require SMB signing/encryption.`,
    snortRule: `alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"INTERNAL Lateral Movement via SMB Share"; flow:to_server,established; content:"|5c 00 41 00 44 00 4d 00 49 00 4e 00 24|"; msg:"Access to ADMIN$ share"; sid:2024004; rev:1;)`,
    sigmaRule: `title: SMB Lateral Movement Logon
id: cba72186-063a-4a87-bf71-3246a1e8e1d5
status: stable
description: Detects remote lateral movement logons via SMB
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4624
    LogonType: 3
    IpAddress|not: '127.0.0.1'
  condition: selection
level: high`
  },
  "T1059.001": {
    markdownContent: `# Execution: PowerShell Download Cradle

## Incident Response Workflow
1. **Process Mitigation**: Kill the parent process and PowerShell execution stream.
2. **Command Reconstruction**: Reconstruct the script executed from command-line arguments or transcript logs.
3. **Network Check**: Verify any outbound connections established by \`powershell.exe\`.
4. **Host Scan**: Scan local directories for downloaded payloads.

## Mitigation Guidance
- Enforce PowerShell Constrained Language Mode.
- Implement AppLocker or WDAC to restrict PowerShell script execution.
- Enable PowerShell Transcript Logging and Script Block Logging.`,
    snortRule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"EXTERNAL PowerShell User-Agent Detected"; flow:to_server,established; content:"WindowsPowerShell"; http_header; sid:2024005; rev:1;)`,
    sigmaRule: `title: Suspicious PowerShell Download Cradle
id: 3b6ab547-1c3b-4a85-bf71-3246a1e8e1d5
status: experimental
description: Detects suspicious PowerShell download cradle patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - 'downloadstring'
  condition: selection
level: high`
  },
  "T1071.004": {
    markdownContent: `# Command and Control: DNS Tunneling Detection

## Incident Response Workflow
1. **Traffic Analysis**: Inspect TXT, CNAME, and Null DNS query responses for encoded payloads.
2. **Host Quarantine**: Isolate the endpoint requesting abnormal subdomains.
3. **DNS Sinkholing**: Route the malicious C2 domain to a local sinkhole.
4. **Log Retention**: Pull DNS server query logs for historical lookup analysis.

## Mitigation Guidance
- Implement DNS filtering and query rate-limiting.
- Inspect outbound DNS requests for high entropy and subdomain length.
- Block direct external DNS queries from endpoints; force routing through corporate resolvers.`,
    snortRule: `alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"EXTERNAL High Rate DNS Queries (Tunneling)"; content:"|00 00 10 00 01|"; threshold:type threshold, track by_src, count 100, seconds 5; sid:2024006; rev:1;)`,
    sigmaRule: `title: DNS Tunneling Pattern Detection
id: 116ab547-1c3b-4a85-bf71-3246a1e8e1d5
status: experimental
description: Detects unusual DNS TXT query rates indicative of tunneling
logsource:
  category: dns
detection:
  selection:
    QueryType: TXT
    QueryLength|gt: 100
  condition: selection
level: high`
  }
};

const defaultDetails = {
  markdownContent: `# Threat Playbook

## Summary
General mitigation and response strategy for the specified threat.

## Remediation Checklist
- [ ] Review system access logs for the affected time window.
- [ ] Verify endpoint firewall configurations.
- [ ] Conduct a full credential sweep on the host.
- [ ] Re-run vulnerability scan on the endpoint.`,
  snortRule: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SUSPICIOUS General Network Activity"; flow:to_server,established; sid:2024999; rev:1;)`,
  sigmaRule: `title: General Suspicious Activity Detection
id: efa82186-063a-4a87-bf71-3246a1e8e1d5
status: experimental
description: Detects generic suspicious behavior indicators
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'suspicious_command'
  condition: selection
level: medium`
};

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
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [isViewerOpen, setIsViewerOpen] = useState(false);

  const handleCardClick = (pb) => {
    const details = playbookDetails[pb.technique] || defaultDetails;
    setSelectedPlaybook({
      ...pb,
      markdownContent: details.markdownContent,
      snortRule: details.snortRule,
      sigmaRule: details.sigmaRule,
    });
    setIsViewerOpen(true);
  };

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
            <PlaybookCard
              key={idx}
              {...pb}
              onClick={() => handleCardClick(pb)}
            />
          ))}
        </div>
      </div>

      {/* Playbook Viewer Modal */}
      {selectedPlaybook && (
        <PlaybookViewer
          isOpen={isViewerOpen}
          onClose={() => setIsViewerOpen(false)}
          {...selectedPlaybook}
        />
      )}
    </div>
  );
};

export default SentinelDashboard;

