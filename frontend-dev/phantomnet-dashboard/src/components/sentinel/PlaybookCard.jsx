import React from "react";
import {
  FaShieldAlt,
  FaCalendarAlt,
  FaLayerGroup,
  FaCrosshairs,
} from "react-icons/fa";
import "../../Styles/components/PlaybookCard.css";

/**
 * PlaybookCard – Displays a generated security playbook with
 * severity badge, MITRE ATT&CK technique, approval status, and metadata.
 *
 * @param {string}  title        – Playbook name/title
 * @param {string}  severity     – "critical" | "high" | "medium" | "low"
 * @param {string}  technique    – MITRE ATT&CK technique ID (e.g. "T1059.001")
 * @param {string}  status       – "approved" | "draft" | "rejected"
 * @param {string}  date         – Human-readable generation date
 * @param {number}  eventCount   – Number of events that triggered this playbook
 */
const PlaybookCard = ({
  title = "Untitled Playbook",
  severity = "medium",
  technique = "T0000",
  status = "draft",
  date = "—",
  eventCount = 0,
  onClick,
}) => {
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
  const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);

  return (
    <div className="playbook-card hud-font" onClick={onClick}>
      {/* HUD Corners */}
      <div className="hud-corner top-left"></div>
      <div className="hud-corner bottom-right"></div>
      <div className="playbook-scan-line"></div>

      {/* ── Header: Title + Severity ── */}
      <div className="playbook-card-header">
        <div className="playbook-title-group">
          <h4 className="playbook-title" title={title}>
            {title}
          </h4>
          <div className="playbook-technique">
            <FaCrosshairs className="technique-icon" />
            <span>{technique}</span>
          </div>
        </div>

        <div className={`severity-badge severity-${severity}`}>
          <span className="severity-dot"></span>
          {severityLabel}
        </div>
      </div>

      {/* ── Divider ── */}
      <div className="playbook-divider"></div>

      {/* ── Body: Status + Meta ── */}
      <div className="playbook-card-body">
        <div className="playbook-status-row">
          <span className="playbook-status-label">Status</span>
          <div className={`playbook-status-badge status-${status}`}>
            <span className="status-dot"></span>
            {statusLabel}
          </div>
        </div>

        <div className="playbook-meta-row">
          <div className="playbook-meta-item">
            <FaCalendarAlt className="meta-icon" />
            <span className="meta-value">{date}</span>
          </div>
          <div className="playbook-meta-item">
            <FaLayerGroup className="meta-icon" />
            <span className="meta-value">
              {typeof eventCount === "number"
                ? eventCount.toLocaleString()
                : eventCount}{" "}
              events
            </span>
          </div>
        </div>
      </div>

      {/* Hover Glow */}
      <div className="playbook-card-glow"></div>
    </div>
  );
};

export default PlaybookCard;
