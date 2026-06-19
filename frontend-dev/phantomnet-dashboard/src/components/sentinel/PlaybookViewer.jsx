import React, { useState, useCallback, useEffect, useRef } from "react";
import {
  FaBook,
  FaTimes,
  FaShieldAlt,
  FaFileCode,
  FaMarkdown,
  FaCrosshairs,
  FaCalendarAlt,
} from "react-icons/fa";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import RulePreview from "./RulePreview";
import "../../Styles/components/PlaybookViewer.css";

/* ═══════════════════════════════════════════════════════════════
   Tab Configuration
   ═══════════════════════════════════════════════════════════════ */

const TABS = [
  { key: "playbook", label: "Playbook",    icon: FaBook },
  { key: "snort",    label: "Snort Rules",  icon: FaShieldAlt },
  { key: "sigma",    label: "Sigma Rules",  icon: FaFileCode },
];

/* ═══════════════════════════════════════════════════════════════
   Severity Helpers
   ═══════════════════════════════════════════════════════════════ */

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high:     "#f59e0b",
  medium:   "#3b82f6",
  low:      "#22c55e",
};

/* ═══════════════════════════════════════════════════════════════
   MarkdownRenderer — Render markdown using react-markdown
   ═══════════════════════════════════════════════════════════════ */

const MarkdownRenderer = ({ content }) => {
  if (!content) {
    return (
      <div className="pbv-markdown-placeholder">
        <FaMarkdown className="pbv-placeholder-icon" />
        <h3 className="pbv-placeholder-title">
          No Playbook Content
        </h3>
        <p className="pbv-placeholder-text">
          Select a playbook or verify that the markdown content is defined.
        </p>
      </div>
    );
  }

  return (
    <div className="pbv-markdown-content">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {content}
      </ReactMarkdown>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════
   PlaybookViewer Component
   ─────────────────────────────────────────────────────────────
   Modal / panel that renders a full security playbook with
   three tabbed views: Playbook content, Snort rules, Sigma rules.

   Props:
   ────────────────────────────────────────────────────────────
   @param {boolean}  isOpen         – Whether the modal is visible
   @param {function} onClose        – Callback to close the modal
   @param {string}   title          – Playbook title
   @param {string}   severity       – "critical" | "high" | "medium" | "low"
   @param {string}   technique      – MITRE ATT&CK technique ID
   @param {string}   date           – Human-readable date string
   @param {string}   markdownContent– Raw Markdown string for the playbook body
   @param {string}   snortRule      – Raw Snort rule text
   @param {string}   sigmaRule      – Raw Sigma YAML text
   ═══════════════════════════════════════════════════════════════ */

const PlaybookViewer = ({
  isOpen = false,
  onClose,
  title = "Untitled Playbook",
  severity = "medium",
  technique = "T0000",
  date = "—",
  markdownContent = "",
  snortRule = "",
  sigmaRule = "",
}) => {
  const [activeTab, setActiveTab] = useState("playbook");
  const panelRef = useRef(null);

  /* ── Close on Escape ── */
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => {
      if (e.key === "Escape") onClose?.();
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  /* ── Lock body scroll when open ── */
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [isOpen]);

  /* ── Close on overlay click ── */
  const handleOverlayClick = useCallback(
    (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        onClose?.();
      }
    },
    [onClose]
  );

  /* ── Reset tab when opened with new data ── */
  useEffect(() => {
    if (isOpen) setActiveTab("playbook");
  }, [isOpen, title]);

  if (!isOpen) return null;

  const severityColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  /* ── Determine which tabs are available ── */
  const availableTabs = TABS.filter((tab) => {
    if (tab.key === "snort" && !snortRule) return false;
    if (tab.key === "sigma" && !sigmaRule) return false;
    return true;
  });

  /* ── Determine markdown readiness status ── */
  const hasMarkdown = Boolean(markdownContent);

  return (
    <div
      className="playbook-viewer-overlay"
      onClick={handleOverlayClick}
      role="dialog"
      aria-modal="true"
      aria-label={`Playbook Viewer: ${title}`}
      id="playbook-viewer-overlay"
    >
      <div className="playbook-viewer-panel" ref={panelRef}>
        {/* HUD Corners */}
        <div className="hud-corner top-left"></div>
        <div className="hud-corner top-right"></div>
        <div className="hud-corner bottom-left"></div>
        <div className="hud-corner bottom-right"></div>
        <div className="playbook-viewer-scan-line"></div>
        <div className="playbook-viewer-glow"></div>

        {/* ═══ Header ═══ */}
        <header className="pbv-header">
          <div className="pbv-header-left">
            <div className="pbv-header-icon">
              <FaBook />
            </div>
            <div className="pbv-header-info">
              <h2 className="pbv-title" title={title}>
                {title}
              </h2>
              <div className="pbv-subtitle">
                <span
                  className="severity-dot-inline"
                  style={{
                    background: severityColor,
                    boxShadow: `0 0 6px ${severityColor}`,
                  }}
                ></span>
                <span>{severityLabel}</span>
                <span style={{ opacity: 0.35 }}>│</span>
                <FaCrosshairs style={{ fontSize: "0.55rem", opacity: 0.6 }} />
                <span>{technique}</span>
                <span style={{ opacity: 0.35 }}>│</span>
                <FaCalendarAlt style={{ fontSize: "0.55rem", opacity: 0.6 }} />
                <span>{date}</span>
              </div>
            </div>
          </div>

          <button
            className="pbv-close-btn"
            onClick={onClose}
            title="Close viewer (Esc)"
            aria-label="Close playbook viewer"
            id="playbook-viewer-close-btn"
          >
            <FaTimes />
          </button>
        </header>

        {/* ═══ Tab Bar ═══ */}
        <nav className="pbv-tab-bar" role="tablist" aria-label="Playbook sections">
          {availableTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                className={`pbv-tab ${activeTab === tab.key ? "active" : ""}`}
                onClick={() => setActiveTab(tab.key)}
                role="tab"
                aria-selected={activeTab === tab.key}
                aria-controls={`pbv-panel-${tab.key}`}
                id={`pbv-tab-${tab.key}`}
              >
                <span className="tab-indicator"></span>
                <Icon className="pbv-tab-icon" />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* ═══ Content Area ═══ */}
        <div className="pbv-content-area">
          {/* ── Playbook Tab ── */}
          {activeTab === "playbook" && (
            <div
              role="tabpanel"
              id="pbv-panel-playbook"
              aria-labelledby="pbv-tab-playbook"
            >
              <MarkdownRenderer content={markdownContent} />
            </div>
          )}

          {/* ── Snort Rules Tab ── */}
          {activeTab === "snort" && (
            <div
              className="pbv-rule-section"
              role="tabpanel"
              id="pbv-panel-snort"
              aria-labelledby="pbv-tab-snort"
            >
              <RulePreview snortRule={snortRule} sigmaRule="" />
            </div>
          )}

          {/* ── Sigma Rules Tab ── */}
          {activeTab === "sigma" && (
            <div
              className="pbv-rule-section"
              role="tabpanel"
              id="pbv-panel-sigma"
              aria-labelledby="pbv-tab-sigma"
            >
              <RulePreview snortRule="" sigmaRule={sigmaRule} />
            </div>
          )}
        </div>

        {/* ═══ Footer ═══ */}
        <footer className="pbv-footer">
          <div className="pbv-footer-left">
            <span className="pbv-footer-label">PhantomNet Sentinel</span>
            <span className="pbv-footer-label" style={{ opacity: 0.4 }}>
              │
            </span>
            <span className="pbv-footer-label">
              {activeTab === "playbook"
                ? "Playbook Content"
                : activeTab === "snort"
                ? "Snort IDS Rule"
                : "Sigma Detection Rule"}
            </span>
          </div>
          <div className="pbv-footer-right">
            <span
              className={`pbv-footer-status ${
                hasMarkdown ? "status-ready" : "status-pending"
              }`}
            >
              <span className="footer-status-dot"></span>
              {hasMarkdown ? "Loaded" : "Awaiting Data"}
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default PlaybookViewer;
