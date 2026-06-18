import React, { useState, useCallback } from "react";
import { FaCopy, FaCheck, FaShieldAlt, FaFileCode } from "react-icons/fa";
import "../../Styles/components/RulePreview.css";

/* ═══════════════════════════════════════════════════════════════
   Syntax Highlighters
   ═══════════════════════════════════════════════════════════════ */

/**
 * Highlights a single line of a Snort rule.
 */
const highlightSnortLine = (line) => {
  if (line.trimStart().startsWith("#")) {
    return <span className="snort-comment">{line}</span>;
  }

  const parts = [];
  let remaining = line;
  let key = 0;

  const headerRe =
    /^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*/;
  const headerMatch = remaining.match(headerRe);

  if (headerMatch) {
    parts.push(<span key={key++} className="snort-action">{headerMatch[1]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-protocol">{headerMatch[2]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-address">{headerMatch[3]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-port">{headerMatch[4]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-direction">{headerMatch[5]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-address">{headerMatch[6]}</span>);
    parts.push(<span key={key++}> </span>);
    parts.push(<span key={key++} className="snort-port">{headerMatch[7]}</span>);
    parts.push(<span key={key++}> </span>);
    remaining = remaining.slice(headerMatch[0].length);
  }

  if (remaining.includes("(")) {
    const optStart = remaining.indexOf("(");
    if (optStart > 0) {
      parts.push(<span key={key++}>{remaining.slice(0, optStart)}</span>);
    }
    parts.push(<span key={key++} className="snort-paren">(</span>);

    const inner = remaining.slice(optStart + 1, remaining.lastIndexOf(")"));
    const options = inner.split(";");
    options.forEach((opt, i) => {
      const trimmed = opt.trim();
      if (!trimmed) return;
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx > 0) {
        parts.push(
          <span key={key++} className="snort-option">{trimmed.slice(0, colonIdx)}</span>
        );
        parts.push(<span key={key++} className="snort-separator">:</span>);
        parts.push(
          <span key={key++} className="snort-value">{trimmed.slice(colonIdx + 1)}</span>
        );
      } else {
        parts.push(<span key={key++} className="snort-option">{trimmed}</span>);
      }
      if (i < options.length - 1) {
        parts.push(<span key={key++} className="snort-separator">; </span>);
      }
    });

    parts.push(<span key={key++} className="snort-paren">)</span>);
  } else if (remaining) {
    parts.push(<span key={key++}>{remaining}</span>);
  }

  return <>{parts}</>;
};

/**
 * Highlights a single line of Sigma YAML.
 */
const highlightYamlLine = (line) => {
  if (line.trimStart().startsWith("#")) {
    return <span className="yaml-comment">{line}</span>;
  }

  const kvMatch = line.match(/^(\s*)([\w.]+)(:)\s*(.*)$/);
  if (kvMatch) {
    const [, indent, keyText, colon, value] = kvMatch;
    let valueEl;
    if (value.startsWith("'") || value.startsWith('"')) {
      valueEl = <span className="yaml-string">{value}</span>;
    } else if (/^(true|false)$/i.test(value)) {
      valueEl = <span className="yaml-bool">{value}</span>;
    } else if (/^\d+$/.test(value)) {
      valueEl = <span className="yaml-number">{value}</span>;
    } else if (value === "|" || value === ">") {
      valueEl = <span className="yaml-pipe">{value}</span>;
    } else {
      valueEl = <span className="yaml-value">{value}</span>;
    }
    return (
      <>
        {indent}
        <span className="yaml-key">{keyText}</span>
        <span className="yaml-dash">{colon}</span>{" "}
        {valueEl}
      </>
    );
  }

  const listMatch = line.match(/^(\s*)(- )(.*)$/);
  if (listMatch) {
    const [, indent, dash, value] = listMatch;
    let valEl;
    if (value.startsWith("'") || value.startsWith('"')) {
      valEl = <span className="yaml-string">{value}</span>;
    } else {
      valEl = <span className="yaml-value">{value}</span>;
    }
    return (
      <>
        {indent}
        <span className="yaml-dash">{dash}</span>
        {valEl}
      </>
    );
  }

  return <>{line}</>;
};

/* ═══════════════════════════════════════════════════════════════
   RulePreview Component
   ═══════════════════════════════════════════════════════════════ */

const RulePreview = ({
  snortRule = "",
  sigmaRule = "",
}) => {
  const [activeTab, setActiveTab] = useState(snortRule ? "snort" : "sigma");
  const [copied, setCopied] = useState(false);

  const currentRule = activeTab === "snort" ? snortRule : sigmaRule;
  const lines = currentRule.split("\n");

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(currentRule);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = currentRule;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [currentRule]);

  const highlightLine =
    activeTab === "snort" ? highlightSnortLine : highlightYamlLine;

  return (
    <div className="rule-preview">
      {/* Toolbar */}
      <div className="rule-preview-toolbar">
        {/* Tab Toggle */}
        <div className="rule-tab-group">
          {snortRule && (
            <button
              className={`rule-tab ${activeTab === "snort" ? "active" : ""}`}
              onClick={() => { setActiveTab("snort"); setCopied(false); }}
            >
              <span className="tab-dot"></span>
              <FaShieldAlt style={{ fontSize: "0.6rem" }} />
              Snort
            </button>
          )}
          {sigmaRule && (
            <button
              className={`rule-tab ${activeTab === "sigma" ? "active" : ""}`}
              onClick={() => { setActiveTab("sigma"); setCopied(false); }}
            >
              <span className="tab-dot"></span>
              <FaFileCode style={{ fontSize: "0.6rem" }} />
              Sigma
            </button>
          )}
        </div>

        {/* Copy Button */}
        <button
          className={`rule-copy-btn ${copied ? "copied" : ""}`}
          onClick={handleCopy}
          title="Copy to clipboard"
        >
          {copied ? (
            <FaCheck className="rule-copy-icon" />
          ) : (
            <FaCopy className="rule-copy-icon" />
          )}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      {/* Code Block */}
      <div className="rule-code-container">
        <pre className="rule-code-block">
          {lines.map((line, idx) => (
            <div key={idx} className="rule-line">
              <span className="rule-line-number">{idx + 1}</span>
              <span className="rule-line-content">{highlightLine(line)}</span>
            </div>
          ))}
        </pre>
      </div>

      {/* Footer */}
      <div className="rule-preview-footer">
        <span className="rule-lang-label">
          {activeTab === "snort" ? "Snort IDS Rule" : "Sigma Detection Rule"}
        </span>
        <span className="rule-line-count">{lines.length} lines</span>
      </div>
    </div>
  );
};

export default RulePreview;
