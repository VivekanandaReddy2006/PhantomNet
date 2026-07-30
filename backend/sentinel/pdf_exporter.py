"""
backend/sentinel/pdf_exporter.py
---------------------------------
PhantomNet Sentinel — PDF Export Engine

Converts a SentinelPlaybook record (ORM object or plain dict) into a
professionally styled PDF document with full PhantomNet branding.

Rendering pipeline
------------------
  1. Build a rich HTML document from playbook metadata + Markdown content.
  2. Convert HTML → PDF bytes via xhtml2pdf (primary path).
  3. If xhtml2pdf fails, fall back to reportlab canvas rendering.
  4. If reportlab also fails, return a minimal valid PDF placeholder so the
     endpoint always responds with *something* rather than a 500 error.

Public API
----------
  generate_pdf(playbook_markdown: str) -> bytes
      Legacy shim — wraps only Markdown content, no metadata.

  generate_pdf_from_playbook(playbook) -> bytes
      Full export: accepts an ORM object or dict, renders all fields.

Week 19, Day 3 — Full PDF export with metadata, error handling, streaming.
"""

from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

import markdown

logger = logging.getLogger("sentinel.pdf_exporter")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe(value: Any, fallback: str = "N/A") -> str:
    """Return str(value) or fallback when value is None/empty."""
    if value is None or str(value).strip() == "":
        return fallback
    return str(value)


def _score_color(score: Optional[float]) -> str:
    """Return a CSS colour string matching the threat score severity."""
    if score is None:
        return "#6c757d"
    if score >= 90:
        return "#dc3545"   # CRITICAL — red
    if score >= 70:
        return "#fd7e14"   # HIGH — orange
    if score >= 40:
        return "#ffc107"   # MEDIUM — amber
    return "#28a745"       # LOW — green


def _severity_badge_color(severity: Optional[str]) -> tuple[str, str]:
    """Return (background, text) CSS colours for a severity badge."""
    s = (severity or "").upper()
    if s == "CRITICAL":
        return "#dc3545", "#ffffff"
    if s == "HIGH":
        return "#fd7e14", "#ffffff"
    if s == "MEDIUM":
        return "#ffc107", "#212529"
    if s == "LOW":
        return "#28a745", "#ffffff"
    return "#6c757d", "#ffffff"


def _status_badge_color(status: Optional[str]) -> tuple[str, str]:
    """Return (background, text) CSS colours for a status badge."""
    s = (status or "").lower()
    if s == "approved":
        return "#28a745", "#ffffff"
    if s == "rejected":
        return "#dc3545", "#ffffff"
    if s == "exported":
        return "#007bff", "#ffffff"
    return "#6c757d", "#ffffff"     # pending / unknown


def _get_attr(obj: Any, key: str, fallback: Any = None) -> Any:
    """Unified attribute/key getter for ORM objects and dicts."""
    if isinstance(obj, dict):
        return obj.get(key, fallback)
    return getattr(obj, key, fallback)


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _build_html(playbook: Any) -> str:
    """
    Construct a full HTML document from playbook fields.

    Args:
        playbook: SentinelPlaybook ORM instance **or** plain dict.

    Returns:
        HTML string suitable for xhtml2pdf rendering.
    """
    g = lambda k, fb="N/A": _safe(_get_attr(playbook, k), fb)  # noqa: E731

    # Metadata
    playbook_id    = g("playbook_id")
    playbook_name  = g("playbook_name", "Untitled Playbook")
    status         = _get_attr(playbook, "status", "pending")
    severity       = _get_attr(playbook, "severity")
    threat_score   = _get_attr(playbook, "threat_score")
    confidence     = _get_attr(playbook, "confidence_score")
    src_ip         = g("src_ip")
    dst_port       = g("dst_port")
    protocol       = g("protocol")
    attack_type    = g("attack_type")
    technique_id   = g("technique_id")
    technique_name = g("technique_name")
    tactic         = g("tactic")
    mitre_url      = g("mitre_url", "")
    snort_rule     = _get_attr(playbook, "snort_rule")
    sigma_rule     = _get_attr(playbook, "sigma_rule")
    playbook_content = _get_attr(playbook, "playbook_content") or ""
    llm_narrative  = _get_attr(playbook, "llm_narrative")
    reviewed_by    = g("reviewed_by")
    reviewed_at_raw = _get_attr(playbook, "reviewed_at")
    created_at_raw  = _get_attr(playbook, "created_at")
    version        = g("version", "1")
    template_name  = g("template_name")

    # Format timestamps
    def _fmt_ts(ts: Any) -> str:
        if ts is None:
            return "N/A"
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(ts)

    created_at_str  = _fmt_ts(created_at_raw)
    reviewed_at_str = _fmt_ts(reviewed_at_raw)
    exported_at_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Colour helpers
    score_color = _score_color(threat_score)
    sev_bg, sev_fg = _severity_badge_color(severity)
    sta_bg, sta_fg = _status_badge_color(status)

    # Convert Markdown content to HTML
    html_content_body = ""
    if playbook_content.strip():
        html_content_body = markdown.markdown(
            playbook_content,
            extensions=["tables", "fenced_code"],
        )
    else:
        html_content_body = "<p><em>No playbook content available.</em></p>"

    # Wrap Executive Summary section
    exec_pattern = re.compile(
        r'(<h[12][^>]*>.*?Executive Summary.*?</h[12]>.*?)(?=<h[12]|$)',
        re.IGNORECASE | re.DOTALL,
    )
    html_content_body = exec_pattern.sub(
        lambda m: f'<div class="executive-summary">\n{m.group(1)}\n</div>',
        html_content_body,
        count=1,
    )

    # Optional LLM narrative block
    llm_block = ""
    if llm_narrative and llm_narrative.strip():
        llm_html = markdown.markdown(
            llm_narrative,
            extensions=["tables", "fenced_code"],
        )
        llm_block = f"""
        <div class="section llm-section">
            <h2>&#129504; AI Threat Narrative</h2>
            <div class="llm-content">{llm_html}</div>
        </div>"""

    # Snort rule block
    snort_block = ""
    if snort_rule and snort_rule.strip():
        snort_escaped = snort_rule.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        snort_block = f"""
        <div class="section">
            <h2>&#128737; Snort IDS Rule</h2>
            <pre class="rule-block">{snort_escaped}</pre>
        </div>"""

    # Sigma rule block
    sigma_block = ""
    if sigma_rule and sigma_rule.strip():
        sigma_escaped = sigma_rule.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        sigma_block = f"""
        <div class="section">
            <h2>&#128202; Sigma Detection Rule</h2>
            <pre class="rule-block">{sigma_escaped}</pre>
        </div>"""

    # MITRE URL link text (plain text for PDF)
    mitre_link = mitre_url if mitre_url and mitre_url != "N/A" else ""

    # Confidence display
    conf_display = f"{float(confidence):.3f}" if confidence is not None else "N/A"
    score_display = f"{float(threat_score):.1f}" if threat_score is not None else "N/A"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PhantomNet Playbook — {playbook_name}</title>
    <style>
        @page {{
            size: a4;
            margin: 2cm 1.5cm 2.5cm 1.5cm;
            @frame header_frame {{
                -pdf-frame-content: header_content;
                left: 50pt; width: 512pt; top: 30pt; height: 45pt;
            }}
            @frame footer_frame {{
                -pdf-frame-content: footer_content;
                left: 50pt; width: 512pt; top: 790pt; height: 20pt;
            }}
        }}

        /* ── Reset ────────────────────────────────────────────────────── */
        * {{ box-sizing: border-box; }}

        body {{
            font-family: Helvetica, Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
            color: #1a1a2e;
            background: #ffffff;
        }}

        /* ── Header / Footer ─────────────────────────────────────────── */
        #header_content {{
            font-family: Arial, sans-serif;
            font-size: 13pt;
            font-weight: bold;
            color: #0f3460;
            border-bottom: 2.5pt solid #e94560;
            padding-bottom: 4pt;
            text-align: left;
        }}

        #header_content span.right {{
            float: right;
            font-size: 8pt;
            font-weight: normal;
            color: #555;
            margin-top: 4pt;
        }}

        #footer_content {{
            font-family: Arial, sans-serif;
            font-size: 8pt;
            color: #777;
            border-top: 1pt solid #e0e0e0;
            padding-top: 4pt;
            text-align: center;
        }}

        /* ── Cover / Title area ──────────────────────────────────────── */
        .cover-block {{
            background-color: #0f3460;
            color: #ffffff;
            padding: 18pt 20pt;
            margin-bottom: 16pt;
            border-radius: 4pt;
        }}

        .cover-block h1 {{
            font-size: 20pt;
            margin: 0 0 6pt 0;
            color: #e94560;
            border: none;
        }}

        .cover-block .sub {{
            font-size: 10pt;
            color: #a0c4ff;
        }}

        .badge {{
            display: inline-block;
            padding: 2pt 8pt;
            border-radius: 3pt;
            font-size: 9pt;
            font-weight: bold;
            margin-right: 6pt;
        }}

        /* ── Section headings ────────────────────────────────────────── */
        h1 {{
            font-size: 18pt;
            color: #0f3460;
            border-bottom: 2pt solid #e94560;
            padding-bottom: 4pt;
            margin-top: 16pt;
            margin-bottom: 8pt;
        }}

        h2 {{
            font-size: 14pt;
            color: #16213e;
            border-bottom: 1pt solid #e0e0e0;
            padding-bottom: 3pt;
            margin-top: 14pt;
            margin-bottom: 6pt;
        }}

        h3 {{
            font-size: 12pt;
            color: #0f3460;
            margin-top: 10pt;
            margin-bottom: 4pt;
        }}

        h4 {{
            font-size: 10pt;
            color: #1a1a2e;
            margin-top: 8pt;
            margin-bottom: 3pt;
        }}

        /* ── Info grid (metadata table) ──────────────────────────────── */
        .meta-grid {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 14pt;
            font-size: 9pt;
        }}

        .meta-grid td {{
            padding: 5pt 8pt;
            border: 1pt solid #dde3f0;
            vertical-align: top;
        }}

        .meta-grid td.label {{
            background-color: #eef2fb;
            font-weight: bold;
            color: #0f3460;
            width: 22%;
            white-space: nowrap;
        }}

        .meta-grid td.value {{
            background-color: #f9faff;
            color: #1a1a2e;
        }}

        .meta-grid tr:nth-child(even) td.value {{
            background-color: #f2f5fc;
        }}

        /* ── Score bar ───────────────────────────────────────────────── */
        .score-bar-wrap {{
            display: block;
            width: 100%;
            background: #e9ecef;
            border-radius: 3pt;
            height: 10pt;
            margin-top: 3pt;
        }}

        .score-bar {{
            display: block;
            height: 10pt;
            border-radius: 3pt;
            background: {score_color};
        }}

        /* ── Section containers ──────────────────────────────────────── */
        .section {{
            margin-bottom: 14pt;
        }}

        /* ── Executive Summary ───────────────────────────────────────── */
        .executive-summary {{
            background-color: #e8f4fd;
            border-left: 4pt solid #0f3460;
            padding: 10pt 14pt;
            margin: 10pt 0;
            border-radius: 0 3pt 3pt 0;
        }}

        .executive-summary h1,
        .executive-summary h2 {{
            margin-top: 0;
            border-bottom: none;
            color: #0f3460;
        }}

        /* ── LLM narrative ───────────────────────────────────────────── */
        .llm-section {{
            background-color: #f0fff4;
            border: 1pt solid #28a745;
            border-radius: 3pt;
            padding: 10pt 14pt;
        }}

        .llm-content {{
            font-size: 9.5pt;
            color: #1a1a2e;
        }}

        /* ── Rule blocks ─────────────────────────────────────────────── */
        .rule-block {{
            background-color: #16213e;
            color: #e2e8f0;
            padding: 10pt;
            font-family: Courier, monospace;
            font-size: 7.5pt;
            border: 1pt solid #0f3460;
            border-radius: 3pt;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        /* ── General code/pre ────────────────────────────────────────── */
        pre {{
            background-color: #263238;
            color: #eeffff;
            padding: 8pt;
            font-family: Courier, monospace;
            font-size: 8pt;
            border: 1pt solid #1c262b;
            border-radius: 2pt;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        code {{
            font-family: Courier, monospace;
            background-color: #f4f4f4;
            color: #c0392b;
            padding: 1pt 3pt;
            font-size: 8.5pt;
            border-radius: 2pt;
        }}

        pre code {{
            background-color: transparent;
            color: #eeffff;
            padding: 0;
        }}

        /* ── Tables ──────────────────────────────────────────────────── */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10pt 0;
        }}

        th {{
            background-color: #0f3460;
            color: #ffffff;
            font-weight: bold;
            padding: 6pt 8pt;
            text-align: left;
            font-size: 9pt;
        }}

        td {{
            border: 1pt solid #dde3f0;
            padding: 5pt 8pt;
            font-size: 9pt;
        }}

        tr:nth-child(even) td {{
            background-color: #f2f5fc;
        }}

        /* ── Lists ───────────────────────────────────────────────────── */
        ul, ol {{
            margin-bottom: 8pt;
            padding-left: 20pt;
        }}

        li {{
            margin-bottom: 3pt;
        }}

        /* ── Divider ─────────────────────────────────────────────────── */
        .divider {{
            border: 0;
            border-top: 1pt solid #dde3f0;
            margin: 14pt 0;
        }}

        /* ── MITRE link ──────────────────────────────────────────────── */
        .mitre-url {{
            font-size: 8pt;
            color: #0f3460;
            word-break: break-all;
        }}

        /* ── Watermark / classification band ─────────────────────────── */
        .classification {{
            text-align: center;
            font-size: 8pt;
            font-weight: bold;
            color: #ffffff;
            background-color: #e94560;
            padding: 3pt;
            margin-bottom: 10pt;
            letter-spacing: 1pt;
            border-radius: 2pt;
        }}
    </style>
</head>
<body>

    <!-- ── Page Header ──────────────────────────────────────────────── -->
    <div id="header_content">
        &#128737; PhantomNet Sentinel — Incident Response Playbook
        <span class="right">Generated: {exported_at_str}</span>
    </div>

    <!-- ── Page Footer ──────────────────────────────────────────────── -->
    <div id="footer_content">
        PhantomNet Sentinel Platform &nbsp;|&nbsp; {playbook_id} &nbsp;|&nbsp;
        Page <pdf:pagenumber> of <pdf:pagecount>
    </div>

    <!-- ── Classification banner ────────────────────────────────────── -->
    <div class="classification">CONFIDENTIAL — FOR AUTHORIZED SECURITY PERSONNEL ONLY</div>

    <!-- ── Cover block ──────────────────────────────────────────────── -->
    <div class="cover-block">
        <h1>{playbook_name}</h1>
        <div class="sub">
            <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
            <span class="badge" style="background-color:{sta_bg};color:{sta_fg};">{(status or 'pending').upper()}</span>
            &nbsp;&nbsp; Version v{version} &nbsp;|&nbsp; {playbook_id}
        </div>
    </div>

    <!-- ── 1. Playbook Metadata ──────────────────────────────────────── -->
    <div class="section">
        <h2>&#128196; Playbook Metadata</h2>
        <table class="meta-grid">
            <tr>
                <td class="label">Playbook ID</td>
                <td class="value">{playbook_id}</td>
                <td class="label">Version</td>
                <td class="value">v{version}</td>
            </tr>
            <tr>
                <td class="label">Status</td>
                <td class="value">
                    <span class="badge" style="background-color:{sta_bg};color:{sta_fg};">{(status or 'pending').upper()}</span>
                </td>
                <td class="label">Severity</td>
                <td class="value">
                    <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
                </td>
            </tr>
            <tr>
                <td class="label">Created At</td>
                <td class="value">{created_at_str}</td>
                <td class="label">Template</td>
                <td class="value">{template_name}</td>
            </tr>
            <tr>
                <td class="label">Reviewed By</td>
                <td class="value">{reviewed_by}</td>
                <td class="label">Reviewed At</td>
                <td class="value">{reviewed_at_str}</td>
            </tr>
            <tr>
                <td class="label">Exported At</td>
                <td class="value">{exported_at_str}</td>
                <td class="label">Export Format</td>
                <td class="value">PDF</td>
            </tr>
        </table>
    </div>

    <!-- ── 2. Threat Context ─────────────────────────────────────────── -->
    <div class="section">
        <h2>&#128165; Threat Context</h2>
        <table class="meta-grid">
            <tr>
                <td class="label">Source IP</td>
                <td class="value">{src_ip}</td>
                <td class="label">Destination Port</td>
                <td class="value">{dst_port}</td>
            </tr>
            <tr>
                <td class="label">Protocol</td>
                <td class="value">{protocol}</td>
                <td class="label">Attack Type</td>
                <td class="value">{attack_type}</td>
            </tr>
            <tr>
                <td class="label">Threat Score</td>
                <td class="value" colspan="3">
                    <strong style="color:{score_color};">{score_display} / 100</strong>
                    <div class="score-bar-wrap">
                        <div class="score-bar" style="width:{min(int(float(threat_score or 0)), 100)}%;"></div>
                    </div>
                </td>
            </tr>
            <tr>
                <td class="label">Confidence Score</td>
                <td class="value">{conf_display}</td>
                <td class="label">Severity Tier</td>
                <td class="value">
                    <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
                </td>
            </tr>
        </table>
    </div>

    <!-- ── 3. MITRE ATT&CK Mapping ──────────────────────────────────── -->
    <div class="section">
        <h2>&#127919; MITRE ATT&amp;CK Mapping</h2>
        <table class="meta-grid">
            <tr>
                <td class="label">Technique ID</td>
                <td class="value"><strong>{technique_id}</strong></td>
                <td class="label">Tactic</td>
                <td class="value">{tactic}</td>
            </tr>
            <tr>
                <td class="label">Technique Name</td>
                <td class="value" colspan="3">{technique_name}</td>
            </tr>
            {"<tr><td class='label'>ATT&amp;CK URL</td><td class='value mitre-url' colspan='3'>" + mitre_link + "</td></tr>" if mitre_link else ""}
        </table>
    </div>

    <hr class="divider">

    <!-- ── 4. Playbook Content ───────────────────────────────────────── -->
    <div class="section">
        <h2>&#128221; Playbook Content</h2>
        <div class="playbook-body">
            {html_content_body}
        </div>
    </div>

    {llm_block}

    {snort_block}

    {sigma_block}

    <hr class="divider">

    <!-- ── 5. Footer disclaimer ──────────────────────────────────────── -->
    <div class="section">
        <p style="font-size:8pt;color:#777;text-align:center;">
            This document was automatically generated by the PhantomNet Sentinel Platform.
            It contains sensitive security information. Handle according to your organisation's
            information security policy. Playbook ID: <strong>{playbook_id}</strong>.
            Export timestamp: {exported_at_str}.
        </p>
    </div>

</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# xhtml2pdf renderer
# ---------------------------------------------------------------------------

def _render_xhtml2pdf(html: str) -> bytes:
    """Render HTML to PDF bytes using xhtml2pdf/pisa."""
    from xhtml2pdf import pisa  # type: ignore[import]

    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_buffer, encoding="utf-8")
    if pisa_status.err:
        raise RuntimeError(f"xhtml2pdf error code {pisa_status.err}")
    return pdf_buffer.getvalue()


# ---------------------------------------------------------------------------
# reportlab fallback renderer
# ---------------------------------------------------------------------------

def _render_reportlab(playbook: Any) -> bytes:
    """
    Fallback PDF renderer using reportlab canvas.

    Produces a plain but complete PDF when xhtml2pdf is unavailable or fails.
    """
    from reportlab.lib.pagesizes import A4  # type: ignore[import]
    from reportlab.pdfgen import canvas  # type: ignore[import]

    g = lambda k, fb="N/A": _safe(_get_attr(playbook, k), fb)  # noqa: E731

    playbook_id   = g("playbook_id")
    playbook_name = g("playbook_name", "Untitled Playbook")
    status        = g("status", "pending")
    severity      = g("severity")
    threat_score  = g("threat_score")
    src_ip        = g("src_ip")
    dst_port      = g("dst_port")
    protocol      = g("protocol")
    attack_type   = g("attack_type")
    technique_id  = g("technique_id")
    technique_name= g("technique_name")
    tactic        = g("tactic")
    snort_rule    = _get_attr(playbook, "snort_rule") or ""
    content       = _get_attr(playbook, "playbook_content") or ""
    reviewed_by   = g("reviewed_by")
    exported_at   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    buf = io.BytesIO()
    page_w, page_h = A4
    c = canvas.Canvas(buf, pagesize=A4)
    margin = 50

    def new_page_if_needed(y: float, needed: float = 30) -> float:
        if y < margin + needed:
            c.showPage()
            return page_h - margin
        return y

    # --- Title page ---
    c.setFillColorRGB(0.059, 0.208, 0.376)  # #0f3460
    c.rect(0, page_h - 80, page_w, 80, fill=1, stroke=0)
    c.setFillColorRGB(0.914, 0.271, 0.376)  # #e94560
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, page_h - 40, "PhantomNet Sentinel — Incident Response Playbook")
    c.setFillColorRGB(0.627, 0.769, 1.0)
    c.setFont("Helvetica", 9)
    c.drawString(margin, page_h - 60, f"Generated: {exported_at}")

    y = page_h - 110
    c.setFillColorRGB(0.059, 0.208, 0.376)
    c.setFont("Helvetica-Bold", 14)
    c.setFillColorRGB(0.102, 0.133, 0.243)
    c.drawString(margin, y, playbook_name)
    y -= 25

    # Metadata block
    fields = [
        ("Playbook ID",    playbook_id),
        ("Status",         status.upper()),
        ("Severity",       severity),
        ("Threat Score",   threat_score),
        ("Source IP",      src_ip),
        ("Destination Port", dst_port),
        ("Protocol",       protocol),
        ("Attack Type",    attack_type),
        ("Technique ID",   technique_id),
        ("Technique Name", technique_name),
        ("Tactic",         tactic),
        ("Reviewed By",    reviewed_by),
    ]

    c.setFont("Helvetica-Bold", 11)
    c.setFillColorRGB(0.059, 0.208, 0.376)
    c.drawString(margin, y, "Playbook Metadata")
    y -= 6
    c.setStrokeColorRGB(0.914, 0.271, 0.376)
    c.line(margin, y, page_w - margin, y)
    y -= 14

    for label, value in fields:
        y = new_page_if_needed(y)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColorRGB(0.059, 0.208, 0.376)
        c.drawString(margin, y, f"{label}:")
        c.setFont("Helvetica", 9)
        c.setFillColorRGB(0.102, 0.133, 0.243)
        c.drawString(margin + 130, y, str(value)[:80])
        y -= 15

    # Snort rule
    if snort_rule.strip():
        y -= 10
        y = new_page_if_needed(y, 60)
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0.059, 0.208, 0.376)
        c.drawString(margin, y, "Snort IDS Rule")
        y -= 6
        c.line(margin, y, page_w - margin, y)
        y -= 14
        c.setFont("Courier", 7.5)
        c.setFillColorRGB(0.102, 0.133, 0.243)
        for line in snort_rule.split("\n"):
            y = new_page_if_needed(y)
            c.drawString(margin, y, line[:110])
            y -= 12

    # Playbook content
    if content.strip():
        y -= 10
        y = new_page_if_needed(y, 40)
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0.059, 0.208, 0.376)
        c.drawString(margin, y, "Playbook Content")
        y -= 6
        c.line(margin, y, page_w - margin, y)
        y -= 14
        c.setFont("Helvetica", 8.5)
        c.setFillColorRGB(0.102, 0.133, 0.243)
        for line in content.split("\n"):
            y = new_page_if_needed(y)
            # Strip basic markdown symbols for readability
            clean = re.sub(r'^[#*_`>]+\s*', '', line).strip()
            if clean:
                c.drawString(margin, y, clean[:105])
                y -= 13

    c.save()
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Minimal valid PDF placeholder (last-resort fallback)
# ---------------------------------------------------------------------------

_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n"
    b"2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n"
    b"3 0 obj\n<</Type /Page /Parent 2 0 R /Resources "
    b"<</Font <</F1 4 0 R>>>>"
    b" /MediaBox [0 0 595.27 841.89] /Contents 5 0 R>>\nendobj\n"
    b"4 0 obj\n<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>\nendobj\n"
    b"5 0 obj\n<</Length 82>>\nstream\n"
    b"BT /F1 18 Tf 100 750 Td (PhantomNet Sentinel Playbook) Tj "
    b"0 -30 Td /F1 11 Tf (PDF generation encountered an error.) Tj ET\n"
    b"endstream\nendobj\n"
    b"xref\n0 6\n"
    b"0000000000 65535 f \n0000000009 00000 n \n"
    b"0000000056 00000 n \n0000000111 00000 n \n"
    b"0000000254 00000 n \n0000000325 00000 n \n"
    b"trailer\n<</Size 6 /Root 1 0 R>>\nstartxref\n459\n%%EOF"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf(playbook_markdown: str) -> bytes:
    """
    Legacy shim: convert a Markdown string into a PDF.

    Wraps the markdown in a minimal playbook dict and delegates to
    :func:`generate_pdf_from_playbook`.  Kept for backward compatibility
    with any existing callers that pass only the content string.

    Args:
        playbook_markdown: Playbook content in Markdown format.

    Returns:
        bytes: PDF byte string.

    Raises:
        RuntimeError: If all rendering backends fail.
    """
    stub = {
        "playbook_id": "EXPORT",
        "playbook_name": "PhantomNet Playbook",
        "playbook_content": playbook_markdown,
        "status": None,
        "severity": None,
        "threat_score": None,
        "confidence_score": None,
        "src_ip": None,
        "dst_port": None,
        "protocol": None,
        "attack_type": None,
        "technique_id": None,
        "technique_name": None,
        "tactic": None,
        "mitre_url": None,
        "snort_rule": None,
        "sigma_rule": None,
        "llm_narrative": None,
        "reviewed_by": None,
        "reviewed_at": None,
        "created_at": None,
        "version": 1,
        "template_name": None,
    }
    return generate_pdf_from_playbook(stub)


def generate_pdf_from_playbook(playbook: Any) -> bytes:
    """
    Generate a rich PDF from a SentinelPlaybook ORM object or equivalent dict.

    Rendering order:
      1. xhtml2pdf  — full HTML-based styled PDF (primary)
      2. reportlab  — plain canvas fallback
      3. _MINIMAL_PDF — last-resort valid PDF bytes (never raises)

    Args:
        playbook: SentinelPlaybook ORM instance **or** plain dict with the
                  same field names.

    Returns:
        bytes: A valid PDF byte string.  Never raises — on total failure a
               minimal placeholder PDF is returned so the endpoint always
               delivers a downloadable file.
    """
    # ── Primary: xhtml2pdf ──────────────────────────────────────────────
    try:
        html = _build_html(playbook)
        pdf_bytes = _render_xhtml2pdf(html)
        logger.info("PDF generated via xhtml2pdf (%d bytes)", len(pdf_bytes))
        return pdf_bytes
    except Exception as exc:
        logger.warning("xhtml2pdf rendering failed: %s — trying reportlab fallback", exc)

    # ── Fallback: reportlab ─────────────────────────────────────────────
    try:
        pdf_bytes = _render_reportlab(playbook)
        logger.info("PDF generated via reportlab fallback (%d bytes)", len(pdf_bytes))
        return pdf_bytes
    except Exception as exc:
        logger.error(
            "reportlab fallback also failed: %s — returning minimal placeholder PDF", exc
        )

    # ── Last resort: minimal valid PDF ──────────────────────────────────
    return _MINIMAL_PDF
