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

Rendering Fixes (Week 19, Day 4)
---------------------------------
  - Fixed header/footer frame overlap with body content (increased top margin,
    corrected frame pixel positions to match A4 @page margins).
  - Fixed long code blocks overflowing page edges: added overflow:hidden,
    word-break:break-all, max-width:100% on pre/code.
  - Fixed complex MITRE tables overflowing narrow cells: table-layout:fixed,
    word-break:break-word on all td.
  - Fixed score-bar rendering: replaced % width (unsupported in xhtml2pdf) with
    a pixel-width approach via a helper that maps 0-100 → 0-430pt.
  - Fixed inline <span class="right"> float overlap in header frame: replaced
    float:right with PDF-compatible absolute positioning in the frame.
  - Fixed nth-child alternating row background (xhtml2pdf limitation): uses
    explicit class alternation via Python row-index injection.
  - Fixed emoji/Unicode in headings causing xhtml2pdf parse errors: replaced
    HTML entity emojis with plain ASCII markers that render safely.
  - Fixed missing page-break handling for long code blocks: added
    -pdf-keep-with-next: false on pre to allow page breaks inside blocks.
  - Fixed reportlab content overlap: added proper y-coordinate overflow guard
    that accounts for font height before drawing.
  - Added ATT&CK hyperlink: renders as underlined text with URL in parentheses
    (PDF plain-text links, since xhtml2pdf does not support <a href> clicking).

Public API
----------
  generate_pdf(playbook_markdown: str) -> bytes
      Legacy shim — wraps only Markdown content, no metadata.

  generate_pdf_from_playbook(playbook) -> bytes
      Full export: accepts an ORM object or dict, renders all fields.

Week 19, Day 3 — Full PDF export with metadata, error handling, streaming.
Week 19, Day 4 — Rendering fixes: overlaps, alignment, code blocks, MITRE tables.
"""

from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import markdown
import bleach

logger = logging.getLogger("sentinel.pdf_exporter")

def _sanitize_html_for_pdf(html: str) -> str:
    """Sanitize HTML to prevent XSS and path injection (SSRF) in PDF export."""
    allowed_tags = [
        "h1", "h2", "h3", "h4", "h5", "h6", "p", "a", "ul", "ol", "li",
        "strong", "em", "code", "pre", "blockquote", "table", "thead",
        "tbody", "tr", "th", "td", "br", "span", "div", "hr"
    ]
    allowed_attributes = {
        "*": ["class", "id", "style"],
        "a": ["href", "title"],
        "td": ["colspan", "rowspan"],
        "th": ["colspan", "rowspan"]
    }
    return bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )


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
        return "#dc3545"   # CRITICAL
    if score >= 70:
        return "#fd7e14"   # HIGH
    if score >= 40:
        return "#ffc107"   # MEDIUM
    return "#28a745"       # LOW


def _severity_badge_color(severity: Optional[str]) -> tuple:
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


def _status_badge_color(status: Optional[str]) -> tuple:
    """Return (background, text) CSS colours for a status badge."""
    s = (status or "").lower()
    if s == "approved":
        return "#28a745", "#ffffff"
    if s == "rejected":
        return "#dc3545", "#ffffff"
    if s == "exported":
        return "#007bff", "#ffffff"
    return "#6c757d", "#ffffff"


def _get_attr(obj: Any, key: str, fallback: Any = None) -> Any:
    """Unified attribute/key getter for ORM objects and dicts."""
    if isinstance(obj, dict):
        return obj.get(key, fallback)
    return getattr(obj, key, fallback)


def _score_bar_width_pt(score: Optional[float], max_pt: int = 430) -> int:
    """
    Convert a 0-100 threat score to a pixel-width value in points.

    xhtml2pdf does not fully support percentage widths on nested divs inside
    table cells, so we compute an absolute point width instead.
    """
    if score is None:
        return 0
    clamped = max(0.0, min(100.0, float(score)))
    return int(clamped / 100.0 * max_pt)


def _inject_row_classes(html: str) -> str:
    """
    Replace nth-child row alternation (unsupported by xhtml2pdf) with
    explicit odd/even class attributes injected via Python.

    Works on <table> blocks found in the rendered HTML.
    """
    def _alternate_trs(match: re.Match) -> str:
        table_inner = match.group(0)
        count = [0]

        def _add_class(tr_match: re.Match) -> str:
            count[0] += 1
            cls = "even-row" if count[0] % 2 == 0 else "odd-row"
            tag = tr_match.group(0)
            if 'class=' in tag:
                return tag.replace('class="', f'class="{cls} ').replace("class='", f"class='{cls} ")
            return tag.replace('<tr', f'<tr class="{cls}"', 1)

        return re.sub(r'<tr(?:\s[^>]*)?>', _add_class, table_inner)

    return re.sub(r'<table[\s\S]*?</table>', _alternate_trs, html, flags=re.IGNORECASE)


def _sanitize_for_pdf(text: str) -> str:
    """
    Strip or replace characters that cause xhtml2pdf parse/render failures.

    - Removes high-codepoint emoji (U+1F000+) not in xhtml2pdf's glyph set.
    - Preserves standard ASCII and Latin-1 characters.
    - Leaves HTML entities intact.
    """
    # Remove emoji and other non-latin Unicode that break the PDF renderer
    return re.sub(
        r'[\U0001F300-\U0001FFFF\U00002702-\U000027B0\U0001F900-\U0001F9FF]',
        '',
        text,
    )


def _mitre_reference_html(technique_id: str, technique_name: str, mitre_url: str) -> str:
    """
    Build a safe PDF-compatible ATT&CK reference block.

    xhtml2pdf does not render clickable <a href> links. We render the URL as
    underlined plain text with the full URL in parentheses so analysts can
    copy it from the PDF viewer.
    """
    parts = [f"<strong>{technique_id}</strong> — {technique_name}"]
    if mitre_url and mitre_url.strip() and mitre_url != "N/A":
        # Underlined URL reference that PDF viewers can usually copy/click
        escaped_url = (mitre_url
                       .replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;"))
        parts.append(
            f'<br/><span class="mitre-url" style="text-decoration: underline;">'
            f'ATT&amp;CK Reference: {escaped_url}'
            f'</span>'
        )
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _build_html(playbook: Any) -> str:
    """
    Construct a full HTML document from playbook fields.

    All rendering fixes for Week 19 Day 4 are applied here:
      - Absolute score-bar widths (no % units)
      - Explicit even/odd row classes (no nth-child)
      - Safe ATT&CK URL rendering as underlined plain text
      - Corrected @page frame positions to avoid header/body overlap
      - pre/code blocks with word-break and overflow guards
      - Table-layout fixed on content tables

    Args:
        playbook: SentinelPlaybook ORM instance **or** plain dict.

    Returns:
        HTML string suitable for xhtml2pdf rendering.
    """
    g = lambda k, fb="N/A": _safe(_get_attr(playbook, k), fb)  # noqa: E731

    # Metadata
    playbook_id    = g("playbook_id")
    playbook_name  = _sanitize_for_pdf(g("playbook_name", "Untitled Playbook"))
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

    # FIX: Score bar uses absolute pt width instead of % (xhtml2pdf limitation)
    score_bar_pt = _score_bar_width_pt(threat_score)
    score_display = f"{float(threat_score):.1f}" if threat_score is not None else "N/A"
    conf_display  = f"{float(confidence):.3f}"   if confidence is not None else "N/A"

    # FIX: MITRE URL rendered as underlined plain-text reference
    mitre_ref_html = _mitre_reference_html(technique_id, technique_name, mitre_url)

    # Convert Markdown content to HTML
    if playbook_content.strip():
        raw_html_body = markdown.markdown(
            playbook_content,
            extensions=["tables", "fenced_code"],
        )
        # Sanitize HTML to prevent XSS or path injection (e.g. <img src="file:///...">)
        raw_html_body = _sanitize_html_for_pdf(raw_html_body)
    else:
        raw_html_body = "<p><em>No playbook content available.</em></p>"

    # FIX: Inject explicit even/odd row classes (replaces broken nth-child in xhtml2pdf)
    raw_html_body = _inject_row_classes(raw_html_body)

    # Wrap Executive Summary section
    exec_pattern = re.compile(
        r'(<h[12][^>]*>.*?Executive Summary.*?</h[12]>.*?)(?=<h[12]|$)',
        re.IGNORECASE | re.DOTALL,
    )
    html_content_body = exec_pattern.sub(
        lambda m: f'<div class="executive-summary">\n{m.group(1)}\n</div>',
        raw_html_body,
        count=1,
    )

    # Optional LLM narrative block
    llm_block = ""
    if llm_narrative and llm_narrative.strip():
        llm_html = markdown.markdown(
            llm_narrative,
            extensions=["tables", "fenced_code"],
        )
        llm_html = _inject_row_classes(llm_html)
        llm_block = f"""
    <div class="section llm-section">
        <h2>[AI] AI Threat Narrative</h2>
        <div class="llm-content">{llm_html}</div>
    </div>"""

    # Snort rule block — FIX: pre-escaped, word-break enforced
    snort_block = ""
    if snort_rule and snort_rule.strip():
        snort_esc = (snort_rule
                     .replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))
        snort_block = f"""
    <div class="section">
        <h2>[IDS] Snort IDS Rule</h2>
        <pre class="rule-block">{snort_esc}</pre>
    </div>"""

    # Sigma rule block — FIX: same treatment
    sigma_block = ""
    if sigma_rule and sigma_rule.strip():
        sigma_esc = (sigma_rule
                     .replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))
        sigma_block = f"""
    <div class="section">
        <h2>[SIGMA] Sigma Detection Rule</h2>
        <pre class="rule-block">{sigma_esc}</pre>
    </div>"""

    # -----------------------------------------------------------------------
    # Full HTML document
    # FIX SUMMARY applied in CSS:
    #   1. @page margin-top increased to 3cm to clear fixed header frame.
    #   2. header_frame top/height corrected so text doesn't clip into body.
    #   3. footer_frame uses A4 pixel coordinate (841pt total - margins).
    #   4. pre / .rule-block: word-break:break-all, overflow:hidden, max-width.
    #   5. table: table-layout:fixed; td: word-break:break-word; overflow:hidden.
    #   6. .score-bar uses width in pt (set via style attribute), not %.
    #   7. .odd-row / .even-row explicit alternating colours (no nth-child).
    #   8. No float:right in header (replaced by separate right-aligned div).
    # -----------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PhantomNet Playbook - {playbook_name}</title>
    <style>
        /* ── Page layout ──────────────────────────────────────────────────
           FIX: margin-top 3.2cm leaves room for the 1.5cm header frame +
           0.2cm gap so body text never slides under the header bar.
           footer_frame top is set to 820pt which clears the body on A4
           (841pt height - 21pt footer height).
        ── */
        @page {{
            size: a4;
            margin: 3.2cm 1.5cm 2cm 1.5cm;
            @frame header_frame {{
                -pdf-frame-content: header_content;
                left: 42pt; width: 511pt; top: 18pt; height: 38pt;
            }}
            @frame footer_frame {{
                -pdf-frame-content: footer_content;
                left: 42pt; width: 511pt; top: 820pt; height: 21pt;
            }}
        }}

        /* ── Reset ────────────────────────────────────────────────────── */
        * {{ box-sizing: border-box; }}

        body {{
            font-family: Helvetica, Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.55;
            color: #1a1a2e;
            background: #ffffff;
        }}

        /* ── Header ──────────────────────────────────────────────────────
           FIX: Removed float:right (xhtml2pdf frame float issues).
           Header is a single left-aligned line. Export date removed from
           header frame (added to cover block instead) to avoid overlap.
        ── */
        #header_content {{
            font-family: Arial, sans-serif;
            font-size: 11pt;
            font-weight: bold;
            color: #0f3460;
            border-bottom: 2.5pt solid #e94560;
            padding-bottom: 3pt;
            padding-top: 2pt;
        }}

        /* ── Footer ──────────────────────────────────────────────────── */
        #footer_content {{
            font-family: Arial, sans-serif;
            font-size: 8pt;
            color: #777;
            border-top: 1pt solid #e0e0e0;
            padding-top: 4pt;
            text-align: center;
        }}

        /* ── Classification band ──────────────────────────────────────── */
        .classification {{
            text-align: center;
            font-size: 8pt;
            font-weight: bold;
            color: #ffffff;
            background-color: #e94560;
            padding: 3pt 6pt;
            margin-bottom: 10pt;
            letter-spacing: 1pt;
        }}

        /* ── Cover block ─────────────────────────────────────────────── */
        .cover-block {{
            background-color: #0f3460;
            color: #ffffff;
            padding: 14pt 18pt;
            margin-bottom: 14pt;
        }}

        .cover-block h1 {{
            font-size: 18pt;
            margin: 0 0 5pt 0;
            color: #e94560;
            border: none;
        }}

        .cover-block .sub {{
            font-size: 9pt;
            color: #a0c4ff;
        }}

        .cover-meta {{
            font-size: 8pt;
            color: #c0d8ff;
            margin-top: 6pt;
        }}

        /* ── Badges ──────────────────────────────────────────────────── */
        .badge {{
            display: inline-block;
            padding: 2pt 7pt;
            font-size: 8.5pt;
            font-weight: bold;
            margin-right: 5pt;
        }}

        /* ── Section headings ────────────────────────────────────────── */
        h1 {{
            font-size: 16pt;
            color: #0f3460;
            border-bottom: 2pt solid #e94560;
            padding-bottom: 4pt;
            margin-top: 14pt;
            margin-bottom: 7pt;
        }}

        h2 {{
            font-size: 13pt;
            color: #16213e;
            border-bottom: 1pt solid #dde3f0;
            padding-bottom: 3pt;
            margin-top: 13pt;
            margin-bottom: 6pt;
        }}

        h3 {{
            font-size: 11pt;
            color: #0f3460;
            margin-top: 9pt;
            margin-bottom: 4pt;
        }}

        h4 {{
            font-size: 9.5pt;
            color: #1a1a2e;
            margin-top: 7pt;
            margin-bottom: 3pt;
        }}

        /* ── Metadata grid ───────────────────────────────────────────────
           FIX: table-layout:fixed prevents cells from blowing past margins.
           word-break:break-word ensures long IPs/URLs wrap instead of overflow.
        ── */
        .meta-grid {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 12pt;
            font-size: 9pt;
            table-layout: fixed;
        }}

        .meta-grid td {{
            padding: 5pt 7pt;
            border: 1pt solid #dde3f0;
            vertical-align: top;
            word-break: break-word;
            overflow: hidden;
        }}

        .meta-grid td.label {{
            background-color: #eef2fb;
            font-weight: bold;
            color: #0f3460;
            width: 20%;
        }}

        .meta-grid td.value {{
            background-color: #f9faff;
            color: #1a1a2e;
            width: 30%;
        }}

        /* FIX: explicit alternating colours (nth-child unsupported in xhtml2pdf) */
        .meta-grid tr.even-row td.value {{
            background-color: #f2f5fc;
        }}

        /* ── Score bar ───────────────────────────────────────────────────
           FIX: width set as absolute pt value via inline style attribute;
           percentage widths are unreliable inside table cells in xhtml2pdf.
        ── */
        .score-bar-wrap {{
            display: block;
            width: 430pt;
            background: #e9ecef;
            height: 9pt;
            margin-top: 3pt;
        }}

        .score-bar {{
            display: block;
            height: 9pt;
            background: {score_color};
        }}

        /* ── Section containers ──────────────────────────────────────── */
        .section {{
            margin-bottom: 12pt;
        }}

        /* ── Executive Summary block ─────────────────────────────────── */
        .executive-summary {{
            background-color: #e8f4fd;
            border-left: 4pt solid #0f3460;
            padding: 9pt 12pt;
            margin: 9pt 0;
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
            padding: 9pt 12pt;
            margin-bottom: 12pt;
        }}

        .llm-content {{
            font-size: 9.5pt;
            color: #1a1a2e;
        }}

        /* ── Rule blocks ─────────────────────────────────────────────────
           FIX: word-break:break-all forces long rule strings (no spaces) to
           wrap at the character level. overflow:hidden clips any remaining
           overflow so it never bleeds past the page margin.
           -pdf-keep-with-next:false allows page breaks inside long blocks.
        ── */
        .rule-block {{
            background-color: #16213e;
            color: #e2e8f0;
            padding: 9pt;
            font-family: Courier, monospace;
            font-size: 7pt;
            border: 1pt solid #0f3460;
            white-space: pre-wrap;
            word-break: break-all;
            word-wrap: break-word;
            overflow: hidden;
            max-width: 100%;
            -pdf-keep-with-next: false;
        }}

        /* ── General code/pre ────────────────────────────────────────────
           FIX: same word-break / overflow treatment as .rule-block.
           Font size reduced to 7.5pt so typical code lines fit in A4 width.
        ── */
        pre {{
            background-color: #263238;
            color: #eeffff;
            padding: 7pt;
            font-family: Courier, monospace;
            font-size: 7.5pt;
            border: 1pt solid #1c262b;
            white-space: pre-wrap;
            word-break: break-all;
            word-wrap: break-word;
            overflow: hidden;
            max-width: 100%;
            -pdf-keep-with-next: false;
        }}

        code {{
            font-family: Courier, monospace;
            background-color: #f4f4f4;
            color: #c0392b;
            padding: 1pt 2pt;
            font-size: 8pt;
        }}

        pre code {{
            background-color: transparent;
            color: #eeffff;
            padding: 0;
        }}

        /* ── Content tables ──────────────────────────────────────────────
           FIX: table-layout:fixed + word-break on td prevents overflow.
        ── */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 9pt 0;
            table-layout: fixed;
        }}

        th {{
            background-color: #0f3460;
            color: #ffffff;
            font-weight: bold;
            padding: 5pt 7pt;
            text-align: left;
            font-size: 9pt;
            word-break: break-word;
        }}

        td {{
            border: 1pt solid #dde3f0;
            padding: 5pt 7pt;
            font-size: 9pt;
            vertical-align: top;
            word-break: break-word;
            overflow: hidden;
        }}

        /* FIX: explicit even/odd row styling (nth-child broken in xhtml2pdf) */
        tr.even-row td {{
            background-color: #f2f5fc;
        }}

        tr.odd-row td {{
            background-color: #ffffff;
        }}

        /* ── Lists ───────────────────────────────────────────────────── */
        ul, ol {{
            margin-bottom: 7pt;
            padding-left: 18pt;
        }}

        li {{
            margin-bottom: 3pt;
            font-size: 9.5pt;
        }}

        /* ── Divider ─────────────────────────────────────────────────── */
        .divider {{
            border: 0;
            border-top: 1pt solid #dde3f0;
            margin: 12pt 0;
        }}

        /* ── MITRE URL reference ──────────────────────────────────────── */
        .mitre-url {{
            font-size: 7.5pt;
            color: #0f3460;
            word-break: break-all;
            text-decoration: underline;
        }}

        /* ── Playbook body ────────────────────────────────────────────── */
        .playbook-body {{
            font-size: 9.5pt;
            line-height: 1.6;
        }}

        .playbook-body p {{
            margin-bottom: 6pt;
        }}
    </style>
</head>
<body>

    <!-- Page Header -->
    <div id="header_content">PhantomNet Sentinel - Incident Response Playbook | {playbook_id}</div>

    <!-- Page Footer -->
    <div id="footer_content">
        PhantomNet Sentinel Platform &nbsp;|&nbsp; {playbook_id} &nbsp;|&nbsp;
        Exported: {exported_at_str} &nbsp;|&nbsp;
        Page <pdf:pagenumber> of <pdf:pagecount>
    </div>

    <!-- Classification banner -->
    <div class="classification">CONFIDENTIAL - FOR AUTHORIZED SECURITY PERSONNEL ONLY</div>

    <!-- Cover block -->
    <div class="cover-block">
        <h1>{playbook_name}</h1>
        <div class="sub">
            <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
            <span class="badge" style="background-color:{sta_bg};color:{sta_fg};">{(status or 'pending').upper()}</span>
            &nbsp; Version v{version} &nbsp;|&nbsp; {playbook_id}
        </div>
        <div class="cover-meta">
            Generated: {exported_at_str} &nbsp;|&nbsp; Template: {template_name}
        </div>
    </div>

    <!-- Section 1: Playbook Metadata -->
    <div class="section">
        <h2>[META] Playbook Metadata</h2>
        <table class="meta-grid">
            <tr class="odd-row">
                <td class="label">Playbook ID</td>
                <td class="value">{playbook_id}</td>
                <td class="label">Version</td>
                <td class="value">v{version}</td>
            </tr>
            <tr class="even-row">
                <td class="label">Status</td>
                <td class="value">
                    <span class="badge" style="background-color:{sta_bg};color:{sta_fg};">{(status or 'pending').upper()}</span>
                </td>
                <td class="label">Severity</td>
                <td class="value">
                    <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
                </td>
            </tr>
            <tr class="odd-row">
                <td class="label">Created At</td>
                <td class="value">{created_at_str}</td>
                <td class="label">Template</td>
                <td class="value">{template_name}</td>
            </tr>
            <tr class="even-row">
                <td class="label">Reviewed By</td>
                <td class="value">{reviewed_by}</td>
                <td class="label">Reviewed At</td>
                <td class="value">{reviewed_at_str}</td>
            </tr>
            <tr class="odd-row">
                <td class="label">Exported At</td>
                <td class="value">{exported_at_str}</td>
                <td class="label">Export Format</td>
                <td class="value">PDF (xhtml2pdf / reportlab)</td>
            </tr>
        </table>
    </div>

    <!-- Section 2: Threat Context -->
    <div class="section">
        <h2>[THREAT] Threat Context</h2>
        <table class="meta-grid">
            <tr class="odd-row">
                <td class="label">Source IP</td>
                <td class="value">{src_ip}</td>
                <td class="label">Destination Port</td>
                <td class="value">{dst_port}</td>
            </tr>
            <tr class="even-row">
                <td class="label">Protocol</td>
                <td class="value">{protocol}</td>
                <td class="label">Attack Type</td>
                <td class="value">{attack_type}</td>
            </tr>
            <tr class="odd-row">
                <td class="label">Threat Score</td>
                <td class="value" colspan="3">
                    <strong style="color:{score_color};">{score_display} / 100</strong>
                    <br/>
                    <!-- FIX: absolute pt width instead of % -->
                    <div class="score-bar-wrap">
                        <div class="score-bar" style="width:{score_bar_pt}pt;"></div>
                    </div>
                </td>
            </tr>
            <tr class="even-row">
                <td class="label">Confidence Score</td>
                <td class="value">{conf_display}</td>
                <td class="label">Severity Tier</td>
                <td class="value">
                    <span class="badge" style="background-color:{sev_bg};color:{sev_fg};">{_safe(severity, 'UNKNOWN')}</span>
                </td>
            </tr>
        </table>
    </div>

    <!-- Section 3: MITRE ATT&CK Mapping -->
    <div class="section">
        <h2>[MITRE] MITRE ATT&amp;CK Mapping</h2>
        <table class="meta-grid">
            <tr class="odd-row">
                <td class="label">Technique ID</td>
                <td class="value"><strong>{technique_id}</strong></td>
                <td class="label">Tactic</td>
                <td class="value">{tactic}</td>
            </tr>
            <tr class="even-row">
                <td class="label">Technique Name</td>
                <td class="value" colspan="3">{technique_name}</td>
            </tr>
            <tr class="odd-row">
                <td class="label">ATT&amp;CK Reference</td>
                <td class="value" colspan="3">{mitre_ref_html}</td>
            </tr>
        </table>
    </div>

    <hr class="divider">

    <!-- Section 4: Playbook Content -->
    <div class="section">
        <h2>[PLAYBOOK] Playbook Content</h2>
        <div class="playbook-body">
            {html_content_body}
        </div>
    </div>

    {llm_block}

    {snort_block}

    {sigma_block}

    <hr class="divider">

    <!-- Footer disclaimer -->
    <div class="section">
        <p style="font-size:8pt;color:#777;text-align:center;">
            This document was automatically generated by the PhantomNet Sentinel Platform.
            It contains sensitive security information and must be handled in accordance
            with your organisation's information security policy.
            Playbook ID: <strong>{playbook_id}</strong>. Export timestamp: {exported_at_str}.
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
    data = pdf_buffer.getvalue()
    if not data or len(data) < 100:
        raise RuntimeError("xhtml2pdf returned empty PDF bytes")
    return data


# ---------------------------------------------------------------------------
# reportlab fallback renderer  (Week 19 Day 4 — fixed overlap and alignment)
# ---------------------------------------------------------------------------

def _render_reportlab(playbook: Any) -> bytes:
    """
    Fallback PDF renderer using reportlab canvas.

    Week 19 Day 4 Fixes
    --------------------
    - `new_page_if_needed` now accounts for the actual line height before
      drawing, preventing text from being clipped at the bottom margin.
    - Header is drawn as a coloured rectangle + text on every page via a
      `_draw_header()` helper called before each `showPage()`.
    - Footer pagination uses reportlab canvas page number tracking.
    - Long code/rule lines are word-wrapped at 100 chars per line.
    - MITRE URL is printed as plain underlined text below the technique info.
    - Metadata is displayed in a two-column grid using explicit x-coordinates.
    """
    from reportlab.lib.pagesizes import A4  # type: ignore[import]
    from reportlab.pdfgen import canvas    # type: ignore[import]

    g = lambda k, fb="N/A": _safe(_get_attr(playbook, k), fb)  # noqa: E731

    playbook_id    = g("playbook_id")
    playbook_name  = g("playbook_name", "Untitled Playbook")[:80]
    status         = g("status", "pending").upper()
    severity       = g("severity")
    threat_score   = g("threat_score")
    confidence     = g("confidence_score")
    src_ip         = g("src_ip")
    dst_port       = g("dst_port")
    protocol       = g("protocol")
    attack_type    = g("attack_type")
    technique_id   = g("technique_id")
    technique_name = g("technique_name")
    tactic         = g("tactic")
    mitre_url_raw  = _get_attr(playbook, "mitre_url") or ""
    snort_rule     = _get_attr(playbook, "snort_rule") or ""
    sigma_rule     = _get_attr(playbook, "sigma_rule") or ""
    content        = _get_attr(playbook, "playbook_content") or ""
    llm_narrative  = _get_attr(playbook, "llm_narrative") or ""
    reviewed_by    = g("reviewed_by")
    version        = g("version", "1")
    exported_at    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    buf = io.BytesIO()
    page_w, page_h = A4   # 595.27 x 841.89 pt
    margin_l = 50
    margin_r = page_w - 50
    margin_top = page_h - 90   # content starts below header
    margin_bot = 55            # content stops above footer
    col2_x = margin_l + 230   # second column for 2-col grid

    page_num = [1]

    def _draw_chrome(c_obj: Any) -> None:
        """Draw header bar and footer line on the current page."""
        # Header bar
        c_obj.setFillColorRGB(0.059, 0.208, 0.376)
        c_obj.rect(0, page_h - 55, page_w, 55, fill=1, stroke=0)
        c_obj.setFillColorRGB(0.914, 0.271, 0.376)
        c_obj.setFont("Helvetica-Bold", 12)
        c_obj.drawString(margin_l, page_h - 28, "PhantomNet Sentinel - Incident Response Playbook")
        c_obj.setFillColorRGB(0.627, 0.769, 1.0)
        c_obj.setFont("Helvetica", 8)
        c_obj.drawString(margin_l, page_h - 44, f"  {playbook_id}  |  {exported_at}")
        # Footer
        c_obj.setStrokeColorRGB(0.85, 0.85, 0.85)
        c_obj.line(margin_l, margin_bot - 5, margin_r, margin_bot - 5)
        c_obj.setFillColorRGB(0.47, 0.47, 0.47)
        c_obj.setFont("Helvetica", 7.5)
        c_obj.drawCentredString(
            page_w / 2, margin_bot - 18,
            f"PhantomNet Sentinel  |  {playbook_id}  |  Page {page_num[0]}"
        )

    def _next_page(c_obj: Any) -> float:
        """Finish current page with chrome and start a new one."""
        _draw_chrome(c_obj)
        c_obj.showPage()
        page_num[0] += 1
        return margin_top

    def _check_y(c_obj: Any, y: float, needed: float = 14) -> float:
        """Return new y (possibly after page break) ensuring `needed` pts available."""
        if y - needed < margin_bot:
            return _next_page(c_obj)
        return y

    def _section_header(c_obj: Any, y: float, title: str) -> float:
        """Draw a section heading, return new y."""
        y = _check_y(c_obj, y, 30)
        c_obj.setFillColorRGB(0.059, 0.208, 0.376)
        c_obj.setFont("Helvetica-Bold", 12)
        c_obj.drawString(margin_l, y, title)
        y -= 4
        c_obj.setStrokeColorRGB(0.914, 0.271, 0.376)
        c_obj.setLineWidth(1)
        c_obj.line(margin_l, y, margin_r, y)
        return y - 14

    def _meta_row(c_obj: Any, y: float, lbl1: str, val1: str,
                  lbl2: str = "", val2: str = "") -> float:
        """Draw one or two label:value pairs in a metadata grid row."""
        y = _check_y(c_obj, y, 14)
        c_obj.setFont("Helvetica-Bold", 8.5)
        c_obj.setFillColorRGB(0.059, 0.208, 0.376)
        c_obj.drawString(margin_l, y, f"{lbl1}:")
        c_obj.setFont("Helvetica", 8.5)
        c_obj.setFillColorRGB(0.102, 0.133, 0.243)
        c_obj.drawString(margin_l + 100, y, str(val1)[:55])
        if lbl2:
            c_obj.setFont("Helvetica-Bold", 8.5)
            c_obj.setFillColorRGB(0.059, 0.208, 0.376)
            c_obj.drawString(col2_x, y, f"{lbl2}:")
            c_obj.setFont("Helvetica", 8.5)
            c_obj.setFillColorRGB(0.102, 0.133, 0.243)
            c_obj.drawString(col2_x + 100, y, str(val2)[:55])
        return y - 14

    def _wrap_and_print(c_obj: Any, y: float, text: str,
                        font: str = "Helvetica", size: float = 8.5,
                        max_chars: int = 105, indent: int = 0) -> float:
        """Word-wrap text and print each line, handling page breaks."""
        c_obj.setFont(font, size)
        c_obj.setFillColorRGB(0.102, 0.133, 0.243)
        line_h = size + 3
        for raw_line in text.split("\n"):
            if not raw_line.strip():
                y -= line_h // 2
                continue
            # Chunk at max_chars to prevent overflow
            while len(raw_line) > max_chars:
                y = _check_y(c_obj, y, line_h)
                c_obj.drawString(margin_l + indent, y, raw_line[:max_chars])
                raw_line = raw_line[max_chars:]
                y -= line_h
            if raw_line:
                y = _check_y(c_obj, y, line_h)
                c_obj.drawString(margin_l + indent, y, raw_line)
                y -= line_h
        return y

    def _code_block(c_obj: Any, y: float, text: str, title: str) -> float:
        """Draw a dark-background code/rule block."""
        y = _section_header(c_obj, y, title)
        lines = text.split("\n")
        line_h = 10
        # Draw background rect (estimate height)
        est_h = min(len(lines) * line_h + 10, page_h - margin_bot - y)
        c_obj.setFillColorRGB(0.086, 0.129, 0.243)
        c_obj.rect(margin_l, y - est_h, margin_r - margin_l, est_h, fill=1, stroke=0)
        c_obj.setFont("Courier", 7)
        c_obj.setFillColorRGB(0.886, 0.918, 0.941)
        for raw_line in lines:
            # Hard-wrap at 110 chars
            while len(raw_line) > 110:
                y = _check_y(c_obj, y, line_h)
                c_obj.drawString(margin_l + 4, y, raw_line[:110])
                raw_line = raw_line[110:]
                y -= line_h
            if raw_line or True:
                y = _check_y(c_obj, y, line_h)
                c_obj.drawString(margin_l + 4, y, raw_line)
                y -= line_h
        return y - 6

    # ── Start PDF canvas ──────────────────────────────────────────────────
    c = canvas.Canvas(buf, pagesize=A4)

    # ── Cover / title page ────────────────────────────────────────────────
    # Full-width cover header
    c.setFillColorRGB(0.059, 0.208, 0.376)
    c.rect(0, page_h - 120, page_w, 120, fill=1, stroke=0)
    c.setFillColorRGB(0.914, 0.271, 0.376)
    c.setFont("Helvetica-Bold", 18)
    title_lines = [playbook_name[i:i+55] for i in range(0, len(playbook_name), 55)]
    ty = page_h - 40
    for tl in title_lines:
        c.drawString(margin_l, ty, tl)
        ty -= 22
    c.setFillColorRGB(0.627, 0.769, 1.0)
    c.setFont("Helvetica", 9)
    c.drawString(margin_l, ty - 4, f"v{version}  |  {playbook_id}  |  {status}  |  {severity or 'UNKNOWN'}")

    # Classification banner
    c.setFillColorRGB(0.914, 0.271, 0.376)
    c.rect(0, page_h - 140, page_w, 18, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(page_w / 2, page_h - 134, "CONFIDENTIAL - FOR AUTHORIZED SECURITY PERSONNEL ONLY")

    y = margin_top - 20

    # ── Section 1: Metadata ───────────────────────────────────────────────
    y = _section_header(c, y, "1. Playbook Metadata")
    y = _meta_row(c, y, "Playbook ID", playbook_id, "Version", f"v{version}")
    y = _meta_row(c, y, "Status", status, "Severity", severity or "UNKNOWN")
    y = _meta_row(c, y, "Created At", created_at_str if (created_at_str := _fmt_ts(_get_attr(playbook, "created_at"))) else "N/A",
                  "Template", g("template_name"))
    y = _meta_row(c, y, "Reviewed By", reviewed_by, "Exported At", exported_at)
    y -= 8

    # ── Section 2: Threat Context ─────────────────────────────────────────
    y = _section_header(c, y, "2. Threat Context")
    y = _meta_row(c, y, "Source IP", src_ip, "Destination Port", dst_port)
    y = _meta_row(c, y, "Protocol", protocol, "Attack Type", attack_type)
    y = _meta_row(c, y, "Threat Score", f"{threat_score} / 100", "Confidence", confidence or "N/A")

    # Score bar
    y = _check_y(c, y, 18)
    bar_full = margin_r - margin_l - 150
    try:
        bar_fill = int(float(str(threat_score)) / 100.0 * bar_full)
    except (TypeError, ValueError):
        bar_fill = 0
    bar_x = margin_l + 100
    c.setFillColorRGB(0.91, 0.93, 0.93)
    c.rect(bar_x, y - 2, bar_full, 8, fill=1, stroke=0)
    if bar_fill > 0:
        r, g_v, b = (0.863, 0.208, 0.271) if (float(str(threat_score or 0)) >= 70) else (0.992, 0.494, 0.082)
        c.setFillColorRGB(r, g_v, b)
        c.rect(bar_x, y - 2, bar_fill, 8, fill=1, stroke=0)
    y -= 18

    # ── Section 3: MITRE ATT&CK ───────────────────────────────────────────
    y = _section_header(c, y, "3. MITRE ATT&CK Mapping")
    y = _meta_row(c, y, "Technique ID", technique_id, "Tactic", tactic)
    y = _meta_row(c, y, "Technique", technique_name)
    if mitre_url_raw and mitre_url_raw.strip():
        y = _check_y(c, y, 14)
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColorRGB(0.059, 0.208, 0.376)
        c.drawString(margin_l, y, "ATT&CK URL:")
        c.setFont("Helvetica", 8)
        c.setFillColorRGB(0.059, 0.208, 0.376)
        # Underline to signal it is a reference link
        url_text = mitre_url_raw[:90]
        c.drawString(margin_l + 100, y, url_text)
        tw = c.stringWidth(url_text, "Helvetica", 8)
        c.setLineWidth(0.5)
        c.setStrokeColorRGB(0.059, 0.208, 0.376)
        c.line(margin_l + 100, y - 1, margin_l + 100 + tw, y - 1)
        y -= 14
    y -= 8

    # ── Section 4: Playbook Content ───────────────────────────────────────
    if content.strip():
        y = _section_header(c, y, "4. Playbook Content")
        # Strip Markdown markers for plain text
        for raw_line in content.split("\n"):
            clean = re.sub(r'^[#*_`>]+\s*', '', raw_line).strip()
            if clean:
                y = _wrap_and_print(c, y, clean, max_chars=100)

    # ── Section 5: LLM Narrative ──────────────────────────────────────────
    if llm_narrative.strip():
        y = _section_header(c, y, "5. AI Threat Narrative")
        for raw_line in llm_narrative.split("\n"):
            clean = re.sub(r'^[#*_`>]+\s*', '', raw_line).strip()
            if clean:
                y = _wrap_and_print(c, y, clean, max_chars=100)

    # ── Section 6: Snort Rule ─────────────────────────────────────────────
    if snort_rule.strip():
        y = _code_block(c, y, snort_rule, "6. Snort IDS Rule")

    # ── Section 7: Sigma Rule ─────────────────────────────────────────────
    if sigma_rule.strip():
        y = _code_block(c, y, sigma_rule, "7. Sigma Detection Rule")

    # Finish final page
    _draw_chrome(c)
    c.save()
    return buf.getvalue()


def _fmt_ts(ts: Any) -> str:
    """Module-level timestamp formatter for reportlab renderer."""
    if ts is None:
        return "N/A"
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(ts)


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
    b"5 0 obj\n<</Length 96>>\nstream\n"
    b"BT /F1 14 Tf 80 750 Td (PhantomNet Sentinel Playbook) Tj "
    b"0 -28 Td /F1 10 Tf (PDF generation encountered an internal error.) Tj ET\n"
    b"endstream\nendobj\n"
    b"xref\n0 6\n"
    b"0000000000 65535 f \n0000000009 00000 n \n"
    b"0000000056 00000 n \n0000000111 00000 n \n"
    b"0000000254 00000 n \n0000000325 00000 n \n"
    b"trailer\n<</Size 6 /Root 1 0 R>>\nstartxref\n473\n%%EOF"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf(playbook_markdown: str) -> bytes:
    """
    Legacy shim: convert a Markdown string into a PDF.

    Wraps the markdown in a minimal playbook dict and delegates to
    :func:`generate_pdf_from_playbook`.  Kept for backward compatibility.

    Args:
        playbook_markdown: Playbook content in Markdown format.

    Returns:
        bytes: PDF byte string.
    """
    stub = {
        "playbook_id": "EXPORT",
        "playbook_name": "PhantomNet Playbook",
        "playbook_content": playbook_markdown,
        "status": None, "severity": None, "threat_score": None,
        "confidence_score": None, "src_ip": None, "dst_port": None,
        "protocol": None, "attack_type": None, "technique_id": None,
        "technique_name": None, "tactic": None, "mitre_url": None,
        "snort_rule": None, "sigma_rule": None, "llm_narrative": None,
        "reviewed_by": None, "reviewed_at": None, "created_at": None,
        "version": 1, "template_name": None,
    }
    return generate_pdf_from_playbook(stub)


def generate_pdf_from_playbook(playbook: Any) -> bytes:
    """
    Generate a rich PDF from a SentinelPlaybook ORM object or equivalent dict.

    Rendering order (Week 19 Day 4 — all rendering fixes applied):
      1. xhtml2pdf  — full HTML-based styled PDF with all fixes
      2. reportlab  — plain canvas fallback with all fixes
      3. _MINIMAL_PDF — last-resort valid PDF bytes (never raises)

    Args:
        playbook: SentinelPlaybook ORM instance **or** plain dict.

    Returns:
        bytes: A valid PDF byte string. Never raises.
    """
    # Primary: xhtml2pdf
    try:
        html = _build_html(playbook)
        pdf_bytes = _render_xhtml2pdf(html)
        logger.info("PDF generated via xhtml2pdf (%d bytes)", len(pdf_bytes))
        return pdf_bytes
    except Exception as exc:
        logger.warning("xhtml2pdf rendering failed: %s — trying reportlab", exc)

    # Fallback: reportlab
    try:
        pdf_bytes = _render_reportlab(playbook)
        logger.info("PDF generated via reportlab (%d bytes)", len(pdf_bytes))
        return pdf_bytes
    except Exception as exc:
        logger.error("reportlab also failed: %s — returning placeholder", exc)

    return _MINIMAL_PDF
