"""
Module for exporting Markdown playbooks to PDF using xhtml2pdf.
"""

import re
from io import BytesIO

import markdown
# pyrefly: ignore [missing-import]
from xhtml2pdf import pisa


def generate_pdf(playbook_markdown: str) -> bytes:
    """
    Converts a Markdown playbook into a styled PDF document with PhantomNet branding.

    Args:
        playbook_markdown (str): The playbook content in Markdown format.

    Returns:
        bytes: The generated PDF as a byte string.
    """
    # Convert Markdown to HTML
    html_content = markdown.markdown(
        playbook_markdown,
        extensions=["tables", "fenced_code"]
    )

    # Wrap the Executive Summary section in a div for special styling
    pattern = re.compile(
        r'(<h[12][^>]*>.*?Executive Summary.*?</h[12]>.*?)(?=<h[12]|$)',
        re.IGNORECASE | re.DOTALL
    )

    def wrap_exec_summary(match):
        return f'<div class="executive-summary">\n{match.group(1)}\n</div>'

    html_content = pattern.sub(wrap_exec_summary, html_content, count=1)

    # Build HTML document with styling supported by xhtml2pdf
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>PhantomNet Playbook</title>
        <style>
            @page {{
                size: a4;
                margin: 2cm 1.5cm;
                @frame header_frame {{
                    -pdf-frame-content: header_content;
                    left: 50pt; width: 512pt; top: 50pt; height: 40pt;
                }}
                @frame footer_frame {{
                    -pdf-frame-content: footer_content;
                    left: 50pt; width: 512pt; top: 772pt; height: 20pt;
                }}
            }}

            body {{
                font-family: Helvetica, Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.5;
                color: #333;
            }}

            #header_content {{
                font-family: Arial, sans-serif;
                font-size: 14pt;
                font-weight: bold;
                color: #004d40;
                border-bottom: 2px solid #004d40;
                padding-bottom: 5px;
                text-align: center;
            }}

            #footer_content {{
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #555;
                border-top: 1px solid #ccc;
                padding-top: 5px;
                text-align: center;
            }}

            h1, h2, h3, h4 {{
                color: #00251a;
                margin-top: 15px;
                margin-bottom: 5px;
            }}

            h1 {{ font-size: 22pt; border-bottom: 2px solid #004d40; padding-bottom: 5px; }}
            h2 {{ font-size: 18pt; border-bottom: 1px solid #e0e0e0; padding-bottom: 3px; }}
            h3 {{ font-size: 14pt; }}

            /* Executive Summary Styling */
            .executive-summary {{
                background-color: #e0f2f1;
                border-left: 5px solid #004d40;
                padding: 10px;
                margin: 15px 0;
            }}

            .executive-summary h1, .executive-summary h2 {{
                margin-top: 0;
                border-bottom: none;
                color: #004d40;
            }}

            /* MITRE Code block formatting */
            pre {{
                background-color: #263238;
                color: #eeffff;
                padding: 10px;
                font-family: Courier, monospace;
                border: 1px solid #1c262b;
            }}

            code {{
                font-family: Courier, monospace;
                background-color: #f4f4f4;
                color: #d32f2f;
                padding: 2px;
                font-size: 0.9em;
            }}

            pre code {{
                background-color: transparent;
                color: #eeffff;
                padding: 0;
                font-size: 1em;
            }}

            /* Dynamic Table Bounds */
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                -pdf-keep-with-next: true;
            }}

            tr {{
                -pdf-keep-with-next: true;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}

            th {{
                background-color: #004d40;
                color: white;
                font-weight: bold;
            }}

            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}

            ul, ol {{
                margin-bottom: 10px;
            }}

            li {{
                margin-bottom: 3px;
            }}
        </style>
    </head>
    <body>
        <div id="header_content">PhantomNet Playbook</div>
        <div id="footer_content">
            Page <pdf:pagenumber> of <pdf:pagecount>
        </div>
        <div class="content">
            {html_content}
        </div>
    </body>
    </html>
    """

    pdf_buffer = BytesIO()
    pisa_status = pisa.CreatePDF(
        full_html,
        dest=pdf_buffer,
        encoding='utf-8'
    )

    if pisa_status.err:
        raise RuntimeError(f"Failed to generate PDF: {pisa_status.err}")

    return pdf_buffer.getvalue()
