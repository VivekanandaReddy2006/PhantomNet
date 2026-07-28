# Architecture Decision Note: PDF Export for Playbook Documentation

## 1. Objective
To evaluate and decide on the most suitable library and architecture for generating PDF reports of playbook documentation. The evaluation considers both client-side and server-side options.

## 2. Options Evaluated

### Option A: Client-Side Generation (jsPDF + jsPDF-autotable)
This approach leverages JavaScript running in the user's browser to generate the PDF file.

*   **Pros:**
    *   **Zero Server Load:** Offloads all PDF processing to the client, reducing server CPU and memory usage.
    *   **Instant Download:** No network latency for generating the file since data is already on the client.
    *   **Good for Simple Data:** `jspdf-autotable` handles basic tables very well.
*   **Cons:**
    *   **Formatting Limitations:** jsPDF uses a canvas/coordinate-based drawing API. Complex layouts, precise typography, and rich HTML formatting are difficult to achieve.
    *   **Performance on Large Data:** Generating large PDFs (100+ pages) can crash the browser tab or freeze the UI.
    *   **Inconsistent Rendering:** Fonts and layouts can sometimes render slightly differently across different browsers.

### Option B: Server-Side Generation with Python (WeasyPrint)
WeasyPrint is a visual rendering engine for HTML and CSS that can export to PDF.

*   **Pros:**
    *   **HTML/CSS Driven:** Templates can be designed using standard web technologies (e.g., Jinja2 + CSS3). This is highly advantageous for complex playbook layouts.
    *   **Rich Formatting:** Supports advanced CSS print media features (page breaks, headers, footers, page numbering).
    *   **Consistency:** Guaranteed to look the same regardless of the client's browser.
*   **Cons:**
    *   **Performance:** Can be slow and memory-intensive for very large documents compared to native PDF libraries.
    *   **Heavy Dependencies:** Requires Cairo, Pango, and GDK-PixBuf installed on the server.

### Option C: Server-Side Generation with Python (ReportLab)
ReportLab is a robust, low-level Python library for creating complex PDFs.

*   **Pros:**
    *   **High Performance:** Extremely fast and efficient, even for massive documents.
    *   **Precise Control:** Offers exact positioning of text, shapes, and images.
*   **Cons:**
    *   **Steep Learning Curve:** Not HTML-based. Layouts must be programmed using ReportLab's proprietary layout engine (Platypus) or canvas API.
    *   **Harder to Maintain:** Updating styles requires changing Python code rather than simply updating a CSS file.

## 3. Technical Decision

**Decision:** We will adopt a **Hybrid/Fallback Strategy**, prioritizing **Server-Side Rendering with WeasyPrint** for high-quality Playbook reports.

**Rationale:**
Playbook documentation typically requires professional formatting, including cover pages, table of contents, headers/footers with logos, and complex nested data structures.
*   **Client-side (`jsPDF`)** is deemed insufficient for the primary export because maintaining complex CSS-like styling via coordinate math becomes unmanageable for rich playbook reports.
*   Between the Python options, **WeasyPrint** is chosen over ReportLab because it allows us to reuse our existing HTML/CSS knowledge and web templates. The performance trade-off is acceptable for the expected size of playbook reports.

*Note: jsPDF + autotable can be retained for simple, quick data table exports (e.g., exporting a basic list of indicators or logs) where rich formatting is not required.*

## 4. Setup & Styling Guidelines

### Backend Setup (WeasyPrint)
1.  **System Dependencies:** Ensure OS-level dependencies (Pango, Cairo) are installed.
2.  **Python Package:** `pip install WeasyPrint Jinja2`
3.  **Template Engine:** Use Jinja2 to render HTML templates injected with playbook data.
4.  **PDF Generation:** Pass the rendered HTML string to `weasyprint.HTML(string=...).write_pdf()`.

### Styling Guidelines for PDF Playbooks
To ensure professional-grade PDFs using WeasyPrint, adhere to the following CSS guidelines:

*   **Page Layout:**
    ```css
    @page {
        size: A4;
        margin: 2cm;
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
        }
        @top-center {
            content: "Confidential - Playbook Report";
            font-size: 9pt;
            color: #777;
        }
    }
    ```
*   **Typography:** Use standard, easily embedded fonts (e.g., Arial, Helvetica, or open-source fonts like Roboto loaded via `@font-face`). Ensure high contrast for readability.
*   **Page Breaks:** Prevent awkward cuts in critical sections:
    ```css
    .playbook-step, .table-container {
        page-break-inside: avoid;
    }
    h1, h2, h3 {
        page-break-after: avoid;
    }
    ```
*   **Tables:** Ensure tables span the full width and have clear borders for print visibility.
    ```css
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
    }
    th {
        background-color: #f2f2f2;
    }
    ```
*   **Colors:** Prefer a minimalist color palette optimized for printing (avoid large dark background areas to save ink, use shades of gray and primary brand colors for highlights).
