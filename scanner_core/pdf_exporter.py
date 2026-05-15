from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from pathlib import Path

# Base directory = project root (one level above scanner_core)
BASE_DIR = Path(__file__).resolve().parent.parent

# Reports directory (shared with logger.py)
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

TXT_REPORT_PATH = REPORTS_DIR / "vulnerability_log.txt"
PDF_REPORT_PATH = REPORTS_DIR / "vulnerability_report.pdf"


def _draw_wrapped_text(c, text, x, y, max_width, line_height):
    """
    Helper to draw word-wrapped text on the PDF.
    Returns the new y position after drawing.
    """
    from textwrap import wrap

    lines = wrap(text, width=int(max_width / 6))  # rough chars-per-line estimate
    for line in lines:
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 11)
            y = letter[1] - 50
        c.drawString(x, y, line)
        y -= line_height
    return y


def generate_pdf_report(
    findings=None,
    summary=None,
    target_url: str | None = None,
    txt_path: Path = TXT_REPORT_PATH,
    pdf_path: Path = PDF_REPORT_PATH,
) -> None:
    """
    Generate a PDF report.

    If findings/summary are provided, they are used to build a structured
    report. The plain text log file is appended at the end (optional) for
    raw reference.
    """
    findings = findings or []
    summary = summary or {"total": 0, "by_type": {}}

    lines_from_log = []
    if txt_path.exists():
        with txt_path.open("r", encoding="utf-8") as f:
            lines_from_log = f.readlines()

    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 14)
    c.drawString(
        30,
        height - 40,
        "Web Vulnerability Scan Report",
    )

    c.setFont("Helvetica", 11)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(30, height - 60, f"Generated: {timestamp}")
    if target_url:
        c.drawString(30, height - 75, f"Target: {target_url}")

    y = height - 100

    # Summary section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, y, "Summary")
    y -= 20
    c.setFont("Helvetica", 11)

    c.drawString(40, y, f"Total findings: {summary.get('total', 0)}")
    y -= 18

    by_type = summary.get("by_type", {})
    if by_type:
        c.drawString(40, y, "By type:")
        y -= 18
        for vtype, count in by_type.items():
            c.drawString(50, y, f"- {vtype}: {count}")
            y -= 16
    else:
        c.drawString(40, y, "No findings detected by this scan.")
        y -= 18

    # Detailed findings
    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, y, "Detailed Findings")
    y -= 20
    c.setFont("Helvetica", 11)

    if findings:
        for idx, f in enumerate(findings, start=1):
            type_val = f.get("type", "Unknown")
            url_val = f.get("url", "Unknown URL")
            severity = f.get("severity", "unknown")
            parameter = f.get("parameter") or "-"
            evidence = f.get("evidence", "")

            if y < 80:
                c.showPage()
                c.setFont("Helvetica", 11)
                y = height - 50

            c.setFont("Helvetica-Bold", 11)
            c.drawString(30, y, f"{idx}. {type_val} (Severity: {severity})")
            y -= 16
            c.setFont("Helvetica", 11)
            y = _draw_wrapped_text(
                c, f"URL: {url_val}", 40, y, max_width=width - 80, line_height=14
            )
            y = _draw_wrapped_text(
                c, f"Parameter: {parameter}", 40, y, max_width=width - 80, line_height=14
            )
            if evidence:
                y = _draw_wrapped_text(
                    c,
                    f"Evidence: {evidence}",
                    40,
                    y,
                    max_width=width - 80,
                    line_height=14,
                )
            y -= 6
    else:
        c.drawString(40, y, "No detailed findings (site considered safe by this scanner).")
        y -= 16

    # Raw log section (optional)
    if lines_from_log:
        if y < 80:
            c.showPage()
            y = height - 50

        c.setFont("Helvetica-Bold", 12)
        c.drawString(30, y, "Raw Text Log")
        y -= 20
        c.setFont("Helvetica", 9)

        for line in lines_from_log:
            line = line.rstrip("\n")
            if y < 40:
                c.showPage()
                c.setFont("Helvetica", 9)
                y = height - 40
            c.drawString(30, y, line)
            y -= 12

    c.save()
    print(f"PDF report generated at: {pdf_path}")