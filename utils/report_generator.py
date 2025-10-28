from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
)
from datetime import datetime
import os

def generate_report(results, output_file="scan_report.pdf", team_name="Team Jack Warriors", logo_path=None):
    """Generate a styled, professional vulnerability scan report."""

    # Create PDF
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()

    # --- Custom Styles ---
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=colors.HexColor("#2E86C1"),
        alignment=1,  # center
        spaceAfter=20
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=16,
        textColor=colors.HexColor("#1B4F72"),
        spaceAfter=10
    )
    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["Normal"],
        fontSize=11,
        leading=16
    )

    # --- Header ---
    if logo_path and os.path.exists(logo_path):
        story.append(Image(logo_path, width=80, height=80))
        story.append(Spacer(1, 10))

    story.append(Paragraph("🔐 Web Vulnerability Scanner Report", title_style))
    story.append(Paragraph(f"<b>Team:</b> {team_name}", normal_style))
    story.append(Paragraph(datetime.now().strftime("Generated on: %B %d, %Y — %I:%M %p"), normal_style))
    story.append(Spacer(1, 20))

    # --- Summary Section ---
    story.append(Paragraph("<b>Summary Overview</b>", heading_style))
    total = len(results)
    high = sum(1 for r in results if r.get("severity") == "High")
    medium = sum(1 for r in results if r.get("severity") == "Medium")
    low = sum(1 for r in results if r.get("severity") == "Low")

    summary_data = [
        ["Metric", "Count"],
        ["Total Findings", str(total)],
        ["High Severity", str(high)],
        ["Medium Severity", str(medium)],
        ["Low Severity", str(low)],
    ]
    table = Table(summary_data, colWidths=[200, 100])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#AED6F1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    # --- Detailed Findings ---
    story.append(Paragraph("<b>Detailed Vulnerability Report</b>", heading_style))
    story.append(Spacer(1, 10))

    if not results:
        story.append(Paragraph("✅ No vulnerabilities found. The target appears secure.", normal_style))
    else:
        for idx, res in enumerate(results, 1):
            severity = res.get("severity", "N/A")
            color = colors.black
            if severity == "High":
                color = colors.red
            elif severity == "Medium":
                color = colors.orange
            elif severity == "Low":
                color = colors.green

            vuln_table = Table([
                ["#", str(idx)],
                ["Vulnerability", res.get("name", "Unknown")],
                ["Severity", severity],
                ["Description", res.get("description", "No description provided.")],
                ["URL", res.get("url", "N/A")],
                ["Recommendation", res.get("recommendation", "N/A")],
            ], colWidths=[120, 380])

            vuln_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F8F5")),
                ("TEXTCOLOR", (1, 2), (1, 2), color),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
            ]))

            story.append(vuln_table)
            story.append(Spacer(1, 15))

    # --- Build PDF ---
    doc.build(story)
    print(f"✅ Report generated successfully: {output_file}")
