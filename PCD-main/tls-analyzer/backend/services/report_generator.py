"""PDF report generator (optional — returns None if reportlab not available)."""

from typing import Optional


def generate_pdf(report) -> Optional[bytes]:
    """Generate a PDF security report. Returns bytes or None if unavailable."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        import io

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("TLS Security Analysis Report", styles["Title"]))
        story.append(Spacer(1, 10 * mm))

        # App info
        app = report.app
        story.append(Paragraph(f"Application: {app.app_name or app.package_name}", styles["Heading2"]))
        story.append(Paragraph(f"Package: {app.package_name}", styles["Normal"]))
        story.append(Paragraph(f"Category: {app.category or 'N/A'}", styles["Normal"]))
        story.append(Spacer(1, 5 * mm))

        # Prediction
        if report.prediction:
            p = report.prediction
            story.append(Paragraph("Security Assessment", styles["Heading2"]))
            story.append(Paragraph(f"Security Score: {p.security_score}/100", styles["Normal"]))
            story.append(Paragraph(f"Risk Level: {p.risk_level}", styles["Normal"]))
            story.append(Paragraph(f"PQC Readiness: {p.pqc_readiness_score}/100", styles["Normal"]))
            story.append(Spacer(1, 5 * mm))

        # Warranty
        if report.warranty:
            w = report.warranty
            story.append(Paragraph("Security Warranty", styles["Heading2"]))
            story.append(Paragraph(f"Status: {w.status}", styles["Normal"]))
            story.append(Paragraph(f"Justification: {w.justification}", styles["Normal"]))
            story.append(Spacer(1, 5 * mm))

        # Domains
        if report.domains:
            story.append(Paragraph("Domains Analyzed", styles["Heading2"]))
            data = [["Domain", "Third Party", "Class"]]
            for d in report.domains:
                data.append([d.domain, "Yes" if d.is_third_party else "No", d.domain_class or ""])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 5 * mm))

        # Vulnerabilities
        if report.vulnerabilities:
            story.append(Paragraph("Vulnerabilities", styles["Heading2"]))
            data = [["CVE", "Severity", "CVSS", "Description"]]
            for v in report.vulnerabilities[:20]:
                data.append([v.cve_id or "N/A", v.severity, str(v.cvss_score or ""), v.description[:80]])
            t = Table(data, colWidths=[60, 50, 30, 300])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]))
            story.append(t)

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        return None
