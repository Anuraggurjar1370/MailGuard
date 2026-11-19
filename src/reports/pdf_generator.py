"""
MailGuard PDF Report Generation Module.
Generates comprehensive forensic security audit reports for individual emails
and full dataset batch dossiers using ReportLab.
"""

import io
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak, KeepTogether
)


def _get_verdict_colors(verdict: str):
    v = (verdict or "").upper()
    if "DANGEROUS" in v or "PHISH" in v:
        return colors.HexColor("#be123c"), colors.HexColor("#ffe4e6"), colors.HexColor("#e11d48")
    elif "SUSPICIOUS" in v:
        return colors.HexColor("#b45309"), colors.HexColor("#fef3c7"), colors.HexColor("#d97706")
    else:
        return colors.HexColor("#047857"), colors.HexColor("#d1fae5"), colors.HexColor("#059669")


class PDFReportGenerator:
    """
    Builds professional forensic PDF reports for single emails and batch datasets.
    """

    @staticmethod
    def generate_single_report(scan_data: Dict[str, Any]) -> bytes:
        """
        Generate a complete forensic PDF audit report for a single analyzed email.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]
        normal_style.fontSize = 9
        normal_style.leading = 12

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold"
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=normal_style,
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b")
        )
        section_style = ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            "BodySmall",
            parent=normal_style,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # --- Header ---
        header_table_data = [
            [
                Paragraph("<b>MAILGUARD DEFENSE</b> | Forensics Security Report", title_style),
                Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/><b>Engine:</b> {scan_data.get('model_name', 'Soft-Voting Ensemble')}", subtitle_style)
            ]
        ]
        header_table = Table(header_table_data, colWidths=[360, 180])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # --- Verdict & Risk Score Banner ---
        verdict = scan_data.get("verdict", "Safe")
        risk_score = scan_data.get("risk_score", 0)
        prob = scan_data.get("phishing_probability", 0.0) * 100
        dark_col, light_col, accent_col = _get_verdict_colors(verdict)

        status_text = "FLAGGED AS PHISHING / ATTACK" if verdict in ["Dangerous", "Suspicious"] else "VERIFIED AS LEGITIMATE"

        banner_text = (
            f"<font size=14><b>VERDICT: {verdict.upper()} ({status_text})</b></font><br/>"
            f"<font size=10><b>Composite Risk Score:</b> {risk_score}/100 &nbsp;|&nbsp; "
            f"<b>Phishing Probability:</b> {prob:.1f}% &nbsp;|&nbsp; "
            f"<b>Latency:</b> {scan_data.get('latency_ms', 0.5)}ms</font>"
        )
        banner_p = Paragraph(banner_text, ParagraphStyle("Banner", parent=normal_style, textColor=dark_col))
        banner_table = Table([[banner_p]], colWidths=[540])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), light_col),
            ('BOX', (0, 0), (-1, -1), 1.5, accent_col),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.append(banner_table)
        elements.append(Spacer(1, 10))

        # --- Email Metadata Table ---
        elements.append(Paragraph("Email Metadata", section_style))
        subject = scan_data.get("subject", "(No Subject)")
        sender = scan_data.get("sender", "(Unknown Sender)")

        meta_data = [
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(subject), body_style)],
            [Paragraph("<b>From:</b>", body_style), Paragraph(str(sender), body_style)],
            [Paragraph("<b>Model Architecture:</b>", body_style), Paragraph(str(scan_data.get("model_name", "Ensemble")), body_style)],
            [Paragraph("<b>Assessment Summary:</b>", body_style), Paragraph(str(scan_data.get("verdict_description", "Analysis completed.")), body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[130, 410])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # --- Brand Impersonation & Security Flags ---
        brand_info = scan_data.get("brand_impersonation") or {}
        if brand_info.get("is_impersonation_detected"):
            brand_p = Paragraph(
                f"<b>[HIGH SEVERITY] BRAND IMPERSONATION DETECTED:</b> {brand_info.get('warning', '')}<br/>"
                f"Target Brand: <b>{brand_info.get('brand', '').upper()}</b> | Sender: {sender}",
                ParagraphStyle("BrandAlert", parent=body_style, textColor=colors.HexColor("#991b1b"))
            )
            brand_table = Table([[brand_p]], colWidths=[540])
            brand_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fee2e2")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#ef4444")),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(brand_table)
            elements.append(Spacer(1, 8))

        # --- Key Security Findings ---
        elements.append(Paragraph("Key Forensic Findings & Indicators", section_style))
        reasons = scan_data.get("key_reasons") or ["No critical threat indicators detected."]
        reasons_data = []
        for r in reasons:
            reasons_data.append([
                Paragraph("<font color='#0284c7'>&#9679;</font>", normal_style),
                Paragraph(r, body_style)
            ])
        reasons_table = Table(reasons_data, colWidths=[15, 525])
        reasons_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(reasons_table)
        elements.append(Spacer(1, 10))

        # --- Psychological Tactics Radar Breakdown ---
        tactics = scan_data.get("tactics") or {}
        scores = tactics.get("scores") or {}
        elements.append(Paragraph("Social Engineering Tactic Breakdown (0 - 100)", section_style))
        tactic_headers = ["Urgency", "Fear / Threat", "Authority", "Reward Bait", "Credentials"]
        tactic_vals = [
            f"{scores.get('urgency', 0)}",
            f"{scores.get('fear', 0)}",
            f"{scores.get('authority', 0)}",
            f"{scores.get('reward', 0)}",
            f"{scores.get('credentials', 0)}"
        ]
        tactic_data = [
            [Paragraph(f"<b>{h}</b>", body_style) for h in tactic_headers],
            [Paragraph(v, body_style) for v in tactic_vals]
        ]
        tactic_table = Table(tactic_data, colWidths=[108]*5)
        tactic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(tactic_table)
        elements.append(Spacer(1, 10))

        # --- Detected URLs Table ---
        urls = scan_data.get("urls_detected") or []
        if urls:
            elements.append(Paragraph(f"Detected Embedded Links ({len(urls)}) - Defanged", section_style))
            url_rows = [[
                Paragraph("<b>Defanged URL</b>", body_style),
                Paragraph("<b>Verdict</b>", body_style),
                Paragraph("<b>Risk</b>", body_style),
                Paragraph("<b>Heuristics</b>", body_style)
            ]]
            for u in urls[:6]:
                heuristics = []
                if u.get("is_ip_host"): heuristics.append("IP Host")
                if u.get("is_shortener"): heuristics.append("Shortener")
                if u.get("is_punycode"): heuristics.append("Punycode")
                if u.get("typosquat", {}).get("is_typosquat"):
                    heuristics.append(f"Typosquat vs {u['typosquat'].get('target_brand', '')}")
                heuristics_str = ", ".join(heuristics) or "Clean"

                url_rows.append([
                    Paragraph(u.get("defanged_url", ""), body_style),
                    Paragraph(u.get("verdict", "Safe"), body_style),
                    Paragraph(str(u.get("url_risk_score", 0)), body_style),
                    Paragraph(heuristics_str, body_style)
                ])

            url_table = Table(url_rows, colWidths=[240, 70, 45, 185])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(url_table)
            elements.append(Spacer(1, 10))

        # --- Remediation / Recommendation ---
        elements.append(Paragraph("Security Remediation & Action Guidance", section_style))
        if verdict in ["Dangerous", "Suspicious"]:
            recom_text = (
                "<b>1. Quarantine Message:</b> Block sender at mail gateway and purge email from mailboxes.<br/>"
                "<b>2. Defang & Blacklist:</b> Blacklist the detected destination IPs and typosquat domains on firewall/DNS filters.<br/>"
                "<b>3. User Alert:</b> Advise recipients not to open attachments or input credentials on external web portals.<br/>"
                "<b>4. Credential Revocation:</b> If any employee accessed links, trigger immediate password reset and MFA audit."
            )
        else:
            recom_text = (
                "<b>1. Standard Delivery:</b> Email exhibits standard cryptographic and linguistic markers of benign traffic.<br/>"
                "<b>2. Continuous Monitoring:</b> Maintain standard zero-trust email monitoring."
            )
        recom_table = Table([[Paragraph(recom_text, body_style)]], colWidths=[540])
        recom_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(recom_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    @staticmethod
    def generate_batch_report(batch_data: Dict[str, Any]) -> bytes:
        """
        Generate a multi-page comprehensive Batch Dataset Audit Dossier
        covering all analyzed emails with executive statistics and individual reports.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]
        normal_style.fontSize = 9
        normal_style.leading = 12

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold"
        )
        section_style = ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=8,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            "BodySmall",
            parent=normal_style,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # --- Dossier Header ---
        elements.append(Paragraph("<b>MAILGUARD DEFENSE</b> | Batch Dataset Threat Audit Dossier", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Multi-Layer Phishing Classification Platform", normal_style))
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # --- Executive Summary Metrics ---
        total = batch_data.get("total_scanned", 0)
        dangerous = batch_data.get("dangerous_count", 0)
        suspicious = batch_data.get("suspicious_count", 0)
        safe = batch_data.get("safe_count", 0)
        phish_total = dangerous + suspicious
        phish_ratio = (phish_total / total * 100) if total > 0 else 0

        summary_box = [
            [
                Paragraph(f"<b>Total Emails Scanned</b><br/><font size=14 color='#0f172a'><b>{total}</b></font>", body_style),
                Paragraph(f"<b>Flagged Phishing (Total)</b><br/><font size=14 color='#be123c'><b>{phish_total} ({phish_ratio:.1f}%)</b></font>", body_style),
                Paragraph(f"<b>Dangerous (High Severity)</b><br/><font size=14 color='#e11d48'><b>{dangerous}</b></font>", body_style),
                Paragraph(f"<b>Suspicious</b><br/><font size=14 color='#d97706'><b>{suspicious}</b></font>", body_style),
                Paragraph(f"<b>Verified Legit (Safe)</b><br/><font size=14 color='#059669'><b>{safe}</b></font>", body_style),
            ]
        ]
        summary_table = Table(summary_box, colWidths=[108]*5)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # --- Dataset Overview Table ---
        elements.append(Paragraph("Dataset Triage Summary Table", section_style))
        results = batch_data.get("results", [])

        table_rows = [[
            Paragraph("<b>#</b>", body_style),
            Paragraph("<b>Subject</b>", body_style),
            Paragraph("<b>Sender</b>", body_style),
            Paragraph("<b>Verdict / Status</b>", body_style),
            Paragraph("<b>Risk</b>", body_style),
            Paragraph("<b>Primary Tactic</b>", body_style)
        ]]

        for idx, r in enumerate(results[:50]):
            verdict = r.get("verdict", "Safe")
            flag_status = "🚩 FLAGGED PHISH" if verdict in ["Dangerous", "Suspicious"] else "✅ LEGIT"
            dark_c, light_c, _ = _get_verdict_colors(verdict)
            table_rows.append([
                Paragraph(str(idx + 1), body_style),
                Paragraph(r.get("subject", "(No Subject)")[:40], body_style),
                Paragraph(r.get("sender", "(Unknown)")[:35], body_style),
                Paragraph(f"<b>{flag_status}</b> ({verdict})", ParagraphStyle("RVerd", parent=body_style, textColor=dark_c)),
                Paragraph(str(r.get("risk_score", 0)), body_style),
                Paragraph(r.get("primary_tactic", "None"), body_style),
            ])

        triage_table = Table(table_rows, colWidths=[20, 150, 140, 120, 35, 75])
        triage_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(triage_table)

        # --- Individual Email Details Section ---
        elements.append(Spacer(1, 14))
        elements.append(Paragraph("Detailed Forensics for Analyzed Emails", section_style))

        for idx, r in enumerate(results[:30]):
            verdict = r.get("verdict", "Safe")
            dark_c, light_c, accent_c = _get_verdict_colors(verdict)
            flag_label = "FLAGGED PHISHING" if verdict in ["Dangerous", "Suspicious"] else "VERIFIED LEGITIMATE"

            email_p = Paragraph(
                f"<b>Email #{idx+1}: {r.get('subject', '(No Subject)')}</b><br/>"
                f"<b>Sender:</b> {r.get('sender', '(Unknown)')} | "
                f"<b>Status:</b> {flag_label} ({verdict}) | "
                f"<b>Risk Score:</b> {r.get('risk_score', 0)}/100 | "
                f"<b>Primary Tactic:</b> {r.get('primary_tactic', 'None')}",
                ParagraphStyle(f"EmailItem_{idx}", parent=body_style, textColor=colors.HexColor("#0f172a"))
            )

            email_card = Table([[email_p]], colWidths=[540])
            email_card.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), light_c),
                ('BOX', (0, 0), (-1, -1), 1, accent_c),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(KeepTogether([email_card, Spacer(1, 6)]))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
