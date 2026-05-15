"""
SENTINEL AI — PDF Report Generator
Professional security assessment report using reportlab.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# Ensure reports directory exists
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Color palette
BRAND_DARK = colors.HexColor("#0f172a")
BRAND_PRIMARY = colors.HexColor("#3b82f6")
BRAND_SUCCESS = colors.HexColor("#22c55e")
BRAND_WARNING = colors.HexColor("#f59e0b")
BRAND_DANGER = colors.HexColor("#ef4444")
BRAND_ORANGE = colors.HexColor("#f97316")
BRAND_GRAY = colors.HexColor("#64748b")
BRAND_LIGHT = colors.HexColor("#f8fafc")

SEVERITY_COLORS = {
    "critical": BRAND_DANGER,
    "high": BRAND_ORANGE,
    "medium": BRAND_WARNING,
    "low": BRAND_PRIMARY,
    "info": BRAND_GRAY,
}

GRADE_COLORS = {
    "Secure": BRAND_SUCCESS,
    "Medium Risk": BRAND_WARNING,
    "High Risk": BRAND_ORANGE,
    "Critical Risk": BRAND_DANGER,
}


def _get_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=36, leading=42, textColor=BRAND_DARK, alignment=TA_CENTER, spaceAfter=20, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=18, textColor=BRAND_GRAY, alignment=TA_CENTER, spaceAfter=40
    ))
    styles.add(ParagraphStyle(
        "ScoreBig", parent=styles["Normal"],
        fontSize=48, leading=56, textColor=BRAND_DARK, alignment=TA_CENTER, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        "GradeBig", parent=styles["Normal"],
        fontSize=20, leading=24, textColor=BRAND_DARK, alignment=TA_CENTER, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        "SectionHead", parent=styles["Heading1"],
        fontSize=20, textColor=BRAND_DARK, spaceBefore=20, spaceAfter=10, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        "SubHead", parent=styles["Heading2"],
        fontSize=14, textColor=BRAND_PRIMARY, spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontSize=11, textColor=BRAND_DARK, spaceAfter=6, leading=16
    ))
    styles.add(ParagraphStyle(
        "SmallGray", parent=styles["Normal"],
        fontSize=9, textColor=BRAND_GRAY, leading=12
    ))
    styles.add(ParagraphStyle(
        "MetaLabel", parent=styles["Normal"],
        fontSize=11, textColor=BRAND_GRAY, fontName="Helvetica-Bold", alignment=TA_RIGHT
    ))
    styles.add(ParagraphStyle(
        "MetaValue", parent=styles["Normal"],
        fontSize=11, textColor=BRAND_DARK, alignment=TA_LEFT
    ))
    return styles


def generate_report(
    scan_data: dict,
    findings: List[dict],
    score_data: dict,
    attack_paths: List[dict] = None,
    comparison_data: Dict = None,
) -> str:
    """
    Generate a professional PDF security report.
    """
    report_id = str(uuid.uuid4())[:8]
    filename = f"sentinel_report_{report_id}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        topMargin=25*mm, bottomMargin=25*mm,
        leftMargin=20*mm, rightMargin=20*mm,
    )

    styles = _get_styles()
    elements = []

    # ── Cover Page ──────────────────────────────
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("SENTINEL AI", styles["CoverTitle"]))
    elements.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 30))

    # Score display
    score = score_data.get("score", 0)
    grade = score_data.get("grade", "Unknown")
    grade_color = GRADE_COLORS.get(grade, BRAND_GRAY)

    score_block = Table(
        [
            [Paragraph(f"<font color='{grade_color.hexval()}'>{score}</font><font size='16' color='{BRAND_GRAY.hexval()}'> /100</font>", styles["ScoreBig"])],
            [Paragraph(f"<font color='{grade_color.hexval()}'>{grade.upper()}</font>", styles["GradeBig"])]
        ],
        colWidths=[240], rowHeights=[70, 40]
    )
    score_block.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 2, grade_color),
        ("BACKGROUND", (0, 0), (-1, -1), BRAND_LIGHT),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 10),
    ]))
    
    centered_score_table = Table([[score_block]], colWidths=[240])
    centered_score_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    
    elements.append(centered_score_table)
    elements.append(Spacer(1, 40))

    # Meta info
    target = scan_data.get("target_raw", "Unknown")
    scan_type = scan_data.get("input_type", scan_data.get("scan_type", "Unknown")).upper()
    scan_date = scan_data.get("completed_at", datetime.now(timezone.utc).isoformat())
    tools = scan_data.get("tools_used", [])
    if isinstance(tools, str): tools = [tools]

    meta_data = [
        [Paragraph("TARGET", styles["MetaLabel"]), Paragraph(str(target), styles["MetaValue"])],
        [Paragraph("SCAN TYPE", styles["MetaLabel"]), Paragraph(str(scan_type), styles["MetaValue"])],
        [Paragraph("DATE", styles["MetaLabel"]), Paragraph(str(scan_date)[:19].replace("T", " ") + " UTC", styles["MetaValue"])],
        [Paragraph("TOOLS", styles["MetaLabel"]), Paragraph(", ".join(tools), styles["MetaValue"])],
        [Paragraph("FINDINGS", styles["MetaLabel"]), Paragraph(str(len(findings)), styles["MetaValue"])],
    ]
    meta_table = Table(meta_data, colWidths=[150, 250])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0,0), (-1,-1), "CENTER")
    ]))
    
    centered_meta_table = Table([[meta_table]], colWidths=[400])
    centered_meta_table.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
    
    elements.append(centered_meta_table)
    elements.append(PageBreak())

    # ── Executive Summary ────────────────────────
    elements.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

    summary = score_data.get("findings_summary", {})
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = summary.get("total", len(findings))

    exec_text = (
        f"A comprehensive security assessment was performed against <b>{target}</b>. "
        f"The assessment identified <b>{total}</b> findings across multiple categories. "
        f"The overall security score is <b>{score}/100</b>, classified as <b>{grade}</b>. "
    )
    elements.append(Paragraph(exec_text, styles["BodyText2"]))
    
    risk_text = ""
    if crit > 0:
        risk_text += f"<font color='{BRAND_DANGER.hexval()}'><b>{crit} critical</b></font> vulnerabilities require immediate attention.<br/>"
    if high > 0:
        risk_text += f"<font color='{BRAND_ORANGE.hexval()}'><b>{high} high</b></font> severity issues were detected.<br/>"
    
    if score >= 81:
        risk_text += "The target demonstrates strong security posture with minor improvements recommended."
    elif score >= 61:
        risk_text += "The target has moderate risk exposure. Address high-severity findings promptly."
    elif score >= 41:
        risk_text += "Significant security gaps exist. Prioritize remediation of critical and high findings."
    else:
        risk_text += "The target is at critical risk. Immediate remediation action is required."

    elements.append(Paragraph(risk_text, styles["BodyText2"]))
    elements.append(Spacer(1, 25))

    # ── Findings Summary Table ────────────────────
    elements.append(Paragraph("2. Findings Summary", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

    summary_data = [
        [Paragraph("<b>Severity Level</b>", styles["BodyText2"]),
         Paragraph("<b>Count</b>", styles["BodyText2"]),
         Paragraph("<b>Score Impact</b>", styles["BodyText2"])]
    ]
    
    if crit > 0: summary_data.append([Paragraph(f"<font color='{BRAND_DANGER.hexval()}'><b>Critical</b></font>", styles["BodyText2"]), str(crit), f"-{crit * 25}"])
    if high > 0: summary_data.append([Paragraph(f"<font color='{BRAND_ORANGE.hexval()}'><b>High</b></font>", styles["BodyText2"]), str(high), f"-{high * 10}"])
    if med > 0:  summary_data.append([Paragraph(f"<font color='{BRAND_WARNING.hexval()}'><b>Medium</b></font>", styles["BodyText2"]), str(med), f"-{med * 5}"])
    if low > 0:  summary_data.append([Paragraph(f"<font color='{BRAND_PRIMARY.hexval()}'><b>Low</b></font>", styles["BodyText2"]), str(low), f"-{low * 1}"])
    
    if len(summary_data) == 1:
        summary_data.append(["No vulnerabilities found", "0", "0"])

    sum_table = Table(summary_data, colWidths=[200, 100, 150])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_LIGHT),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    
    centered_sum_table = Table([[sum_table]], colWidths=[450])
    centered_sum_table.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
    
    elements.append(centered_sum_table)
    elements.append(Spacer(1, 25))

    # ── Key Findings (Top 10) ────────────────────
    elements.append(Paragraph("3. Key Findings", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info").lower(), 5))

    if not sorted_findings:
        elements.append(Paragraph("No vulnerabilities were identified during this assessment.", styles["BodyText2"]))
    else:
        for i, f in enumerate(sorted_findings[:10]):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown Finding")
            desc = f.get("description", "")[:300]
            component = f.get("affected_component", "")
            remediation = f.get("remediation", "Apply vendor patch.")
            tool = f.get("tool_name", "")
            cve = f.get("cve_id", "")

            sev_color = SEVERITY_COLORS.get(f.get("severity", "info").lower(), BRAND_GRAY)

            block = []
            block.append(Paragraph(
                f"<font color='{sev_color.hexval()}'><b>[{sev}]</b></font> {title}",
                styles["SubHead"]
            ))
            
            meta_str = ""
            if component: meta_str += f"<b>Component:</b> {component} &nbsp; "
            if tool: meta_str += f"<b>Tool:</b> {tool} &nbsp; "
            if cve: meta_str += f"<b>CVE:</b> {cve}"
            
            if meta_str:
                block.append(Paragraph(meta_str, styles["SmallGray"]))
                block.append(Spacer(1, 4))
                
            block.append(Paragraph(f"<b>Description:</b> {desc}", styles["BodyText2"]))
            block.append(Paragraph(f"<b>Remediation:</b> {remediation}", styles["BodyText2"]))
            
            finding_table = Table([[block]], colWidths=[480])
            finding_table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, BRAND_GRAY),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fafafa")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 15),
                ("RIGHTPADDING", (0, 0), (-1, -1), 15),
            ]))
            
            elements.append(KeepTogether([finding_table, Spacer(1, 15)]))

        if len(sorted_findings) > 10:
            elements.append(Paragraph(
                f"<i>... and {len(sorted_findings) - 10} more findings. See the full list below.</i>",
                styles["SmallGray"]
            ))

    elements.append(PageBreak())

    # ── Attack Paths ────────────────────────────
    if attack_paths:
        elements.append(Paragraph("4. Attack Paths", styles["SectionHead"]))
        elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

        for path in attack_paths[:5]:
            path_name = path.get("name", "Unknown Path")
            steps = path.get("chain_steps", [])
            impact = path.get("final_impact", "")

            elements.append(Paragraph(f"<b>{path_name}</b>", styles["SubHead"]))
            chain_text = " -> ".join(steps) if isinstance(steps, list) else str(steps)
            elements.append(Paragraph(f"Chain: {chain_text}", styles["BodyText2"]))
            if impact:
                elements.append(Paragraph(f"<b>Impact:</b> {impact}", styles["BodyText2"]))
            elements.append(Spacer(1, 8))

        elements.append(PageBreak())

    # ── Full Vulnerability List ─────────────────
    elements.append(Paragraph("5. Complete Vulnerability List", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

    if not sorted_findings:
        elements.append(Paragraph("No vulnerabilities to display.", styles["BodyText2"]))
    else:
        vuln_header = [
            Paragraph("<b>#</b>", styles["BodyText2"]),
            Paragraph("<b>Severity</b>", styles["BodyText2"]),
            Paragraph("<b>Title</b>", styles["BodyText2"]),
            Paragraph("<b>Component</b>", styles["BodyText2"])
        ]
        vuln_rows = [vuln_header]
        for i, f in enumerate(sorted_findings):
            sev = f.get("severity", "info").upper()
            sev_color = SEVERITY_COLORS.get(f.get("severity", "info").lower(), BRAND_GRAY)
            vuln_rows.append([
                str(i + 1),
                Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev}</b></font>", styles["BodyText2"]),
                Paragraph(f.get("title", "")[:80], styles["SmallGray"]),
                Paragraph(f.get("affected_component", "")[:40] or "-", styles["SmallGray"]),
            ])

        vtable = Table(vuln_rows, colWidths=[30, 80, 220, 150])
        vtable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_LIGHT),
            ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(vtable)

    elements.append(Spacer(1, 30))

    # -- Before vs After Comparison (if available) --
    if comparison_data:
        elements.append(PageBreak())
        elements.append(Paragraph("6. Before vs After Comparison", styles["SectionHead"]))
        elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

        sc_before = comparison_data.get("score_before", 0)
        sc_after = comparison_data.get("score_after", 0)
        delta = comparison_data.get("score_delta", 0)
        trend = "Improved" if delta > 0 else ("Degraded" if delta < 0 else "Unchanged")
        trend_color = BRAND_SUCCESS if delta > 0 else (BRAND_DANGER if delta < 0 else BRAND_GRAY)

        comp_table = Table(
            [
                [Paragraph("<b>Metric</b>", styles["BodyText2"]),
                 Paragraph("<b>Before</b>", styles["BodyText2"]),
                 Paragraph("<b>After</b>", styles["BodyText2"]),
                 Paragraph("<b>Change</b>", styles["BodyText2"])],
                ["Security Score", f"{sc_before}", f"{sc_after}", f"{'+' if delta > 0 else ''}{delta:.0f}"],
                ["New Findings", "-", str(comparison_data.get("new_count", 0)), ""],
                ["Resolved", str(comparison_data.get("resolved_count", 0)), "-", ""],
                ["Persistent", str(comparison_data.get("persistent_count", 0)), str(comparison_data.get("persistent_count", 0)), "No change"],
            ],
            colWidths=[130, 100, 100, 100],
        )
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_LIGHT, colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(comp_table)
        elements.append(Spacer(1, 10))

        summary_text = comparison_data.get("summary", "")
        elements.append(Paragraph(f"<b>Trend:</b> <font color='{trend_color.hexval()}'>{trend}</font> | {summary_text}", styles["BodyText2"]))


    # ── Compliance Mapping ────────────────────────────────────────
    try:
        from backend.services.compliance.mapper import map_findings_to_compliance
        compliance = map_findings_to_compliance(findings)

        elements.append(PageBreak())
        section_num = 7 if comparison_data else 6
        elements.append(Paragraph(f"{section_num}. Compliance Mapping", styles["SectionHead"]))
        elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_PRIMARY, spaceAfter=15))

        comp_summary = compliance.get("summary", {})
        comp_score = comp_summary.get("compliance_score", 100)
        comp_status = comp_summary.get("overall_status", "compliant").upper()

        elements.append(Paragraph(
            f"Overall compliance score: <b>{comp_score}%</b> — Status: <b>{comp_status}</b>",
            styles["BodyText2"]
        ))
        elements.append(Spacer(1, 10))

        frameworks = [
            ("OWASP Top 10", "owasp_top_10", comp_summary.get("owasp_violations", 0), comp_summary.get("owasp_total", 10)),
            ("PCI-DSS v4.0", "pci_dss", comp_summary.get("pci_violations", 0), comp_summary.get("pci_total", 11)),
            ("ISO 27001:2022", "iso_27001", comp_summary.get("iso_gaps", 0), comp_summary.get("iso_total", 11)),
            ("NIST CSF 2.0", "nist_csf", comp_summary.get("nist_gaps", 0), comp_summary.get("nist_total", 8)),
        ]

        fw_header = [
            Paragraph("<b>Framework</b>", styles["SmallGray"]),
            Paragraph("<b>Controls</b>", styles["SmallGray"]),
            Paragraph("<b>Violations</b>", styles["SmallGray"]),
            Paragraph("<b>Pass Rate</b>", styles["SmallGray"]),
            Paragraph("<b>Status</b>", styles["SmallGray"]),
        ]
        fw_rows = [fw_header]
        for fw_name, fw_key, violations, total in frameworks:
            pass_rate = f"{((total - violations) / total * 100):.0f}%" if total else "N/A"
            status_text = "PASS" if violations == 0 else "FAIL"
            fw_rows.append([fw_name, str(total), str(violations), pass_rate, status_text])

        fw_table = Table(fw_rows, colWidths=[140, 70, 80, 80, 80])
        fw_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.3, BRAND_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_LIGHT, colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(fw_table)
        elements.append(Spacer(1, 12))

        # Add detailed OWASP findings
        owasp = compliance.get("owasp_top_10", {})
        failed_owasp = {k: v for k, v in owasp.items() if v.get("status") == "fail"}
        if failed_owasp:
            elements.append(Paragraph(f"<b>OWASP Top 10 Violations ({len(failed_owasp)}):</b>", styles["SubHead"]))
            for code, info in failed_owasp.items():
                sev_color = SEVERITY_COLORS.get(info.get("max_severity", "info").lower(), BRAND_GRAY)
                elements.append(Paragraph(
                    f"<font color='{sev_color.hexval()}'>[{info['max_severity'].upper()}]</font> "
                    f"<b>{code}</b> — {info['name']} ({info['count']} finding{'s' if info['count'] > 1 else ''})",
                    styles["BodyText2"]
                ))
            elements.append(Spacer(1, 8))

    except Exception:
        pass  # Graceful degradation — compliance section is optional

    # -- Footer --
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GRAY))

    try:
        from backend.common.config import settings as _settings
        _version = _settings.APP_VERSION
    except Exception:
        _version = "5.0.0"

    elements.append(Paragraph(
        f"Generated by Sentinel AI v{_version} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["SmallGray"]
    ))

    # Build PDF
    doc.build(elements)
    return filepath
