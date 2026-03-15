"""Generate the one-page market analysis PDF for the assignment."""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

# ── Color palette ────────────────────────────────────────────────────────
DARK = colors.HexColor("#0a0c0f")
ACCENT = colors.HexColor("#00d4ff")
ACCENT_DARK = colors.HexColor("#0099bb")
SURFACE = colors.HexColor("#1a2130")
BORDER = colors.HexColor("#243040")
TEXT = colors.HexColor("#e2eaf4")
TEXT2 = colors.HexColor("#8da0b8")
AMBER = colors.HexColor("#ffaa00")
GREEN = colors.HexColor("#00c87a")
RED_LIGHT = colors.HexColor("#ff6464")

OUTPUT = "/Users/goutam/Learning/MCPLearning/threat-intel-mcp/soc_copilot_market_analysis.pdf"

def make_pdf():
    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=letter,
        leftMargin=0.6*inch,
        rightMargin=0.6*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    s_title = ParagraphStyle("title",
        fontName="Helvetica-Bold", fontSize=22, textColor=DARK,
        spaceAfter=2, leading=26)
    s_subtitle = ParagraphStyle("subtitle",
        fontName="Helvetica", fontSize=11, textColor=ACCENT_DARK,
        spaceAfter=8, leading=14)
    s_section = ParagraphStyle("section",
        fontName="Helvetica-Bold", fontSize=9, textColor=ACCENT_DARK,
        spaceBefore=10, spaceAfter=4, leading=12,
        borderPad=0, textTransform="uppercase", letterSpacing=1.2)
    s_body = ParagraphStyle("body",
        fontName="Helvetica", fontSize=9.5, textColor=DARK,
        leading=14, spaceAfter=4, alignment=TA_JUSTIFY)
    s_bullet = ParagraphStyle("bullet",
        fontName="Helvetica", fontSize=9, textColor=DARK,
        leading=13, leftIndent=14, spaceAfter=2)
    s_small = ParagraphStyle("small",
        fontName="Helvetica", fontSize=8, textColor=TEXT2,
        leading=11, spaceAfter=2)
    s_label = ParagraphStyle("label",
        fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
        leading=10, alignment=TA_CENTER)
    s_value = ParagraphStyle("value",
        fontName="Helvetica-Bold", fontSize=18, textColor=DARK,
        leading=20, alignment=TA_CENTER)
    s_metric_label = ParagraphStyle("metric_label",
        fontName="Helvetica", fontSize=8, textColor=TEXT2,
        leading=10, alignment=TA_CENTER)

    story = []

    # ── Header bar ───────────────────────────────────────────────────────
    header_data = [[
        Paragraph("SOC COPILOT MCP", ParagraphStyle("h",
            fontName="Helvetica-Bold", fontSize=18, textColor=colors.white,
            leading=22)),
        Paragraph("AI-Native Security Investigation Assistant", ParagraphStyle("hs",
            fontName="Helvetica", fontSize=10, textColor=ACCENT,
            leading=14, alignment=2)),
    ]]
    header_table = Table(header_data, colWidths=[3.5*inch, 3.8*inch])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (0,0), 14),
        ("RIGHTPADDING", (-1,0), (-1,0), 14),
        ("TOPPADDING", (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))

    # ── Metrics row ──────────────────────────────────────────────────────
    metrics = [
        ("$214B", "Global Cybersecurity Market"),
        ("$28B", "Threat Intel Segment"),
        ("3.4M", "SOC Analyst Shortage"),
        ("2 hrs", "Avg. Manual IOC Investigation"),
    ]
    cell_style = [
        ("BACKGROUND", (0,0), (-1,-1), SURFACE),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("LINEAFTER", (0,0), (2,0), 0.5, BORDER),
    ]
    metrics_data = [[
        [Paragraph(v, s_value), Paragraph(l, s_metric_label)]
        for v, l in metrics
    ]]
    metrics_cells = [[
        Table([[Paragraph(v, s_value)], [Paragraph(l, s_metric_label)]],
              colWidths=[1.7*inch])
        for v, l in metrics
    ]]
    metrics_table = Table(metrics_cells, colWidths=[1.77*inch]*4)
    metrics_table.setStyle(TableStyle(cell_style + [
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("BOX", (0,0), (-1,-1), 0.5, BORDER),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 10))

    # ── Two-column layout ─────────────────────────────────────────────────
    col_w = 3.55 * inch

    def section(title):
        return [Paragraph(title, s_section), HRFlowable(width="100%", thickness=0.5, color=BORDER)]

    # Left column
    left = []
    left += section("What Problem Does It Solve?")
    left.append(Paragraph(
        "Security Operations Center (SOC) analysts spend 2–4 hours per incident manually "
        "correlating threat data across VirusTotal, Shodan, AbuseIPDB, MITRE ATT&CK, and "
        "NVD. This is repetitive, error-prone, and expensive — at $80–120K/analyst/year. "
        "SOC Copilot reduces a full IOC investigation to a single natural-language prompt, "
        "delivering correlated verdicts, MITRE technique mappings, YARA rules, and a "
        "management-ready IR report in seconds.", s_body))

    left += section("Target Market")
    for item in [
        "Enterprise SOC teams (Fortune 500, financial, healthcare, government)",
        "Managed Security Service Providers (MSSPs) — highest value, serve many clients",
        "Threat intelligence analysts and incident responders",
        "Red teams and penetration testers (CVE exploitability, domain hunting)",
        "SMBs with limited security staff who need enterprise-grade intelligence",
    ]:
        left.append(Paragraph(f"• {item}", s_bullet))

    left += section("Why MCP Is the Right Architecture")
    left.append(Paragraph(
        "MCP is purpose-built for this use case. It gives LLM structured, typed access "
        "to external APIs without prompt-injection risk. Tool definitions enforce input "
        "validation (correct IP format, valid hash length). The agentic loop lets LLM "
        "autonomously chain tools — e.g., run correlate_ioc, then generate_yara_rule, then "
        "draft_ir_report — in a single investigation without user intervention.", s_body))
    left.append(Paragraph(
        "Alternative architectures (RAG, fine-tuning) would require retraining as APIs "
        "change. MCP is pluggable, versioned, and swappable — add a new intel source in "
        "one file, no model retraining needed.", s_body))

    # Right column
    right = []
    right += section("Value Proposition")
    vp_data = [
        ["Without SOC Copilot", "With SOC Copilot"],
        ["2–4 hrs per investigation", "< 60 seconds"],
        ["5–7 browser tabs open", "1 chat interface"],
        ["Manual MITRE mapping", "Automatic + verified"],
        ["YARA rules: senior skill", "Generated from hash"],
        ["IR report: 45 min writing", "Draft in 1 prompt"],
    ]
    vp_table = Table(vp_data, colWidths=[1.68*inch, 1.75*inch])
    vp_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT_DARK),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("BACKGROUND", (0,1), (0,-1), colors.HexColor("#fff0f0")),
        ("BACKGROUND", (1,1), (1,-1), colors.HexColor("#f0fff8")),
        ("FONTNAME", (0,1), (-1,-1), "Helvetica"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("GRID", (0,0), (-1,-1), 0.5, BORDER),
    ]))
    right.append(vp_table)
    right.append(Spacer(1, 8))

    right += section("Who Pays and Why?")
    right.append(Paragraph(
        "<b>Primary buyer: MSSP firms.</b> They serve dozens of enterprise clients — "
        "a tool that cuts analyst time by 80% lets them handle 5× the client load "
        "with the same headcount. At $400/seat/month, a 20-analyst MSSP saves "
        "$160K/year in labor while growing revenue.", s_body))
    right.append(Paragraph(
        "<b>Secondary buyer: Enterprise CISO.</b> A 10-analyst SOC saving 2hrs/day = "
        "20 analyst-hours recaptured daily. At $50/hr fully-loaded cost, "
        "that is $1,000/day in recovered productivity. ROI positive in week one.", s_body))

    right += section("Industry Disruption Potential")
    right.append(Paragraph(
        "Tier-1 SOC analyst roles ($50–70K/year, highly repetitive) are the most "
        "directly automatable by this system. Gartner estimates 40% of Tier-1 "
        "alert triage will be AI-handled by 2026.", s_body))
    right.append(Paragraph(
        "The broader disruption extends to the $4B threat intelligence platform market "
        "(Recorded Future, Mandiant, CrowdStrike Falcon). These platforms sell static "
        "dashboards; SOC Copilot provides an interactive, reasoning agent that can "
        "explain, correlate, and act — not just display data.", s_body))

    # Combine into two-column table
    two_col = Table(
        [[left, right]],
        colWidths=[col_w, col_w],
    )
    two_col.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (0,-1), 0),
        ("RIGHTPADDING", (0,0), (0,-1), 16),
        ("LEFTPADDING", (1,0), (1,-1), 16),
        ("RIGHTPADDING", (1,0), (1,-1), 0),
        ("LINEAFTER", (0,0), (0,-1), 0.5, BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(two_col)
    story.append(Spacer(1, 10))

    # ── Footer ───────────────────────────────────────────────────────────
    footer_data = [[
        Paragraph(
            "15 MCP tools  ·  VirusTotal + AbuseIPDB + Shodan + NVD  ·  "
            "MITRE ATT&CK mapping  ·  YARA generation  ·  IR report drafting  ·  "
            "Lookalike domain hunting  ·  Full investigation orchestration",
            ParagraphStyle("ft", fontName="Helvetica", fontSize=7.5,
                           textColor=ACCENT, leading=10, alignment=TA_CENTER)),
    ]]
    footer_table = Table(footer_data, colWidths=[7.3*inch])
    footer_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    story.append(footer_table)

    doc.build(story)
    print(f"PDF saved to {OUTPUT}")

if __name__ == "__main__":
    make_pdf()
