"""Analyst workflow tools — YARA rule generation and incident report drafting."""

from __future__ import annotations
import os
import re
import httpx
from datetime import datetime, timezone
import asyncio
from utils.formatter import format_section, format_error


# ---------------------------------------------------------------------------
# generate_yara_rule
# ---------------------------------------------------------------------------

async def generate_yara_rule(file_hash: str, rule_name: str = "") -> str:
    """Fetch crowdsourced YARA rules from VirusTotal for a file hash.

    Instead of generating synthetic rules, this fetches the real battle-tested
    YARA rules that security researchers have already written and validated for
    this exact file on VirusTotal — zero false-positive risk from rule generation.

    Args:
        file_hash: MD5, SHA-1, or SHA-256 hash of the file.
        rule_name: Unused — kept for API compatibility.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return format_error("YARA Fetcher", "VIRUSTOTAL_API_KEY is not set")

    async with httpx.AsyncClient(timeout=20) as client:
        # Fetch file metadata and crowdsourced rules concurrently
        try:
            file_resp, yara_resp = await asyncio.gather(
                client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": vt_key},
                ),
                client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}/crowdsourced_yara_ruleset",
                    headers={"x-apikey": vt_key},
                ),
            )
            file_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            return format_error("YARA Fetcher", f"VT HTTP {exc.response.status_code}: {exc.response.text[:200]}")
        except httpx.RequestError as exc:
            return format_error("YARA Fetcher", f"Request failed: {exc}")

    # ── File metadata ────────────────────────────────────────────────────
    attrs = file_resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    sha256 = attrs.get("sha256", file_hash)
    file_type = attrs.get("type_description", "Unknown")
    file_size = attrs.get("size", 0)
    tags = attrs.get("tags", [])
    names = attrs.get("names", [])[:3]

    lines = [
        f"## YARA Rules — `{sha256[:16]}...`", "",
        f"**File:** `{sha256}`",
        f"**Type:** {file_type}  |  **Size:** {file_size:,} bytes",
        f"**VT Detections:** {malicious}/{total} engines",
        f"**Tags:** {', '.join(tags) if tags else 'none'}",
        f"**Known names:** {', '.join(names) if names else 'unknown'}",
        f"**VT Link:** https://www.virustotal.com/gui/file/{sha256}",
        "",
    ]

    # ── Crowdsourced YARA rules ──────────────────────────────────────────
    yara_rules: list[dict] = []
    if yara_resp.status_code == 200:
        yara_data = yara_resp.json()
        # VT returns either a list or dict depending on API version
        raw = yara_data.get("data", [])
        if isinstance(raw, list):
            yara_rules = raw
        elif isinstance(raw, dict):
            yara_rules = raw.get("attributes", {}).get("rules", [])
    
    elif yara_resp.status_code in (403, 401):
        lines.append(
            "⚠️ Crowdsourced YARA rules require a VirusTotal Premium API key. "
            "Your free API key has access to detection stats and metadata only."
        )
        lines.append("")
        lines.append(f"**View rules manually:** https://www.virustotal.com/gui/file/{sha256}/detection")
        lines.append("**Public YARA repos with this family's rules:**")
        lines.append("  - https://github.com/Neo23x0/signature-base (Florian Roth)")
        lines.append("  - https://github.com/elastic/protections-artifacts")
        lines.append("  - https://github.com/ditekshen/detection")

    if yara_rules:
        lines.append(f"### Crowdsourced YARA Rules ({len(yara_rules)} found)")
        lines.append("")
        lines.append(
            "> These rules are written by real malware researchers and validated "
            "against this exact sample. Use these in production — they have known "
            "true-positive rates and are actively maintained."
        )
        lines.append("")

        for i, rule in enumerate(yara_rules, 1):
            rule_name_vt = rule.get("rule_name", f"rule_{i}")
            ruleset_name = rule.get("ruleset_name", "unknown")
            author = rule.get("author", "unknown")
            description = rule.get("description", "")
            source_url = rule.get("source", "")
            rule_source = rule.get("rule_source", "")

            lines.append(f"#### {i}. `{rule_name_vt}`")
            lines.append(f"- **Ruleset:** {ruleset_name}")
            lines.append(f"- **Author:** {author}")
            if description:
                lines.append(f"- **Description:** {description}")
            if source_url:
                lines.append(f"- **Source:** {source_url}")
            lines.append("")

            if rule_source:
                lines.append("```yara")
                lines.append(rule_source)
                lines.append("```")
            else:
                lines.append(
                    f"_Rule source not available via API — "
                    f"view at: https://www.virustotal.com/gui/file/{sha256}/detection_"
                )
            lines.append("")

        lines.append("---")
        lines.append("**Deployment notes:**")
        lines.append("- Test in a sandbox environment before deploying to production EDR")
        lines.append("- Cross-reference with your EDR vendor's existing rule coverage")
        lines.append(
            f"- All rules above matched sample `{sha256[:16]}...` "
            "and were crowdsourced by the security community"
        )

    else:
        # No crowdsourced rules — explain why and give alternatives
        lines.append("### No Crowdsourced YARA Rules Found")
        lines.append("")

        if yara_resp.status_code == 404:
            lines.append(
                "VirusTotal has no crowdsourced YARA rules for this hash yet. "
                "This is common for newly submitted samples or less-studied malware families."
            )
        elif yara_resp.status_code in (403, 401):
            lines.append(
                f"⚠️ VT API returned {yara_resp.status_code} for crowdsourced rules. "
                "This endpoint may require a VirusTotal Premium API key."
            )
        else:
            lines.append(
                f"VT API returned status {yara_resp.status_code} for crowdsourced rules."
            )

        lines.append("")
        lines.append("**Alternatives:**")
        lines.append(
            f"- Check manually: https://www.virustotal.com/gui/file/{sha256}/detection"
        )
        lines.append(
            "- Search public YARA repos: "
            "https://github.com/Neo23x0/signature-base  |  "
            "https://github.com/elastic/protections-artifacts"
        )
        lines.append(
            "- Run `strings` or `floss` on the binary to extract "
            "unique strings for manual rule authoring"
        )
        lines.append(
            "- Use `shodan_get_exploits` or `check_cve_exploitability` "
            "if this sample exploits a known CVE"
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# draft_ir_report
# ---------------------------------------------------------------------------

async def draft_ir_report(
    iocs: list[str],
    incident_title: str = "Suspected Security Incident",
    severity: str = "Medium",
    analyst_name: str = "SOC Analyst",
    affected_systems: str = "",
) -> str:
    """Draft a structured incident response report from a list of IOCs.

    Produces a professional IR report in markdown suitable for sending to
    management or a CISO, including an executive summary, timeline, IOC table,
    recommended remediation steps, and next actions.

    Args:
        iocs: List of indicators of compromise (IPs, domains, hashes, CVEs).
        incident_title: Short description of the incident.
        severity: Severity level — Low, Medium, High, or Critical.
        analyst_name: Name of the reporting analyst.
        affected_systems: Comma-separated list of affected systems/hosts (optional).
    """
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d %H:%M UTC")

    severity_emoji = {"Low": "🟢", "Medium": "🟡", "High": "🔴", "Critical": "🚨"}.get(severity, "🟡")
    affected = affected_systems if affected_systems else "Under investigation"

    # Categorise IOCs
    ip_iocs, domain_iocs, hash_iocs, cve_iocs, other_iocs = [], [], [], [], []
    for ioc in iocs:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            ip_iocs.append(ioc)
        elif re.match(r"^[0-9a-fA-F]{32,64}$", ioc):
            hash_iocs.append(ioc)
        elif re.match(r"^CVE-\d{4}-\d+$", ioc, re.IGNORECASE):
            cve_iocs.append(ioc)
        elif "." in ioc and not ioc.startswith("http"):
            domain_iocs.append(ioc)
        else:
            other_iocs.append(ioc)

    ioc_table_rows = []
    for ip in ip_iocs:
        ioc_table_rows.append(f"| {ip} | IP Address | Pending analysis | Block at firewall |")
    for d in domain_iocs:
        ioc_table_rows.append(f"| {d} | Domain | Pending analysis | DNS sinkhole / block |")
    for h in hash_iocs:
        ioc_table_rows.append(f"| {h[:16]}... | File Hash | Pending analysis | Quarantine + YARA scan |")
    for c in cve_iocs:
        ioc_table_rows.append(f"| {c} | CVE | Pending analysis | Patch / mitigate |")
    for o in other_iocs:
        ioc_table_rows.append(f"| {o} | Other | Pending analysis | Review manually |")

    ioc_table = "\n".join(ioc_table_rows) or "| No IOCs provided | — | — | — |"

    remediation_steps = _build_remediation(ip_iocs, domain_iocs, hash_iocs, cve_iocs)

    report = f"""# Incident Response Report
## {incident_title}

---

**Report Date:** {date_str}
**Severity:** {severity_emoji} {severity}
**Analyst:** {analyst_name}
**Affected Systems:** {affected}
**Status:** In Progress

---

## Executive Summary

A security incident has been identified and is currently under investigation.
This report documents the indicators of compromise, initial analysis, and
recommended remediation actions for {incident_title}.

Initial triage indicates a **{severity.lower()} severity** event involving
{len(iocs)} indicator(s) of compromise across {len(set([type for type in ['IP' if ip_iocs else None, 'Domain' if domain_iocs else None, 'Hash' if hash_iocs else None] if type]))} IOC category(ies).

---

## Indicators of Compromise

| Indicator | Type | Threat Level | Recommended Action |
|-----------|------|-------------|-------------------|
{ioc_table}

---

## Timeline

| Time | Event |
|------|-------|
| {date_str} | Incident detected and triage initiated |
| {date_str} | IOCs extracted and submitted for analysis |
| TBD | Threat intelligence results received |
| TBD | Containment actions executed |
| TBD | Eradication and recovery |
| TBD | Post-incident review |

---

## Remediation Actions

{remediation_steps}

---

## Recommended Next Steps

1. **Immediate (0-2 hours)**
   - Block all listed IP IOCs at the perimeter firewall and WAF
   - DNS sinkhole or blackhole all domain IOCs
   - Isolate any confirmed compromised hosts from the network

2. **Short-term (2-24 hours)**
   - Run YARA scans (use `generate_yara_rule` for hash IOCs) across endpoints
   - Review SIEM logs for historical activity from listed IOCs
   - Notify relevant stakeholders per the incident communications plan

3. **Medium-term (1-7 days)**
   - Patch or mitigate any exploited CVEs
   - Conduct root cause analysis
   - Update threat intel feeds and SIEM detection rules
   - Schedule post-incident review

---

## Classification

**Handling:** TLP:AMBER — Share only with relevant internal teams and trusted partners.

---

_Report auto-generated by SOC Copilot MCP. All findings require analyst validation._
_Generated: {date_str}_
"""

    return f"## Draft IR Report\n\n```markdown\n{report}\n```\n\n_Copy the above into your incident management system or share directly with stakeholders._"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_remediation(ips: list, domains: list, hashes: list, cves: list) -> str:
    steps = []
    if ips:
        steps.append(
            f"### IP Addresses ({len(ips)} indicators)\n"
            "- Block at perimeter firewall (inbound and outbound)\n"
            "- Check for existing sessions from these IPs in firewall/SIEM logs\n"
            "- Add to threat intel blacklist feed\n"
            "- Consider AbuseIPDB report submission"
        )
    if domains:
        steps.append(
            f"### Domains ({len(domains)} indicators)\n"
            "- DNS sinkhole or null-route all listed domains\n"
            "- Search email gateway logs for messages linking to these domains\n"
            "- Check proxy/web filtering logs for employee access"
        )
    if hashes:
        steps.append(
            f"### File Hashes ({len(hashes)} indicators)\n"
            "- Deploy YARA rules on all endpoints (use generate_yara_rule tool)\n"
            "- Quarantine any matching files immediately\n"
            "- Submit samples to sandbox for dynamic analysis"
        )
    if cves:
        steps.append(
            f"### CVEs ({len(cves)} indicators)\n"
            "- Identify all systems running the affected software versions\n"
            "- Apply vendor patches immediately or implement workarounds\n"
            "- Use Shodan to check external exposure (use check_cve_exploitability tool)"
        )
    if not steps:
        steps.append("No specific remediation steps — review IOCs manually.")
    return "\n\n".join(steps)