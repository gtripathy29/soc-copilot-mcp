"""Full investigation orchestrator — runs all relevant tools and produces an analyst brief."""

from __future__ import annotations
import asyncio
import re
from datetime import datetime, timezone

from tools.correlation import correlate_ioc
from tools.analyst_tools import draft_ir_report
from tools import virustotal, abuseipdb, shodan


async def full_investigation(
    iocs: list[str],
    incident_title: str = "Threat Investigation",
    analyst_name: str = "SOC Analyst",
) -> str:
    """Run a complete multi-source threat investigation on a list of IOCs.

    Orchestrates all available tools in parallel:
    - Cross-source correlation (VT + AbuseIPDB) for each IOC
    - Shodan lookup for IP IOCs
    - MITRE ATT&CK technique mapping
    - Unified threat scoring
    - Auto-generated incident response brief

    Use this as your first tool when a user provides multiple IOCs or says
    'investigate', 'analyse', or 'run a full check'.

    Args:
        iocs: List of IOCs to investigate (IPs, domains, hashes, CVEs, mixed).
        incident_title: Title for the generated investigation report.
        analyst_name: Name of the analyst running the investigation.
    """
    start = datetime.now(timezone.utc)
    results: dict[str, str] = {}
    errors: list[str] = []

    # Categorise IOCs
    ip_iocs, domain_iocs, hash_iocs, cve_iocs = [], [], [], []
    for ioc in iocs:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            ip_iocs.append(ioc)
        elif re.match(r"^[0-9a-fA-F]{32,64}$", ioc):
            hash_iocs.append(ioc)
        elif re.match(r"^CVE-\d{4}-\d+$", ioc, re.IGNORECASE):
            cve_iocs.append(ioc)
        elif "." in ioc:
            domain_iocs.append(ioc)

    # -----------------------------------------------------------------------
    # Phase 1 — Run correlations and Shodan lookups concurrently
    # -----------------------------------------------------------------------
    tasks: list[tuple[str, object]] = []

    for ip in ip_iocs[:5]:  # cap at 5 to respect rate limits
        tasks.append((f"correlate_{ip}", correlate_ioc(ip, "ip")))
        tasks.append((f"shodan_{ip}", shodan.lookup_ip(ip)))

    for domain in domain_iocs[:3]:
        tasks.append((f"correlate_{domain}", correlate_ioc(domain, "domain")))

    for h in hash_iocs[:3]:
        tasks.append((f"correlate_{h[:8]}", correlate_ioc(h, "hash")))

    if tasks:
        task_names = [t[0] for t in tasks]
        task_coros = [t[1] for t in tasks]
        gathered = await asyncio.gather(
            *task_coros,              # type: ignore[arg-type]
            return_exceptions=True,
        )
        for name, result in zip(task_names, gathered):
            if isinstance(result, BaseException):
                errors.append(f"{name}: {result}")
            else:
                results[name] = str(result)

    # -----------------------------------------------------------------------
    # Phase 2 — Draft the IR report
    # -----------------------------------------------------------------------
    ir_report = await draft_ir_report(
        iocs=iocs,
        incident_title=incident_title,
        analyst_name=analyst_name,
        severity=_assess_severity(results),
    )

    # -----------------------------------------------------------------------
    # Compose the unified brief
    # -----------------------------------------------------------------------
    elapsed = (datetime.now(timezone.utc) - start).seconds

    lines = [
        f"# Full Investigation Brief — {incident_title}",
        f"_Generated in {elapsed}s | {len(iocs)} IOC(s) | Analyst: {analyst_name}_",
        "",
        "---",
        "",
        f"## IOC Summary",
        f"- **IPs:** {len(ip_iocs)}   **Domains:** {len(domain_iocs)}   **Hashes:** {len(hash_iocs)}   **CVEs:** {len(cve_iocs)}",
        "",
    ]

    # Add correlation results per IOC
    for ioc in iocs[:5]:
        corr_key = next((k for k in results if k.startswith("correlate_") and ioc[:8] in k), None)
        if corr_key:
            lines.append(results[corr_key])
            lines.append("---")

    # Add Shodan summaries for IPs
    for ip in ip_iocs[:3]:
        shodan_key = f"shodan_{ip}"
        if shodan_key in results:
            lines.append(results[shodan_key])
            lines.append("---")

    if errors:
        lines.append("## Errors During Investigation")
        for e in errors:
            lines.append(f"  - {e}")
        lines.append("")
        lines.append("---")

    # Add IR report
    lines.append(ir_report)
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Suggested Next Tool Calls")
    if hash_iocs:
        lines.append(f"- `generate_yara_rule(\"{hash_iocs[0]}\")` — create endpoint detection rule")
    if domain_iocs:
        lines.append(f"- `hunt_lookalike_domains(\"{domain_iocs[0]}\")` — find phishing variants")
    if cve_iocs:
        lines.append(f"- `check_cve_exploitability(\"{cve_iocs[0]}\")` — assess internet exposure")
    if ip_iocs:
        lines.append(f"- `abuseipdb_report_ip(\"{ip_iocs[0]}\", [18, 14])` — report confirmed malicious IP")
    lines.append("")

    return "\n".join(lines)


def _assess_severity(results: dict[str, str]) -> str:
    """Quick heuristic severity from correlated results text."""
    combined = " ".join(results.values()).lower()
    if "malicious" in combined or "critical" in combined or "🚨" in combined:
        return "Critical"
    if "likely malicious" in combined or "high" in combined or "🔴" in combined:
        return "High"
    if "suspicious" in combined or "medium" in combined or "🟠" in combined:
        return "Medium"
    return "Low"
