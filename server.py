"""SOC Copilot MCP Server — Threat Intelligence + Analyst Workflow.

Exposes 15 tools across 5 categories:
  1. VirusTotal  — IP, domain, file hash lookups
  2. AbuseIPDB   — check and report abusive IPs
  3. Shodan      — host lookup, search, exploit DB
  4. Correlation — cross-source IOC scoring + MITRE ATT&CK mapping
  5. Workflow    — YARA rule generation, IR reports, lookalike domain hunting,
                   CVE exploitability, full investigation orchestration

Run with:
    python server.py
Or via MCP stdio (for Claude Desktop / web client):
    python server.py
"""

from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP  # pyright: ignore[reportMissingImports]
from tools import virustotal, abuseipdb, shodan
from tools.correlation import correlate_ioc, map_to_mitre
from tools.analyst_tools import generate_yara_rule, draft_ir_report
from tools.hunting import hunt_lookalike_domains, check_cve_exploitability
from tools.orchestrator import full_investigation

mcp = FastMCP(
    "soc-copilot",
    instructions=(
        "SOC Copilot — an AI-native security investigation assistant. "
        "You have access to 15 threat intelligence and analyst workflow tools. "
        "For any investigation request, prefer 'full_investigation' first to get a "
        "comprehensive picture. Use individual tools for targeted lookups. "
        "Always summarise findings with a clear verdict and recommended actions. "
        "Map threats to MITRE ATT&CK where possible."
    ),
)

# ===========================================================================
# Category 1: VirusTotal
# ===========================================================================

@mcp.tool(description=(
    "Check an IP address against VirusTotal. Returns detection ratio, "
    "country, ASN, reputation score, and tags."
))
async def vt_check_ip(ip: str) -> str:
    """Query VirusTotal for threat intelligence on an IP address.
    Args:
        ip: IPv4 or IPv6 address to look up.
    """
    return await virustotal.check_ip(ip)


@mcp.tool(description=(
    "Check a domain against VirusTotal. Returns detection ratio, "
    "registrar, creation date, reputation score, and categories."
))
async def vt_check_domain(domain: str) -> str:
    """Query VirusTotal for threat intelligence on a domain.
    Args:
        domain: Fully-qualified domain name (e.g. example.com).
    """
    return await virustotal.check_domain(domain)


@mcp.tool(description=(
    "Check a file hash (MD5, SHA-1, or SHA-256) against VirusTotal. "
    "Returns detection ratio, file type, size, and associated names."
))
async def vt_check_file_hash(file_hash: str) -> str:
    """Query VirusTotal for threat intelligence on a file hash.
    Args:
        file_hash: MD5, SHA-1, or SHA-256 hash of the file.
    """
    return await virustotal.check_file_hash(file_hash)


# ===========================================================================
# Category 2: AbuseIPDB
# ===========================================================================

@mcp.tool(description=(
    "Check an IP address against AbuseIPDB. Returns abuse confidence "
    "score (0-100), total reports, ISP, country, and top abuse categories."
))
async def abuseipdb_check_ip(ip: str, max_age_days: int = 90) -> str:
    """Query AbuseIPDB for reports on an IP address.
    Args:
        ip: IPv4 or IPv6 address to check.
        max_age_days: Only include reports within this many days (1-365, default 90).
    """
    return await abuseipdb.check_ip(ip, max_age_days)


@mcp.tool(description=(
    "Report an abusive IP address to AbuseIPDB. "
    "Category IDs: 18=Brute-Force, 22=SSH, 14=Port Scan, "
    "7=Phishing, 11=Email Spam, 16=SQL Injection, 21=Web App Attack."
))
async def abuseipdb_report_ip(ip: str, categories: list[int], comment: str = "") -> str:
    """Submit an abuse report for an IP address to AbuseIPDB.
    Args:
        ip: IPv4 or IPv6 address to report.
        categories: List of AbuseIPDB category IDs describing the abuse.
        comment: Optional free-text description of the abuse incident.
    """
    return await abuseipdb.report_ip(ip, categories, comment)


# ===========================================================================
# Category 3: Shodan
# ===========================================================================

@mcp.tool(description=(
    "Look up an IP address on Shodan. Returns open ports, running "
    "services, detected CVEs, hostnames, organisation, and geolocation."
))
async def shodan_lookup_ip(ip: str) -> str:
    """Retrieve all Shodan data for an IP address.
    Args:
        ip: IPv4 address to look up.
    """
    return await shodan.lookup_ip(ip)


@mcp.tool(description=(
    "Search Shodan using a query string. Supports filters: "
    "port:, country:, org:, product:, vuln:. Returns up to 10 matches."
))
async def shodan_search(query: str, page: int = 1) -> str:
    """Search Shodan for internet-connected devices matching a query.
    Args:
        query: Shodan search query (e.g. 'apache country:DE port:443').
        page: Results page number (default 1).
    """
    return await shodan.search(query, page)


@mcp.tool(description=(
    "Search the Shodan Exploits database for public exploits. "
    "Accepts CVE IDs, product names, or vulnerability descriptions."
))
async def shodan_get_exploits(query: str) -> str:
    """Search Shodan Exploits DB for known public exploits.
    Args:
        query: Search term — a CVE ID (e.g. 'CVE-2021-44228'), product name,
               or vulnerability description.
    """
    return await shodan.get_exploits(query)


# ===========================================================================
# Category 4: Correlation & Intelligence
# ===========================================================================

@mcp.tool(description=(
    "Query ALL threat intel sources for a single IOC and return a unified "
    "correlated verdict with threat score, source breakdown, conflict "
    "detection, and automatic MITRE ATT&CK technique mapping. "
    "Supports IPs, domains, and file hashes."
))
async def correlate_ioc_tool(ioc: str, ioc_type: str = "auto") -> str:
    """Cross-source IOC correlation with unified threat scoring.
    Args:
        ioc: Indicator of compromise — IP address, domain, or file hash.
        ioc_type: One of 'ip', 'domain', 'hash', or 'auto' (default).
    """
    return await correlate_ioc(ioc, ioc_type)


@mcp.tool(description=(
    "Map any free-text threat description, IOC data, or abuse report to "
    "MITRE ATT&CK techniques and tactics. Accepts port numbers, "
    "abuse categories, malware names, attack descriptions, or CVE IDs."
))
async def map_to_mitre_tool(threat_description: str) -> str:
    """Map threat data to MITRE ATT&CK framework techniques.
    Args:
        threat_description: Free text describing threat behaviour, abuse
                            categories, open ports, malware, or attack patterns.
    """
    return await map_to_mitre(threat_description)


# ===========================================================================
# Category 5: Analyst Workflow
# ===========================================================================

@mcp.tool(description=(
    "Generate a YARA detection rule from a file hash using VirusTotal metadata. "
    "Extracts file names, PE sections, size, and imphash to build a rule "
    "deployable on endpoints and SIEM/EDR platforms."
))
async def generate_yara_rule_tool(file_hash: str, rule_name: str = "") -> str:
    """Auto-generate a YARA rule from VirusTotal file metadata.
    Args:
        file_hash: MD5, SHA-1, or SHA-256 hash of the malicious file.
        rule_name: Optional name for the YARA rule (auto-generated if omitted).
    """
    return await generate_yara_rule(file_hash, rule_name)


@mcp.tool(description=(
    "Draft a complete, professional incident response report from a list of IOCs. "
    "Produces an executive summary, IOC table, attack timeline, remediation steps, "
    "and recommended next actions — ready to send to a CISO or management."
))
async def draft_ir_report_tool(
    iocs: list[str],
    incident_title: str = "Suspected Security Incident",
    severity: str = "Medium",
    analyst_name: str = "SOC Analyst",
    affected_systems: str = "",
) -> str:
    """Auto-draft a structured incident response report.
    Args:
        iocs: List of IOCs involved in the incident.
        incident_title: Short title describing the incident.
        severity: Severity level — Low, Medium, High, or Critical.
        analyst_name: Name of the reporting analyst.
        affected_systems: Comma-separated list of affected hosts (optional).
    """
    return await draft_ir_report(iocs, incident_title, severity, analyst_name, affected_systems)


@mcp.tool(description=(
    "Find typosquat and lookalike domains that attackers may use for phishing "
    "against a target brand. Generates permutations (keyboard errors, omissions, "
    "additions, TLD swaps, homoglyphs) and optionally checks which ones are live."
))
async def hunt_lookalike_domains_tool(domain: str, check_dns: bool = True) -> str:
    """Detect active typosquat and lookalike domains for brand protection.
    Args:
        domain: The legitimate domain to protect (e.g. 'company.com').
        check_dns: If True, DNS-check candidates to find live phishing domains.
    """
    return await hunt_lookalike_domains(domain, check_dns)


@mcp.tool(description=(
    "Assess a CVE's real-world exploitability by combining NVD CVSS data with "
    "Shodan internet exposure scanning. Returns CVSS score, attack vector, "
    "number of exposed internet hosts, sample vulnerable IPs, and patch guidance."
))
async def check_cve_exploitability_tool(cve_id: str) -> str:
    """Assess CVE severity + real-world internet exposure via NVD + Shodan.
    Args:
        cve_id: CVE identifier (e.g. 'CVE-2021-44228').
    """
    return await check_cve_exploitability(cve_id)


@mcp.tool(description=(
    "Run a complete threat investigation on multiple IOCs in one call. "
    "Orchestrates all available tools concurrently: cross-source correlation, "
    "Shodan host lookups, MITRE ATT&CK mapping, and generates a full incident "
    "response brief ready for management. Use this as the FIRST tool when "
    "a user provides IOCs or asks for a full investigation."
))
async def full_investigation_tool(
    iocs: list[str],
    incident_title: str = "Threat Investigation",
    analyst_name: str = "SOC Analyst",
) -> str:
    """Orchestrate a full multi-source investigation across all IOCs.
    Args:
        iocs: List of IOCs to investigate (IPs, domains, hashes, CVEs — mixed OK).
        incident_title: Title for the investigation report.
        analyst_name: Name of the analyst running the investigation.
    """
    return await full_investigation(iocs, incident_title, analyst_name)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
