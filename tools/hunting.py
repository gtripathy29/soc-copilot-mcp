"""Advanced threat hunting tools — lookalike domains and CVE exploitability."""

from __future__ import annotations
import asyncio
import os
import httpx
import itertools
from utils.formatter import format_section, format_error


# ---------------------------------------------------------------------------
# hunt_lookalike_domains
# ---------------------------------------------------------------------------

_COMMON_TLDS = [".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".online", ".site"]

_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["à", "á", "â", "ä", "а"],
    "e": ["è", "é", "ê", "ë", "е"],
    "i": ["í", "ì", "î", "ï", "і"],
    "o": ["ò", "ó", "ô", "ö", "о"],
    "u": ["ù", "ú", "û", "ü"],
    "c": ["с"],
    "p": ["р"],
    "s": ["ѕ"],
    "l": ["1", "I"],
    "0": ["o", "O"],
}


def _generate_typosquats(domain: str) -> list[str]:
    """Generate typosquat candidates for a domain name."""
    parts = domain.rsplit(".", 1)
    base = parts[0] if len(parts) == 2 else domain
    tld = f".{parts[1]}" if len(parts) == 2 else ".com"

    candidates: set[str] = set()

    # 1. Character substitutions (adjacent keyboard keys)
    keyboard_neighbors = {
        "q":"wa", "w":"qes", "e":"wrd", "r":"etf", "t":"ryg",
        "y":"tuh", "u":"yij", "i":"uok", "o":"ipl", "p":"o",
        "a":"sqz", "s":"awdx", "d":"sec", "f":"drv", "g":"ftb",
        "h":"gyn", "j":"hkm", "k":"jl", "l":"k",
        "z":"ax", "x":"zsc", "c":"xvd", "v":"cbf", "b":"vng",
        "n":"bmh", "m":"nj",
    }
    for i, ch in enumerate(base):
        for sub in keyboard_neighbors.get(ch, ""):
            candidates.add(base[:i] + sub + base[i+1:] + tld)

    # 2. Character omissions
    for i in range(len(base)):
        if len(base) > 3:
            candidates.add(base[:i] + base[i+1:] + tld)

    # 3. Character duplications
    for i, ch in enumerate(base):
        candidates.add(base[:i] + ch + base[i:] + tld)

    # 4. Common prefix/suffix additions
    for prefix in ["my", "the", "get", "go", "app", "login", "secure", "account", "mail"]:
        candidates.add(f"{prefix}{base}{tld}")
        candidates.add(f"{prefix}-{base}{tld}")
    for suffix in ["-login", "-account", "-secure", "-verify", "app", "web"]:
        candidates.add(f"{base}{suffix}{tld}")

    # 5. TLD swaps
    for alt_tld in _COMMON_TLDS:
        if alt_tld != tld:
            candidates.add(f"{base}{alt_tld}")

    # 6. Hyphen insertion
    for i in range(1, len(base)):
        candidates.add(f"{base[:i]}-{base[i:]}{tld}")

    # 7. Common confusables (l→1, 0→o)
    for i, ch in enumerate(base):
        if ch == "l":
            candidates.add(base[:i] + "1" + base[i+1:] + tld)
        if ch == "o":
            candidates.add(base[:i] + "0" + base[i+1:] + tld)
        if ch == "i":
            candidates.add(base[:i] + "1" + base[i+1:] + tld)

    # Filter: remove the original domain and very long candidates
    candidates.discard(domain)
    candidates.discard(base + tld)
    return sorted(c for c in candidates if len(c) < 60)[:60]


async def _check_domain_dns(client: httpx.AsyncClient, domain: str) -> tuple[str, bool]:
    """Check if a domain resolves (exists) using a public DNS API."""
    try:
        resp = await client.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "A"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("Status", 3)
            answers = data.get("Answer", [])
            exists = status == 0 and bool(answers)
            return domain, exists
    except Exception:
        pass
    return domain, False


async def hunt_lookalike_domains(domain: str, check_dns: bool = True) -> str:
    """Find typosquat and lookalike domains that could be used for phishing.

    Generates permutations (keyboard typos, omissions, additions, TLD swaps)
    and optionally checks which ones actually resolve via DNS.

    Args:
        domain: The legitimate domain to protect (e.g. 'company.com').
        check_dns: If True, perform DNS resolution checks to find live domains.
    """
    candidates = _generate_typosquats(domain)

    live_domains: list[str] = []
    checked = 0

    if check_dns and candidates:
        # Check DNS resolution for up to 40 candidates concurrently
        to_check = candidates[:40]
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(
                *[_check_domain_dns(client, d) for d in to_check],
                return_exceptions=True,
            )
        for result in results:
            if isinstance(result, tuple):
                dom, alive = result
                checked += 1
                if alive:
                    live_domains.append(dom)

    lines = [f"## Lookalike Domain Hunt — {domain}", ""]
    lines.append(f"**Candidates generated:** {len(candidates)}")
    lines.append(f"**DNS checks performed:** {checked}")
    lines.append(f"**Live / resolving domains found:** {len(live_domains)}")
    lines.append("")

    if live_domains:
        lines.append("### ⚠️  Live Lookalike Domains (take action immediately)")
        for d in live_domains:
            lines.append(f"  - `{d}`")
        lines.append("")
        lines.append("**Recommended actions:**")
        lines.append("  - Submit live domains to VirusTotal (vt_check_domain)")
        lines.append("  - File UDRP/abuse complaint with respective registrar")
        lines.append("  - Block at DNS level and add to threat intel feeds")
        lines.append("  - Alert brand protection / legal team")
    else:
        lines.append("No live lookalike domains detected in the checked sample.")
        lines.append("_Note: Only 40 of the top candidates were DNS-checked._")

    lines.append("")
    lines.append("### Sample Permutations Generated")
    for c in candidates[:20]:
        marker = " ← LIVE" if c in live_domains else ""
        lines.append(f"  - `{c}`{marker}")
    if len(candidates) > 20:
        lines.append(f"  - _(+{len(candidates) - 20} more generated but not shown)_")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# check_cve_exploitability
# ---------------------------------------------------------------------------

async def check_cve_exploitability(cve_id: str) -> str:
    """Check a CVE's exploitability using NVD data and Shodan internet exposure.

    Fetches CVSS score and description from the NVD, then searches Shodan
    for publicly exposed internet hosts that may be vulnerable.

    Args:
        cve_id: CVE identifier (e.g. 'CVE-2021-44228').
    """
    cve_upper = cve_id.upper().strip()
    results: dict = {}
    errors: list[str] = []

    async with httpx.AsyncClient(timeout=20) as client:
        # NVD API (public, no key required)
        try:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_upper},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            nvd_data = resp.json()
            vulns = nvd_data.get("vulnerabilities", [])
            if vulns:
                cve_item = vulns[0].get("cve", {})
                descriptions = cve_item.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")
                metrics = cve_item.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                cvss_score, cvss_severity, attack_vector = "N/A", "N/A", "N/A"
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    cvss_severity = cvss_data.get("baseSeverity", "N/A")
                    attack_vector = cvss_data.get("attackVector", "N/A")
                published = cve_item.get("published", "N/A")[:10]
                results["nvd"] = {
                    "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "attack_vector": attack_vector,
                    "published": published,
                }
            else:
                errors.append(f"NVD: CVE {cve_upper} not found")
        except Exception as exc:
            errors.append(f"NVD lookup failed: {exc}")

        # Shodan vuln search
        shodan_key = os.getenv("SHODAN_API_KEY", "")
        exposed_count = 0
        sample_hosts: list[str] = []
        if shodan_key:
            try:
                resp = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": shodan_key, "query": f"vuln:{cve_upper}", "page": 1},
                )
                if resp.status_code == 200:
                    shodan_data = resp.json()
                    exposed_count = shodan_data.get("total", 0)
                    for match in shodan_data.get("matches", [])[:5]:
                        ip = match.get("ip_str", "")
                        org = match.get("org", "Unknown")
                        country = match.get("location", {}).get("country_name", "Unknown")
                        if ip:
                            sample_hosts.append(f"{ip} ({org}, {country})")
            except Exception as exc:
                errors.append(f"Shodan search failed: {exc}")
        else:
            errors.append("Shodan: SHODAN_API_KEY not set — skipping internet exposure check")

    # Exploitability risk assessment
    risk_level = "Unknown"
    if results.get("nvd"):
        score = results["nvd"]["cvss_score"]
        try:
            score_f = float(score)
            if exposed_count > 10000:
                risk_level = "🚨 CRITICAL — High CVSS + massive internet exposure"
            elif exposed_count > 1000:
                risk_level = "🔴 HIGH — Significant internet-facing exposure"
            elif exposed_count > 0:
                risk_level = "🟠 MEDIUM — Some exposed hosts found"
            elif score_f >= 9.0:
                risk_level = "🔴 HIGH — Critical CVSS (no Shodan data)"
            elif score_f >= 7.0:
                risk_level = "🟠 MEDIUM — High CVSS score"
            else:
                risk_level = "🟡 LOW — Moderate CVSS score"
        except (ValueError, TypeError):
            pass

    lines = [f"## CVE Exploitability Assessment — {cve_upper}", ""]

    if results.get("nvd"):
        nvd = results["nvd"]
        lines.append(f"**Risk Level:** {risk_level}")
        lines.append(f"**CVSS Score:** {nvd['cvss_score']} ({nvd['cvss_severity']})")
        lines.append(f"**Attack Vector:** {nvd['attack_vector']}")
        lines.append(f"**Published:** {nvd['published']}")
        lines.append("")
        lines.append(f"**Description:** {nvd['description']}")

    lines.append("")
    lines.append(f"**Internet-Exposed Hosts (Shodan):** {exposed_count:,}")

    if sample_hosts:
        lines.append("")
        lines.append("**Sample Exposed Hosts:**")
        for host in sample_hosts:
            lines.append(f"  - {host}")

    if errors:
        lines.append("")
        lines.append("**Notes:**")
        for e in errors:
            lines.append(f"  - {e}")

    lines.append("")
    lines.append("**Recommended Actions:**")
    lines.append("  - Identify all internal systems running the affected software")
    lines.append("  - Apply vendor patches immediately if available")
    lines.append("  - Implement virtual patching via WAF/IDS if patch is unavailable")
    lines.append(f"  - Search Shodan for your org's IPs: `org:'YourOrg' vuln:{cve_upper}`")
    lines.append("")

    return "\n".join(lines)
