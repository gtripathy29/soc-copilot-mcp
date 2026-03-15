"""Shodan threat intelligence tools."""

import os
import httpx
from utils.formatter import format_section, format_error

BASE_URL = "https://api.shodan.io"


def _api_key() -> str:
    key = os.getenv("SHODAN_API_KEY", "")
    if not key:
        raise ValueError("SHODAN_API_KEY is not set")
    return key


async def lookup_ip(ip: str) -> str:
    """Retrieve all available Shodan data for an IP address.

    Returns open ports, services, banners, CVEs, and geolocation info.
    """
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            resp = await client.get(
                f"{BASE_URL}/shodan/host/{ip}",
                params={"key": _api_key()},
            )
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("Shodan", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("Shodan", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("Shodan", f"Request failed: {exc}")

    data = resp.json()
    ports = sorted(data.get("ports", []))
    raw_vulns = data.get("vulns", [])
    if isinstance(raw_vulns, dict):
        vulns = list(raw_vulns.keys())
    elif isinstance(raw_vulns, list):
        vulns = raw_vulns
    else:
        vulns = []
    
    services = _extract_services(data.get("data", []))

    return format_section(f"Shodan — IP: {ip}", {
        "Organisation": data.get("org", "N/A"),
        "ISP": data.get("isp", "N/A"),
        "ASN": data.get("asn", "N/A"),
        "Country": data.get("country_name", "N/A"),
        "City": data.get("city", "N/A"),
        "OS": data.get("os") or "Unknown",
        "Open Ports": ports or ["None detected"],
        "Services": services or ["None detected"],
        "Hostnames": data.get("hostnames", []),
        "Domains": data.get("domains", []),
        "Last Update": data.get("last_update", "N/A"),
        "CVEs": vulns or ["None detected"],
    })


async def search(query: str, page: int = 1) -> str:
    """Search Shodan using a search query string.

    Args:
        query: Shodan search query (e.g. 'apache country:US port:443').
        page: Results page number (each page contains up to 100 results).
    """
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            resp = await client.get(
                f"{BASE_URL}/shodan/host/search",
                params={"key": _api_key(), "query": query, "page": page},
            )
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("Shodan", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("Shodan", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("Shodan", f"Request failed: {exc}")

    data = resp.json()
    total = data.get("total", 0)
    matches = data.get("matches", [])

    lines = [f"## Shodan Search — `{query}`", ""]
    lines.append(f"**Total Results:** {total}  |  **Page:** {page}  |  **Showing:** {len(matches)}")
    lines.append("")

    for i, match in enumerate(matches[:10], 1):
        ip = match.get("ip_str", "N/A")
        port = match.get("port", "N/A")
        org = match.get("org", "N/A")
        country = match.get("location", {}).get("country_name", "N/A")
        product = match.get("product", "")
        version = match.get("version", "")
        service = f"{product} {version}".strip() or "N/A"
        lines.append(f"**{i}.** `{ip}:{port}` — {org} ({country}) — {service}")

    lines.append("")
    return "\n".join(lines)


async def get_exploits(query: str) -> str:
    """Search Shodan Exploits DB for public exploits matching a query.

    Args:
        query: Search term (e.g. CVE ID, product name, or vulnerability description).
    """
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                f"{BASE_URL}/exploits/search",
                params={"key": _api_key(), "query": query},
            )
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("Shodan Exploits", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("Shodan Exploits", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("Shodan Exploits", f"Request failed: {exc}")

    data = resp.json()
    total = data.get("total", 0)
    matches = data.get("matches", [])

    lines = [f"## Shodan Exploits — `{query}`", ""]
    lines.append(f"**Total Exploits Found:** {total}")
    lines.append("")

    for i, exploit in enumerate(matches[:10], 1):
        title = exploit.get("description", "N/A")
        source = exploit.get("source", "N/A")
        exploit_type = exploit.get("type", "N/A")
        platform = exploit.get("platform", "N/A")
        cve_list = exploit.get("cve", [])
        cves = ", ".join(cve_list) if cve_list else "N/A"
        lines.append(f"**{i}.** {title}")
        lines.append(f"   - Source: {source}  |  Type: {exploit_type}  |  Platform: {platform}")
        lines.append(f"   - CVEs: {cves}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_services(banners: list[dict]) -> list[str]:
    """Extract unique service descriptions from Shodan banner data."""
    seen: set[str] = set()
    for banner in banners:
        product = banner.get("product", "")
        version = banner.get("version", "")
        port = banner.get("port", "")
        transport = banner.get("transport", "tcp")
        if product:
            label = f"{product} {version}".strip() + f" ({port}/{transport})"
        else:
            module = banner.get("_shodan", {}).get("module", "")
            label = f"{module} ({port}/{transport})" if module else f"Port {port}/{transport}"
        seen.add(label)
    return sorted(seen)
