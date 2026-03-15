"""AbuseIPDB threat intelligence tools."""

import os
import httpx
from utils.formatter import format_section, format_error, format_risk_score

BASE_URL = "https://api.abuseipdb.com/api/v2"


def _headers() -> dict[str, str]:
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        raise ValueError("ABUSEIPDB_API_KEY is not set")
    return {"Key": key, "Accept": "application/json"}


async def check_ip(ip: str, max_age_days: int = 90) -> str:
    """Check an IP address against the AbuseIPDB database.

    Args:
        ip: IPv4 or IPv6 address to check.
        max_age_days: Only include reports from the last N days (1-365).
    """
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max(1, min(365, max_age_days))),
        "verbose": "",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{BASE_URL}/check", headers=_headers(), params=params)
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("AbuseIPDB", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("AbuseIPDB", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("AbuseIPDB", f"Request failed: {exc}")

    data = resp.json().get("data", {})
    categories = _summarise_categories(data.get("reports", []))

    return format_section(f"AbuseIPDB — IP: {ip}", {
        "Abuse Confidence Score": format_risk_score(data.get("abuseConfidenceScore", 0)),
        "Total Reports": data.get("totalReports", 0),
        "Distinct Reporters": data.get("numDistinctUsers", 0),
        "Last Reported": data.get("lastReportedAt") or "Never",
        "ISP": data.get("isp", "N/A"),
        "Domain": data.get("domain", "N/A"),
        "Country": data.get("countryCode", "N/A"),
        "Usage Type": data.get("usageType", "N/A"),
        "Is Whitelisted": data.get("isWhitelisted", False),
        "Is TOR": data.get("isTor", False),
        "Top Abuse Categories": categories or ["None reported"],
    })


async def report_ip(ip: str, categories: list[int], comment: str = "") -> str:
    """Report an IP address to AbuseIPDB.

    Args:
        ip: IPv4 or IPv6 address to report.
        categories: List of AbuseIPDB category IDs (see https://www.abuseipdb.com/categories).
        comment: Optional description of the abuse.
    """
    payload = {
        "ip": ip,
        "categories": ",".join(str(c) for c in categories),
        "comment": comment,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(f"{BASE_URL}/report", headers=_headers(), data=payload)
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("AbuseIPDB", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("AbuseIPDB", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("AbuseIPDB", f"Request failed: {exc}")

    data = resp.json().get("data", {})
    return format_section(f"AbuseIPDB — Report Submitted: {ip}", {
        "IP Address": data.get("ipAddress", ip),
        "New Abuse Confidence Score": format_risk_score(data.get("abuseConfidenceScore", 0)),
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[int, str] = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _summarise_categories(reports: list[dict]) -> list[str]:
    """Return deduplicated, human-readable category names from report list."""
    seen: set[str] = set()
    for report in reports:
        for cat_id in report.get("categories", []):
            name = _CATEGORY_MAP.get(cat_id, f"Category {cat_id}")
            seen.add(name)
    return sorted(seen)
