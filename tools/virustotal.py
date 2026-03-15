"""VirusTotal threat intelligence tools."""

import os
import httpx
from utils.formatter import format_section, format_error, format_verdict

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict[str, str]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        raise ValueError("VIRUSTOTAL_API_KEY is not set")
    return {"x-apikey": key, "Accept": "application/json"}


async def check_ip(ip: str) -> str:
    """Query VirusTotal for threat data on an IP address."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers())
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("VirusTotal", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("VirusTotal", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("VirusTotal", f"Request failed: {exc}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    return format_section(f"VirusTotal — IP: {ip}", {
        "Verdict": format_verdict(malicious, total),
        "Detections": f"{malicious}/{total} engines",
        "Country": attrs.get("country", "N/A"),
        "ASN": attrs.get("asn", "N/A"),
        "AS Owner": attrs.get("as_owner", "N/A"),
        "Reputation Score": attrs.get("reputation", "N/A"),
        "Network": attrs.get("network", "N/A"),
        "Tags": attrs.get("tags", []),
    })


async def check_domain(domain: str) -> str:
    """Query VirusTotal for threat data on a domain."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{BASE_URL}/domains/{domain}", headers=_headers())
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("VirusTotal", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("VirusTotal", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("VirusTotal", f"Request failed: {exc}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    return format_section(f"VirusTotal — Domain: {domain}", {
        "Verdict": format_verdict(malicious, total),
        "Detections": f"{malicious}/{total} engines",
        "Registrar": attrs.get("registrar", "N/A"),
        "Creation Date": attrs.get("creation_date", "N/A"),
        "Reputation Score": attrs.get("reputation", "N/A"),
        "Categories": attrs.get("categories", {}),
        "Tags": attrs.get("tags", []),
    })


async def check_file_hash(file_hash: str) -> str:
    """Query VirusTotal for threat data on a file hash (MD5/SHA1/SHA256)."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{BASE_URL}/files/{file_hash}", headers=_headers())
            resp.raise_for_status()
        except ValueError as exc:
            return format_error("VirusTotal", str(exc))
        except httpx.HTTPStatusError as exc:
            return format_error("VirusTotal", f"HTTP {exc.response.status_code}: {exc.response.text}")
        except httpx.RequestError as exc:
            return format_error("VirusTotal", f"Request failed: {exc}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    return format_section(f"VirusTotal — File Hash: {file_hash}", {
        "Verdict": format_verdict(malicious, total),
        "Detections": f"{malicious}/{total} engines",
        "File Type": attrs.get("type_description", "N/A"),
        "File Size": f"{attrs.get('size', 'N/A')} bytes",
        "MD5": attrs.get("md5", "N/A"),
        "SHA1": attrs.get("sha1", "N/A"),
        "SHA256": attrs.get("sha256", "N/A"),
        "Names": attrs.get("names", [])[:5],
        "Tags": attrs.get("tags", []),
    })
