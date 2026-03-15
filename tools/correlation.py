"""Cross-source IOC correlation and MITRE ATT&CK mapping tools."""

from __future__ import annotations
import asyncio
import os
import re
from typing import cast
import httpx
from utils.formatter import format_section, format_error

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique signatures — keyword-based heuristic mapping
# ---------------------------------------------------------------------------

_TECHNIQUE_SIGNATURES: list[tuple[list[str], str, str, str]] = [
    (["ssh", "brute", "brute-force", "22"],          "T1110.003", "Brute Force: Password Spraying",        "TA0006 Credential Access"),
    (["rdp", "3389", "remote desktop"],               "T1021.001", "Remote Services: RDP",                  "TA0008 Lateral Movement"),
    (["port scan", "port-scan", "scanning", "14"],    "T1046",     "Network Service Discovery",              "TA0007 Discovery"),
    (["phishing", "spear", "credential"],             "T1566",     "Phishing",                              "TA0001 Initial Access"),
    (["sql injection", "sqli", "16"],                 "T1190",     "Exploit Public-Facing Application",      "TA0001 Initial Access"),
    (["web app attack", "21", "xss", "rce"],          "T1190",     "Exploit Public-Facing Application",      "T0001 Initial Access"),
    (["ddos", "flood", "amplification", "4"],         "T1498",     "Network Denial of Service",              "TA0040 Impact"),
    (["c2", "command and control", "beacon", "443"],  "T1071.001", "App Layer Protocol: Web Protocols",      "TA0011 C2"),
    (["dns", "53", "tunneling"],                      "T1071.004", "App Layer Protocol: DNS",                "TA0011 C2"),
    (["email spam", "11", "smtp", "25"],              "T1566.001", "Phishing: Spearphishing Attachment",     "TA0001 Initial Access"),
    (["open proxy", "tor", "vpn", "9", "13"],         "T1090",     "Proxy",                                 "TA0011 C2"),
    (["exploit", "cve-", "vulnerability"],            "T1203",     "Exploitation for Client Execution",      "TA0002 Execution"),
    (["botnet", "spam", "compromised"],               "T1584",     "Compromise Infrastructure",              "TA0042 Resource Development"),
    (["data exfil", "exfiltration", "upload"],        "T1041",     "Exfiltration Over C2 Channel",           "TA0010 Exfiltration"),
    (["iot", "23", "telnet", "mirai"],                "T1595",     "Active Scanning",                        "TA0043 Reconnaissance"),
]


def _map_techniques(text: str) -> list[dict[str, str]]:
    lower = text.lower()
    matched: dict[str, dict[str, str]] = {}
    for keywords, tid, name, tactic in _TECHNIQUE_SIGNATURES:
        if any(kw in lower for kw in keywords):
            if tid not in matched:
                matched[tid] = {"id": tid, "name": name, "tactic": tactic}
    return list(matched.values())


# ---------------------------------------------------------------------------
# correlate_ioc
# ---------------------------------------------------------------------------

async def correlate_ioc(ioc: str, ioc_type: str = "auto") -> str:
    detected_type = ioc_type if ioc_type != "auto" else _detect_ioc_type(ioc)
    print(f"DEBUG: ioc={ioc[:16]}... type={detected_type} ioc_type_param={ioc_type}")

    errors: list[str] = []

    async with httpx.AsyncClient(timeout=20) as client:
        tasks: list[tuple[str, object]] = []

        if detected_type in ("ip", "auto"):
            tasks.append(("virustotal_ip", _vt_ip(client, ioc)))
            tasks.append(("abuseipdb", _abuseipdb(client, ioc)))
        if detected_type == "domain":
            tasks.append(("virustotal_domain", _vt_domain(client, ioc)))
        if detected_type == "hash":
            tasks.append(("virustotal_hash", _vt_hash(client, ioc)))

        fetched = await asyncio.gather(
            *[t[1] for t in tasks],   # type: ignore[arg-type]
            return_exceptions=True,
        )

    source_data: dict[str, dict[str, object]] = {}
    for (name, _), result in zip(tasks, fetched):
        if isinstance(result, BaseException):
            errors.append(f"{name}: {result}")
        else:
            source_data[name] = cast(dict[str, object], result)

    # Build unified score
    scores: list[float] = []
    notes: list[str] = []
    vt_ratio: float = 0.0
    vt_raw: tuple[int, int] = (0, 0)

    if any(k in source_data for k in ("virustotal_ip", "virustotal_domain", "virustotal_hash")):
        vt_key = next(k for k in source_data if k.startswith("virustotal"))
        vt = source_data[vt_key]
        malicious = int(vt.get("malicious", 0))   # type: ignore[arg-type]
        total = int(vt.get("total", 1))            # type: ignore[arg-type]
        vt_ratio = malicious / max(total, 1)
        vt_raw = (malicious, total)
        # Weight VT higher (0.6) — it aggregates many engines
        scores.append(vt_ratio * 100 * 0.6)
        notes.append(f"VirusTotal: {malicious}/{total} engines flagged")

    if "abuseipdb" in source_data:
        ab = source_data["abuseipdb"]
        abuse_score = float(ab.get("abuseConfidenceScore", 0))  # type: ignore[arg-type]
        # Weight AbuseIPDB lower (0.4) — community reports, can be noisy
        scores.append(abuse_score * 0.4)
        notes.append(f"AbuseIPDB: confidence score {int(abuse_score)}/100")

    # Normalise back to 0-100
    # Since weights sum to 1.0, scores already represent weighted contribution
    unified_score = round(sum(scores)) if scores else -1

    # IOC-type specific verdict — IPs need lower thresholds than hashes
    if unified_score == -1:
        verdict = "⚠️ Unknown — all intelligence sources failed"
    else:
        verdict = _score_to_verdict(unified_score, detected_type, vt_raw)

    has_errors = len(errors) > 0
    has_data = len(scores) > 0

    if not has_data and has_errors:
        # All sources failed — cannot make any verdict
        verdict = "⚠️ Unknown — all intelligence sources failed"
        unified_score = -1  # sentinel: means "no data", not "clean"
    elif not has_data:
        verdict = "⚠️ Unknown — no intelligence sources returned data"
        unified_score = -1
    else:
        unified_score = round(sum(scores) / len(scores))
        verdict = _score_to_verdict(unified_score, detected_type, vt_raw)

    conflict = ""
    if len(scores) >= 2 and max(scores) - min(scores) > 40:
        conflict = (
            f"⚠️  Source conflict detected — scores differ by "
            f"{round(max(scores) - min(scores))} points. "
            "This may indicate a recently listed/delisted IP or evasion technique."
        )

    raw_combined = " ".join(str(v) for v in source_data.values())
    techniques = _map_techniques(raw_combined)

    lines = [f"## Correlated Threat Intelligence — {ioc}", ""]
    lines.append(f"**IOC Type:** {detected_type.upper()}")

    if unified_score == -1:
        lines.append("**Unified Threat Score:** N/A — insufficient data")
    else:
        lines.append(f"**Unified Threat Score:** {unified_score}/100")

    lines.append(f"**Verdict:** {verdict}")
    lines.append("")
    lines.append("**Source Breakdown:**")
    for note in notes:
        lines.append(f"  - {note}")
    
    if has_errors:
        lines.append("")
        lines.append("**⚠️ Source Errors (results may be incomplete):**")
        for e in errors:
            lines.append(f"  - {e}")
        if not has_data:
            lines.append("")
            lines.append(
                "> ❌ No sources returned valid data. "
                "Do NOT treat this IOC as clean — verify API keys and retry."
            )
    
    if conflict:
        lines.append("")
        lines.append(conflict)

    if techniques:
        lines.append("")
        lines.append("**Likely MITRE ATT&CK Techniques:**")
        for t in techniques:
            lines.append(f"  - [{t['id']}] {t['name']} — {t['tactic']}")
    
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# map_to_mitre
# ---------------------------------------------------------------------------

async def map_to_mitre(threat_description: str) -> str:
    techniques = _map_techniques(threat_description)

    if not techniques:
        return format_section("MITRE ATT&CK Mapping", {
            "Result": "No techniques matched. Try including specific indicators such as "
                      "port numbers, abuse categories, CVE IDs, or attack descriptions.",
        })

    lines = ["## MITRE ATT&CK Mapping", ""]
    lines.append(f"**Techniques identified:** {len(techniques)}")
    lines.append("")

    tactic_groups: dict[str, list[dict[str, str]]] = {}
    for t in techniques:
        tactic_groups.setdefault(t["tactic"], []).append(t)

    for tactic, techs in tactic_groups.items():
        lines.append(f"**{tactic}**")
        for t in techs:
            url = f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/"
            lines.append(f"  - [{t['id']}] {t['name']}  →  {url}")
        lines.append("")

    lines.append("_Mapping is heuristic-based on keywords. Verify against official ATT&CK Navigator._")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_ioc_type(ioc: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{32,64}$", ioc):
        return "hash"
    return "domain"


def _score_to_verdict(score: int, ioc_type: str = "hash", vt_raw: tuple[int, int] = (0, 0)) -> str:
    """Return verdict with different thresholds per IOC type.
    
    IPs: even 3-4 VT detections = suspicious. 10+ = malicious.
    Domains: similar to IPs — low detection count still matters.
    Hashes: higher bar — malware packing means fewer detections sometimes.
    """
    malicious_engines, total_engines = vt_raw

    # Hard overrides based on raw VT engine count — regardless of score
    if ioc_type in ("ip", "domain"):
        if malicious_engines >= 10:
            return "🚨 Malicious — flagged by 10+ VT engines (high confidence)"
        if malicious_engines >= 5:
            return "🔴 High risk — flagged by 5+ VT engines"
        if malicious_engines >= 2:
            return "🟠 Suspicious — multiple VT engines flagged"
        if malicious_engines == 1:
            return "🟡 Low risk — single VT engine flagged, verify manually"

    if ioc_type == "hash":
        if malicious_engines >= 20:
            return "🚨 Malicious — confirmed by 20+ AV engines"
        if malicious_engines >= 10:
            return "🔴 High risk — detected by 10+ AV engines"
        if malicious_engines >= 5:
            return "🟠 Suspicious — detected by 5+ AV engines"
        if malicious_engines >= 1:
            return "🟡 Low risk — minimal detections, investigate further"

    # Fallback to weighted score
    if score == 0:
        return "🟢 Clean — no threat signals detected"
    if score < 15:
        return "🟡 Low risk — minor signals"
    if score < 35:
        return "🟠 Suspicious — moderate threat indicators"
    if score < 55:
        return "🔴 High risk — strong threat signals"
    return "🚨 Malicious — confirmed by multiple sources"



async def _vt_ip(client: httpx.AsyncClient, ip: str) -> dict[str, object]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    resp = await client.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key},
    )
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "total": sum(stats.values()),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", ""),
        "tags": " ".join(attrs.get("tags", [])),
    }


async def _vt_domain(client: httpx.AsyncClient, domain: str) -> dict[str, object]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    resp = await client.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": key},
    )
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "total": sum(stats.values()),
        "registrar": attrs.get("registrar", ""),
        "tags": " ".join(attrs.get("tags", [])),
    }


async def _vt_hash(client: httpx.AsyncClient, file_hash: str) -> dict[str, object]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    resp = await client.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key},
    )
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "total": sum(stats.values()),
        "type": attrs.get("type_description", ""),
        "names": " ".join(attrs.get("names", [])[:3]),
        "tags": " ".join(attrs.get("tags", [])),
    }


async def _abuseipdb(client: httpx.AsyncClient, ip: str) -> dict[str, object]:
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    resp = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    category_ids: list[int] = []
    for report in data.get("reports", []):
        category_ids.extend(report.get("categories", []))
    return {
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "totalReports": data.get("totalReports", 0),
        "isp": data.get("isp", ""),
        "usageType": data.get("usageType", ""),
        "categories": " ".join(str(c) for c in set(category_ids)),
    }