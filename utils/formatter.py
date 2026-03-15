"""Shared formatting utilities for threat intelligence results."""

from typing import Any


def format_section(title: str, data: dict[str, Any]) -> str:
    """Format a key-value section with a title."""
    lines = [f"## {title}", ""]
    for key, value in data.items():
        if isinstance(value, list):
            lines.append(f"**{key}:**")
            for item in value:
                lines.append(f"  - {item}")
        elif isinstance(value, dict):
            lines.append(f"**{key}:**")
            for k, v in value.items():
                lines.append(f"  - {k}: {v}")
        else:
            lines.append(f"**{key}:** {value}")
    lines.append("")
    return "\n".join(lines)


def format_error(source: str, message: str) -> str:
    """Format an error response consistently."""
    return f"**[{source} Error]** {message}"


def format_verdict(malicious: int, total: int) -> str:
    """Return a human-readable verdict based on detection ratio."""
    if total == 0:
        return "unknown"
    ratio = malicious / total
    if ratio == 0:
        return "clean"
    if ratio < 0.1:
        return "suspicious"
    if ratio < 0.5:
        return "likely malicious"
    return "malicious"


def format_risk_score(score: int, max_score: int = 100) -> str:
    """Return a labelled risk string from a numeric score."""
    pct = score / max_score if max_score else 0
    if pct == 0:
        label = "None"
    elif pct < 0.25:
        label = "Low"
    elif pct < 0.5:
        label = "Medium"
    elif pct < 0.75:
        label = "High"
    else:
        label = "Critical"
    return f"{score}/{max_score} ({label})"
