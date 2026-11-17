"""Report generation — Markdown, JSON, and SIEM-ready formats."""

from __future__ import annotations

from datetime import datetime, timezone

from .analyzer import AnalyzedEvent


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_markdown(event: AnalyzedEvent) -> str:
    """Render a single analyzed event as a Markdown incident report."""
    lines: list[str] = [
        "# Security Incident Report",
        "",
        f"**Generated:** {_now_iso()}",
        f"**Source:** {event.source or 'unknown'}",
        f"**Severity:** {event.severity.upper()}",
        f"**Confidence:** {event.confidence:.0%}",
        "",
        "## Summary",
        "",
        f"{event.summary}",
        "",
    ]
    if event.mitre_technique:
        lines.extend(
            [
                "## MITRE ATT&CK",
                "",
                f"- **Technique:** {event.mitre_technique} — {event.mitre_technique_name or 'N/A'}",
                f"- **Tactic:** {event.mitre_tactic or 'N/A'}",
                "",
            ]
        )
    if event.indicators:
        lines.extend(
            [
                "## Indicators of Compromise",
                "",
                *[f"- `{ind}`" for ind in event.indicators],
                "",
            ]
        )
    lines.extend(
        [
            "## Remediation",
            "",
            f"{event.remediation}",
            "",
            "## Raw Log Excerpt",
            "",
            "```",
            f"{event.raw_excerpt}",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def to_json(event: AnalyzedEvent) -> str:
    """Serialize an analyzed event to JSON."""
    import json

    return json.dumps(
        {
            "timestamp": _now_iso(),
            "source": event.source,
            "severity": event.severity,
            "confidence": event.confidence,
            "summary": event.summary,
            "mitre_technique": event.mitre_technique,
            "mitre_technique_name": event.mitre_technique_name,
            "mitre_tactic": event.mitre_tactic,
            "indicators": event.indicators,
            "remediation": event.remediation,
            "raw_excerpt": event.raw_excerpt,
        },
        indent=2,
    )


def to_siem(event: AnalyzedEvent) -> str:
    """Serialize an analyzed event to a SIEM-ready JSON object."""
    import json

    siem = {
        "event_timestamp": _now_iso(),
        "event_source": event.source or "cyberllm",
        "event_severity": event.severity.upper(),
        "event_confidence": round(event.confidence, 2),
        "event_summary": event.summary,
        "mitre": {
            "technique_id": event.mitre_technique,
            "technique_name": event.mitre_technique_name,
            "tactic": event.mitre_tactic,
        },
        "indicators": event.indicators,
        "remediation": event.remediation,
        "raw_excerpt": event.raw_excerpt,
    }
    return json.dumps(siem, indent=2)


FORMATTERS = {
    "markdown": to_markdown,
    "json": to_json,
    "siem": to_siem,
}


def format_event(event: AnalyzedEvent, fmt: str = "markdown") -> str:
    """Format an analyzed event using the requested formatter."""
    formatter = FORMATTERS.get(fmt)
    if formatter is None:
        raise ValueError(f"Unknown format: {fmt!r}. Use: {', '.join(FORMATTERS)}")
    return formatter(event)
