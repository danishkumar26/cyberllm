"""Log parsers — convert raw log files into a common schema."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class LogEntry:
    """A single normalized log entry."""

    timestamp: str | None = None
    hostname: str | None = None
    service: str | None = None
    message: str = ""
    raw: str = ""
    severity: str | None = None
    source_ip: str | None = None
    user: str | None = None


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"$'
)
WINDOWS_EVENT_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<event_id>\d+)\s+"
    r"(?P<message>.*)$"
)


@dataclass
class ParserResult:
    entries: list[LogEntry] = field(default_factory=list)
    parse_errors: int = 0


def _iter_lines(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")


def parse_syslog(path: str) -> ParserResult:
    """Parse syslog-format logs (e.g. /var/log/auth.log)."""
    result = ParserResult()
    for line in _iter_lines(path):
        if not line.strip():
            continue
        m = SYSLOG_RE.match(line)
        if m:
            ip = None
            ip_match = IPV4_RE.search(m.group("message"))
            if ip_match:
                ip = ip_match.group(0)
            result.entries.append(
                LogEntry(
                    timestamp=m.group("timestamp"),
                    hostname=m.group("hostname"),
                    service=m.group("service"),
                    message=m.group("message"),
                    raw=line,
                    source_ip=ip,
                )
            )
        else:
            result.parse_errors += 1
    return result


def parse_json(path: str) -> ParserResult:
    """Parse one-JSON-object-per-line logs."""
    result = ParserResult()
    for line in _iter_lines(path):
        if not line.strip():
            continue
        try:
            import json

            obj = json.loads(line)
        except json.JSONDecodeError:
            result.parse_errors += 1
            continue
        ip = obj.get("source_ip") or obj.get("src_ip") or obj.get("ip")
        result.entries.append(
            LogEntry(
                timestamp=str(obj.get("timestamp", "")),
                hostname=str(obj.get("hostname", "")),
                service=str(obj.get("service", obj.get("process", ""))),
                message=str(obj.get("message", obj.get("msg", ""))),
                raw=line,
                source_ip=str(ip) if ip else None,
                user=str(obj.get("user", obj.get("username", ""))),
            )
        )
    return result


def parse_apache(path: str) -> ParserResult:
    """Parse Apache/Nginx combined access logs."""
    result = ParserResult()
    for line in _iter_lines(path):
        if not line.strip():
            continue
        m = APACHE_RE.match(line)
        if m:
            result.entries.append(
                LogEntry(
                    timestamp=m.group("timestamp"),
                    service="httpd",
                    message=f"{m.group('method')} {m.group('path')} {m.group('status')} {m.group('size')}",
                    raw=line,
                    source_ip=m.group("ip"),
                )
            )
        else:
            result.parse_errors += 1
    return result


def parse_windows_event(path: str) -> ParserResult:
    """Parse simple Windows Event log exports."""
    result = ParserResult()
    for line in _iter_lines(path):
        if not line.strip():
            continue
        m = WINDOWS_EVENT_RE.match(line)
        if m:
            result.entries.append(
                LogEntry(
                    timestamp=m.group("timestamp"),
                    service=m.group("source"),
                    message=m.group("message"),
                    raw=line,
                )
            )
        else:
            result.parse_errors += 1
    return result


PARSERS = {
    "syslog": parse_syslog,
    "json": parse_json,
    "apache": parse_apache,
    "windows_event": parse_windows_event,
}


def parse_file(path: str, parser: str | None = None) -> ParserResult:
    """Parse a log file, auto-detecting format when ``parser`` is None."""
    if parser:
        return PARSERS[parser](path)

    # Auto-detect: try JSON first (one object per line), then syslog
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first_non_empty = next((line for line in fh if line.strip()), "")
    if first_non_empty.lstrip().startswith("{"):
        return parse_json(path)
    return parse_syslog(path)
