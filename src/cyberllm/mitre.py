"""MITRE ATT&CK technique mapping helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MITREMapping:
    technique_id: str | None
    technique_name: str | None
    tactic: str | None
    confidence: float


# A small, curated mapping of common indicator keywords -> MITRE ATT&CK.
# Intended to be expanded; not a full ATT&CK export (keeps dependency-free).
KEYWORD_TO_ATTACK: dict[str, list[MITREMapping]] = {
    "failed password": [
        MITREMapping("T1110.001", "Brute Force: Password Guessing", "Credential Access", 0.8)
    ],
    "brute force": [
        MITREMapping("T1110", "Brute Force", "Credential Access", 0.85)
    ],
    "authentication failure": [
        MITREMapping("T1110", "Brute Force", "Credential Access", 0.6)
    ],
    "invalid user": [
        MITREMapping("T1110.001", "Brute Force: Password Guessing", "Credential Access", 0.7)
    ],
    "session opened": [
        MITREMapping("T1021", "Remote Services", "Lateral Movement", 0.5)
    ],
    "sudo": [
        MITREMapping("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", 0.6)
    ],
    "cron": [
        MITREMapping("T1053.003", "Scheduled Task/Job: Cron", "Persistence", 0.5)
    ],
    "sql injection": [
        MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8)
    ],
    "xss": [
        MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", 0.7)
    ],
    "path traversal": [
        MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", 0.75)
    ],
    "rce": [
        MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9)
    ],
    "remote code execution": [
        MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9)
    ],
    "reverse shell": [
        MITREMapping("T1041", "Exfiltration Over C2 Channel", "Command and Control", 0.85)
    ],
    "beacon": [
        MITREMapping("T1071", "Application Layer Protocol", "Command and Control", 0.8)
    ],
    "mimikatz": [
        MITREMapping("T1003", "OS Credential Dumping", "Credential Access", 0.95)
    ],
    "lsass": [
        MITREMapping("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", 0.9)
    ],
    "powershell": [
        MITREMapping("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", 0.5)
    ],
    "base64": [
        MITREMapping("T1027.001", "Obfuscated Files or Information: Binary Padding", "Defense Evasion", 0.5)
    ],
}


def map_to_mitre(message: str) -> MITREMapping | None:
    """Map a log message to a MITRE ATT&CK technique via keyword matching.

    Returns the highest-confidence match, or None if no keyword matches.
    """
    lowered = message.lower()
    best: MITREMapping | None = None
    for keyword, mappings in KEYWORD_TO_ATTACK.items():
        if keyword in lowered:
            for mapping in mappings:
                if best is None or mapping.confidence > best.confidence:
                    best = mapping
    return best
