"""Threat intelligence enrichment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class TIResult:
    indicator: str
    indicator_type: str  # ip, domain, hash
    malicious: bool = False
    reputation: int = 0
    source: str = ""
    details: dict = field(default_factory=dict)


class BaseEnricher:
    """Abstract base for threat-intel enrichers."""

    def enrich_ip(self, ip: str) -> TIResult:
        raise NotImplementedError

    def enrich_domain(self, domain: str) -> TIResult:
        raise NotImplementedError


class LocalListEnricher(BaseEnricher):
    """Enrich using local allow/block lists."""

    def __init__(self, allow_list: list[str], block_list: list[str]) -> None:
        self.allow_list = set(allow_list)
        self.block_list = set(block_list)

    def enrich_ip(self, ip: str) -> TIResult:
        if ip in self.block_list:
            return TIResult(ip, "ip", malicious=True, reputation=100, source="local_block_list")
        if ip in self.allow_list:
            return TIResult(ip, "ip", malicious=False, reputation=0, source="local_allow_list")
        return TIResult(ip, "ip", malicious=False, reputation=0, source="local")

    def enrich_domain(self, domain: str) -> TIResult:
        return TIResult(domain, "domain", malicious=False, reputation=0, source="local")


class VirusTotalEnricher(BaseEnricher):
    """Enrich using the VirusTotal API."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def enrich_ip(self, ip: str) -> TIResult:
        try:
            resp = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
                timeout=20,
            )
            if resp.status_code == 404:
                return TIResult(ip, "ip", malicious=False, reputation=0, source="virustotal")
            resp.raise_for_status()
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            return TIResult(
                ip,
                "ip",
                malicious=malicious,
                reputation=stats.get("malicious", 0),
                source="virustotal",
                details={
                    "harmless": stats.get("harmless", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"),
                },
            )
        except requests.RequestException:
            return TIResult(ip, "ip", malicious=False, reputation=0, source="virustotal_error")

    def enrich_domain(self, domain: str) -> TIResult:
        try:
            resp = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers={"x-apikey": self.api_key},
                timeout=20,
            )
            if resp.status_code == 404:
                return TIResult(domain, "domain", malicious=False, reputation=0, source="virustotal")
            resp.raise_for_status()
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            return TIResult(
                domain,
                "domain",
                malicious=malicious,
                reputation=stats.get("malicious", 0),
                source="virustotal",
                details={
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                },
            )
        except requests.RequestException:
            return TIResult(domain, "domain", malicious=False, reputation=0, source="virustotal_error")


def build_enricher(
    providers: list[str],
    *,
    vt_api_key: Optional[str] = None,
    abuseipdb_api_key: Optional[str] = None,
    allow_list: list[str] | None = None,
    block_list: list[str] | None = None,
) -> BaseEnricher:
    """Build an enricher chain. Local list is always applied; VT/AbuseIPDB layered on top."""
    enrichers: list[BaseEnricher] = [
        LocalListEnricher(allow_list or [], block_list or [])
    ]
    if "virustotal" in providers and vt_api_key:
        enrichers.append(VirusTotalEnricher(vt_api_key))
    # Chain: return the last enricher that has a non-local result when available
    if len(enrichers) == 1:
        return enrichers[0]
    return _ChainEnricher(enrichers)


class _ChainEnricher(BaseEnricher):
    def __init__(self, enrichers: list[BaseEnricher]) -> None:
        self.enrichers = enrichers

    def enrich_ip(self, ip: str) -> TIResult:
        result = self.enrichers[0].enrich_ip(ip)
        for enricher in self.enrichers[1:]:
            sub = enricher.enrich_ip(ip)
            if sub.source not in ("local", "virustotal_error"):
                result = sub
        return result

    def enrich_domain(self, domain: str) -> TIResult:
        result = self.enrichers[0].enrich_domain(domain)
        for enricher in self.enrichers[1:]:
            sub = enricher.enrich_domain(domain)
            if sub.source not in ("local", "virustotal_error"):
                result = sub
        return result
