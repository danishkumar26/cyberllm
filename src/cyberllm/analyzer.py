"""Core analysis engine — orchestrates parsing, LLM analysis, enrichment, MITRE mapping."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Settings
from .enrichment import build_enricher
from .mitre import map_to_mitre
from .parsers import LogEntry, parse_file
from .providers import get_provider


@dataclass
class AnalyzedEvent:
    source: str
    severity: str
    confidence: float
    summary: str
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    indicators: list[str] = field(default_factory=list)
    remediation: str = ""
    raw_excerpt: str = ""
    provider: str = ""
    model: str = ""


class Analyzer:
    """Analyze log files end-to-end: parse → LLM → enrich → MITRE → report-ready events."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.provider = get_provider(
            settings.provider,
            settings.model,
            ollama_base_url=settings.ollama_base_url,
            openai_api_key=settings.openai_api_key,
            temperature=settings.temperature,
            max_tokens=settings.max_tokens,
        )
        self.enricher = build_enricher(
            settings.ti_providers,
            vt_api_key=settings.vt_api_key,
            abuseipdb_api_key=settings.abuseipdb_api_key,
            allow_list=settings.local_allow_list,
            block_list=settings.local_block_list,
        ) if settings.enable_ti else None

    def analyze_file(self, path: str, context: Optional[str] = None) -> list[AnalyzedEvent]:
        """Parse and analyze a single log file."""
        parser_result = parse_file(path)
        events: list[AnalyzedEvent] = []

        # Group entries into chunks to fit LLM context
        chunks = self._chunk_entries(parser_result.entries, self.settings.max_lines)
        for chunk in chunks:
            log_text = "\n".join(e.raw for e in chunk if e.raw)
            if not log_text.strip():
                continue
            event = self._analyze_text(log_text, source=path, context=context)
            events.append(event)

        # If no parseable entries but file had content, analyze raw text
        if not events and parser_result.entries == []:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            if raw.strip():
                events.append(self._analyze_text(raw, source=path, context=context))

        return events

    def analyze_text(self, text: str, source: str = "stdin", context: Optional[str] = None) -> AnalyzedEvent:
        """Analyze an arbitrary block of log text."""
        return self._analyze_text(text, source=source, context=context)

    def _chunk_entries(self, entries: list[LogEntry], max_lines: int) -> list[list[LogEntry]]:
        chunks: list[list[LogEntry]] = []
        current: list[LogEntry] = []
        count = 0
        for entry in entries:
            lines = entry.raw.count("\n") + 1 if entry.raw else 1
            if count + lines > max_lines and current:
                chunks.append(current)
                current = []
                count = 0
            current.append(entry)
            count += lines
        if current:
            chunks.append(current)
        return chunks

    def _analyze_text(self, log_text: str, source: str, context: Optional[str] = None) -> AnalyzedEvent:
        # LLM analysis
        result = self.provider.analyze(log_text)

        # MITRE mapping on LLM summary + raw text
        mitre = map_to_mitre(result.get("summary", "") + " " + log_text)
        if mitre is None:
            mitre_technique = None
            mitre_technique_name = None
            mitre_tactic = None
        else:
            mitre_technique = mitre.technique_id
            mitre_technique_name = mitre.technique_name
            mitre_tactic = mitre.tactic

        # Enrich indicators
        indicators = list(result.get("indicators", []))
        if self.enricher is not None:
            enriched: list[str] = []
            for ind in indicators:
                ti = self.enricher.enrich_ip(ind)
                if ti.malicious:
                    enriched.append(f"{ind} [MALICIOUS via {ti.source}]")
                else:
                    enriched.append(ind)
            indicators = enriched

        return AnalyzedEvent(
            source=source,
            severity=str(result.get("severity", "low")),
            confidence=float(result.get("confidence", 0.0)),
            summary=str(result.get("summary", "")),
            mitre_technique=mitre_technique,
            mitre_technique_name=mitre_technique_name,
            mitre_tactic=mitre_tactic,
            indicators=indicators,
            remediation=str(result.get("remediation", "")),
            raw_excerpt=str(result.get("raw_log_excerpt", log_text[:500])),
            provider=type(self.provider).__name__.replace("Provider", "").lower(),
            model=self.settings.model,
        )

    def store_correction(self, event: AnalyzedEvent, corrected: dict) -> None:
        """Save an analyst correction as a few-shot example (human-in-the-loop)."""
        if not self.settings.store_corrections:
            return
        corrections_dir = Path(self.settings.corrections_dir)
        corrections_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "original": {
                "summary": event.summary,
                "severity": event.severity,
                "mitre_technique": event.mitre_technique,
                "remediation": event.remediation,
            },
            "corrected": corrected,
            "source": event.source,
            "model": event.model,
        }
        out_file = corrections_dir / f"correction_{len(list(corrections_dir.glob('*.json'))) + 1}.json"
        with out_file.open("w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
