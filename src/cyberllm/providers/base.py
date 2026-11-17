"""LLM provider abstractions for CyberLLM analysis."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests


class AnalysisResult(dict):
    """Structured output from an LLM security analysis.

    Expected fields:
        summary: human-readable one-paragraph summary
        severity: low | medium | high | critical
        confidence: 0.0 - 1.0
        mitre_technique: optional MITRE ATT&CK technique ID (e.g. T1110)
        mitre_tactic: optional MITRE tactic (e.g. Credential Access)
        indicators: list of extracted IOCs (IPs, domains, hashes)
        remediation: recommended action
        raw_log_excerpt: the log lines that triggered the finding
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            {
                "summary": "",
                "severity": "low",
                "confidence": 0.0,
                "mitre_technique": None,
                "mitre_tactic": None,
                "indicators": [],
                "remediation": "",
                "raw_log_excerpt": "",
            }
        )
        self.update(kwargs)


class BaseProvider(ABC):
    """Abstract base for LLM providers."""

    def __init__(self, model: str, temperature: float = 0.1, max_tokens: int = 1000) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    @abstractmethod
    def analyze(self, prompt: str) -> AnalysisResult:
        """Send a prompt to the LLM and return a parsed AnalysisResult."""
        raise NotImplementedError

    @staticmethod
    def _build_prompt(log_text: str, context: Optional[str] = None) -> str:
        """Build the analysis prompt given raw log text."""
        ctx = f"\nAdditional context: {context}\n" if context else ""
        return f"""You are a senior cybersecurity analyst. Analyze the following security log
entries and return a SINGLE valid JSON object with these exact keys:

{{
  "summary": "one-paragraph human-readable summary",
  "severity": "low | medium | high | critical",
  "confidence": 0.0 to 1.0,
  "mitre_technique": "MITRE ATT&CK technique ID (e.g. T1110) or null",
  "mitre_tactic": "MITRE tactic name (e.g. Credential Access) or null",
  "indicators": ["list of extracted IOCs: IPs, domains, file hashes"],
  "remediation": "recommended remediation action",
  "raw_log_excerpt": "the most relevant log lines (verbatim)"
}}

Respond ONLY with the JSON object. No markdown fences, no extra text.{ctx}

LOG ENTRIES:
{log_text}
"""

    @staticmethod
    def _parse_json(raw: str) -> AnalysisResult:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    data = json.loads(raw[start : end + 1])
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}
        return AnalysisResult(**data)


class OllamaProvider(BaseProvider):
    """Local Ollama provider — no API key required."""

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        max_tokens: int = 1000,
    ) -> None:
        super().__init__(model, temperature, max_tokens)
        self.base_url = base_url.rstrip("/")

    def analyze(self, prompt: str) -> AnalysisResult:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
            "format": "json",
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,  # type: ignore[arg-type]
                timeout=120,
            )
            resp.raise_for_status()
        except requests.RequestException:  # pragma: no cover - network
            return AnalysisResult(
                summary="Ollama request failed: connection error",
                severity="low",
                confidence=0.0,
                remediation="Verify Ollama is running at {self.base_url}",
            )

        raw = resp.json().get("response", "{}")
        return self._parse_json(raw)


class OpenAIProvider(BaseProvider):
    """OpenAI-compatible API provider."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 1000,
    ) -> None:
        super().__init__(model, temperature, max_tokens)
        self.api_key = api_key
        self.base_url = base_url or "https://api.openai.com/v1"

    def analyze(self, prompt: str) -> AnalysisResult:
        if not self.api_key:
            return AnalysisResult(
                summary="OpenAI API key not configured",
                severity="low",
                confidence=0.0,
                remediation="Set OPENAI_API_KEY in your environment",
            )
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity analyst. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,  # type: ignore[arg-type]
                headers=headers,
                timeout=120,
            )
            resp.raise_for_status()
        except requests.RequestException:  # pragma: no cover - network
            return AnalysisResult(
                summary="OpenAI request failed: connection error",
                severity="low",
                confidence=0.0,
                remediation="Check your network and API key",
            )

        raw = resp.json()["choices"][0]["message"]["content"]
        return BaseProvider._parse_json(raw)
