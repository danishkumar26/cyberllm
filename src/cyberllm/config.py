"""Application settings — environment variables + YAML config."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class Settings:
    """Runtime configuration for CyberLLM.

    Precedence: environment variable > config.yaml > defaults.
    """

    # LLM provider
    provider: str = "ollama"
    model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 1000

    # Analysis
    max_lines: int = 200
    enable_mitre: bool = True
    enable_ti: bool = False

    # Threat intel
    ti_providers: list[str] = field(default_factory=lambda: ["local"])
    vt_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    local_allow_list: list[str] = field(default_factory=list)
    local_block_list: list[str] = field(default_factory=list)

    # Reporting
    default_format: str = "markdown"
    output_dir: str = "./reports"

    # Parsers
    parsers: list[str] = field(default_factory=lambda: ["syslog", "json", "apache", "windows_event"])

    # Human-in-the-loop
    store_corrections: bool = True
    corrections_dir: str = "./data/corrections"

    @classmethod
    def load(cls, config_path: Optional[str | Path] = None) -> "Settings":
        """Load settings from config.yaml (if present) and environment."""
        data: dict[str, Any] = {}

        # 1) config.yaml
        candidate_paths = [
            config_path,
            Path("config.yaml"),
            Path.home() / ".config" / "cyberllm" / "config.yaml",
        ]
        for path in candidate_paths:
            if path is None:
                continue
            p = Path(path)
            if p.exists():
                with p.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                break

        data = data or {}

        def env(key: str, default: Any = None) -> Any:
            return os.environ.get(key, default)

        # 2) environment overrides (prefix CYBERLLM_ or direct)
        def _get_env(key: str, default: Any) -> Any:
            return os.environ.get(f"CYBERLLM_{key}", os.environ.get(key, default))

        return cls(
            provider=_get_env("PROVIDER", data.get("provider", "ollama")),
            model=_get_env("MODEL", data.get("model", "llama3.2")),
            ollama_base_url=_get_env(
                "OLLAMA_BASE_URL", data.get("ollama_base_url", "http://localhost:11434")
            ),
            openai_api_key=env("OPENAI_API_KEY") or data.get("openai_api_key"),
            temperature=float(_get_env("TEMPERATURE", data.get("temperature", 0.1))),
            max_tokens=int(_get_env("MAX_TOKENS", data.get("max_tokens", 1000))),
            max_lines=int(_get_env("MAX_LINES", data.get("max_lines", 200))),
            enable_mitre=_get_env("ENABLE_MITRE", data.get("enable_mitre", True))
            not in (False, "false", "False", 0, "0"),
            enable_ti=_get_env("ENABLE_TI", data.get("enable_ti", False))
            in (True, "true", "True", 1, "1"),
            ti_providers=data.get("ti_providers", ["local"]),
            vt_api_key=env("VT_API_KEY") or data.get("vt_api_key"),
            abuseipdb_api_key=env("ABUSEIPDB_API_KEY") or data.get("abuseipdb_api_key"),
            local_allow_list=data.get("local_allow_list", []),
            local_block_list=data.get("local_block_list", []),
            default_format=_get_env("DEFAULT_FORMAT", data.get("default_format", "markdown")),
            output_dir=_get_env("OUTPUT_DIR", data.get("output_dir", "./reports")),
            parsers=data.get(
                "parsers", ["syslog", "json", "apache", "windows_event"]
            ),
            store_corrections=_get_env(
                "STORE_CORRECTIONS", data.get("store_corrections", True)
            )
            not in (False, "false", "False", 0, "0"),
            corrections_dir=_get_env(
                "CORRECTIONS_DIR", data.get("corrections_dir", "./data/corrections")
            ),
        )


def get_settings() -> Settings:
    """Convenience: load and return a Settings instance."""
    return Settings.load()
