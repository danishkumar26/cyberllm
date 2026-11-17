"""LLM provider factory."""

from __future__ import annotations

from typing import Optional

from .base import (
    AnalysisResult,
    BaseProvider,
    OllamaProvider,
    OpenAIProvider,
)


def get_provider(
    provider: str,
    model: str,
    *,
    ollama_base_url: str = "http://localhost:11434",
    openai_api_key: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 1000,
) -> BaseProvider:
    """Factory: return a configured LLM provider instance."""
    provider = provider.lower()
    if provider == "ollama":
        return OllamaProvider(
            model=model,
            base_url=ollama_base_url,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    if provider == "openai":
        return OpenAIProvider(
            model=model,
            api_key=openai_api_key,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    raise ValueError(f"Unknown provider: {provider!r}. Use 'ollama' or 'openai'.")


__all__ = [
    "AnalysisResult",
    "BaseProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "get_provider",
]
