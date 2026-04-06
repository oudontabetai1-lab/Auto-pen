"""Factory function to instantiate LLM providers by name."""

from __future__ import annotations

import os
from typing import Any

from autopen.llm.base import BaseLLMProvider


def get_provider(provider: str, model: str, **kwargs: Any) -> BaseLLMProvider:
    """
    Return an LLM provider instance.

    provider: "ollama" | "openai" | "anthropic"
    model:    model name (e.g. "llama3.1", "gpt-4o", "claude-sonnet-4-6")
    kwargs:   passed through to the provider constructor
    """
    provider = provider.lower()

    if provider == "ollama":
        from autopen.llm.ollama import OllamaProvider

        return OllamaProvider(
            model=model,
            base_url=kwargs.get("base_url", "http://localhost:11434"),
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    if provider == "openai":
        from autopen.llm.openai import OpenAIProvider

        return OpenAIProvider(
            model=model,
            api_key=kwargs.get("api_key") or os.environ.get("OPENAI_API_KEY", ""),
            base_url=kwargs.get("base_url"),
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    if provider == "anthropic":
        from autopen.llm.anthropic import AnthropicProvider

        return AnthropicProvider(
            model=model,
            api_key=kwargs.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", ""),
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    raise ValueError(
        f"Unknown LLM provider '{provider}'. Supported: ollama, openai, anthropic"
    )
