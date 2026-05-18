"""Factory function to instantiate LLM providers by name."""

from __future__ import annotations

import os
from typing import Any

from autopen.llm.base import BaseLLMProvider


class LLMConfigError(ValueError):
    """Raised when an LLM provider is selected but mis-configured (e.g. missing API key)."""


def _require_env(name: str, provider: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise LLMConfigError(
            f"{provider} provider selected but environment variable {name} is empty. "
            f"Export {name} or pass api_key=… to get_provider()."
        )
    return val


def get_provider(provider: str, model: str, **kwargs: Any) -> BaseLLMProvider:
    """
    Return an LLM provider instance.

    provider: "ollama" | "openai" | "anthropic"
    model:    model name (e.g. "llama3.1", "gpt-4o", "claude-sonnet-4-6")
    kwargs:   passed through to the provider constructor

    Raises LLMConfigError when a cloud provider is selected without a key.
    """
    provider = provider.lower()

    if provider == "ollama":
        from autopen.llm.ollama import OllamaProvider

        return OllamaProvider(
            model=model,
            base_url=kwargs.get("base_url") or "http://localhost:11434",
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    if provider == "openai":
        from autopen.llm.openai import OpenAIProvider

        api_key = kwargs.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
        # Allow empty api_key only when an explicit base_url is provided
        # (LM Studio / vLLM / LocalAI generally don't require one).
        base_url = kwargs.get("base_url")
        if not api_key and not base_url:
            raise LLMConfigError(
                "openai provider requires OPENAI_API_KEY (or api_key=…) when no base_url is set. "
                "For local OpenAI-compatible servers, pass base_url=http://…"
            )
        return OpenAIProvider(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    if provider == "anthropic":
        from autopen.llm.anthropic import AnthropicProvider

        api_key = kwargs.get("api_key") or _require_env("ANTHROPIC_API_KEY", "anthropic")
        return AnthropicProvider(
            model=model,
            api_key=api_key,
            timeout=kwargs.get("timeout", 120.0),
            temperature=kwargs.get("temperature", 0.1),
        )

    raise ValueError(
        f"Unknown LLM provider '{provider}'. Supported: ollama, openai, anthropic"
    )
