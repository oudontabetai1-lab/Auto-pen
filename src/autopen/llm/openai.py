"""OpenAI-compatible LLM backend (also works with LM Studio, vLLM, etc.)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from autopen.llm.base import BaseLLMProvider, LLMMessage, LLMResponse, ToolCall


class OpenAIProvider(BaseLLMProvider):
    """
    Uses the openai Python SDK.

    Compatible with any OpenAI-format API:
    - OpenAI (gpt-4o, gpt-4o-mini)
    - LM Studio (http://localhost:1234/v1)
    - vLLM, LocalAI, etc.
    """

    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str = "",
        base_url: str | None = None,
        timeout: float = 120.0,
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.temperature = temperature

    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError as e:
            raise RuntimeError("openai package is not installed. Run: pip install openai") from e

        client = AsyncOpenAI(
            api_key=self.api_key or "no-key",
            base_url=self.base_url,
            timeout=self.timeout,
        )

        oai_messages = self.build_openai_messages(messages, system_prompt)

        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=oai_messages,  # type: ignore[arg-type]
                tools=[{"type": "function", "function": t} for t in tools] if tools else None,  # type: ignore[arg-type]
                temperature=self.temperature,
            )
        except Exception as exc:
            cls_name = type(exc).__name__
            raise RuntimeError(f"OpenAI API error ({cls_name}): {exc}") from exc

        choice = response.choices[0]
        msg = choice.message
        content = msg.content or None

        tool_calls: list[ToolCall] = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                args: Any = tc.function.arguments
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {"raw": args}
                tool_calls.append(
                    ToolCall(id=tc.id or str(uuid.uuid4()), name=tc.function.name, arguments=args)
                )

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
        )
