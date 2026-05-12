"""Anthropic Claude LLM backend."""

from __future__ import annotations

import uuid
from typing import Any

from autopen.llm.base import BaseLLMProvider, LLMMessage, LLMResponse, ToolCall


class AnthropicProvider(BaseLLMProvider):
    """
    Uses the anthropic Python SDK (tool_use API).

    Recommended models: claude-opus-4-6, claude-sonnet-4-6
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        api_key: str = "",
        timeout: float = 120.0,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic package is not installed. Run: pip install anthropic"
            ) from e

        client = anthropic.AsyncAnthropic(api_key=self.api_key, timeout=self.timeout)

        # Convert to Anthropic message format (no system in messages list)
        ant_messages = self._convert_messages(messages)

        # Convert tool schemas to Anthropic format
        ant_tools = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {}),
            }
            for t in tools
        ]

        try:
            response = await client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_prompt,
                messages=ant_messages,
                tools=ant_tools if ant_tools else anthropic.NOT_GIVEN,  # type: ignore[arg-type]
                temperature=self.temperature,
            )
        except Exception as exc:
            cls_name = type(exc).__name__
            raise RuntimeError(f"Anthropic API error ({cls_name}): {exc}") from exc

        content_text = None
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                content_text = block.text
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id or str(uuid.uuid4()),
                        name=block.name,
                        arguments=block.input if isinstance(block.input, dict) else {},
                    )
                )

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            model=self.model,
            prompt_tokens=response.usage.input_tokens if response.usage else 0,
            completion_tokens=response.usage.output_tokens if response.usage else 0,
        )

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, Any]]:
        """Convert to Anthropic's message format."""
        result = []
        for m in messages:
            if m.role == "system":
                continue  # handled as top-level system param
            if m.role == "assistant" and m.tool_calls:
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    )
                result.append({"role": "assistant", "content": blocks})
            elif m.role == "tool":
                result.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.tool_call_id or "",
                                "content": m.content or "",
                            }
                        ],
                    }
                )
            else:
                result.append({"role": m.role, "content": m.content or ""})
        return result
