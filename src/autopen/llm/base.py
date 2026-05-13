"""Abstract base for LLM providers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any]


class LLMMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None


class LLMResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = []
    reasoning: str | None = None
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0


class BaseLLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        """Send messages + available tools to the LLM and return its response."""

    def build_openai_messages(
        self, messages: list[LLMMessage], system_prompt: str
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        for m in messages:
            if m.role == "assistant" and m.tool_calls:
                result.append(
                    {
                        "role": "assistant",
                        "content": m.content or "",
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments),
                                },
                            }
                            for tc in m.tool_calls
                        ],
                    }
                )
            elif m.role == "tool":
                result.append(
                    {
                        "role": "tool",
                        "tool_call_id": m.tool_call_id or "",
                        "content": m.content or "",
                    }
                )
            else:
                result.append({"role": m.role, "content": m.content or ""})
        return result
