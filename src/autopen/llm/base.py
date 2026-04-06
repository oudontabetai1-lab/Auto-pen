"""Abstract base for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel


class ToolCall(BaseModel):
    """A tool invocation requested by the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


class LLMMessage(BaseModel):
    """A single message in the conversation."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] | None = None  # for role=assistant
    tool_call_id: str | None = None           # for role=tool


class LLMResponse(BaseModel):
    """Response from the LLM."""

    content: str | None = None
    tool_calls: list[ToolCall] = []
    reasoning: str | None = None             # chain-of-thought if available
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0


class BaseLLMProvider(ABC):
    """Abstract interface that every LLM backend must implement."""

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
        """Convert LLMMessage list to OpenAI-compatible message dicts."""
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
                                    "arguments": str(tc.arguments),
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
