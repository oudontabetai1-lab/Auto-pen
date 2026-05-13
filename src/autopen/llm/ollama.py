"""Ollama LLM backend (local, privacy-preserving default)."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

from autopen.llm.base import BaseLLMProvider, LLMMessage, LLMResponse, ToolCall


class OllamaProvider(BaseLLMProvider):
    name = "ollama"

    def __init__(
        self,
        model: str = "llama3.1",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature

    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system_prompt: str,
    ) -> LLMResponse:
        payload = self._build_payload(messages, tools, system_prompt)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError as exc:
            raise RuntimeError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Is the Ollama server running? Try: ollama serve"
            ) from exc
        except httpx.TimeoutException as exc:
            raise RuntimeError(
                f"Ollama request timed out after {self.timeout}s. "
                "The model may be loading or the request is too large."
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"Ollama API error {exc.response.status_code}: {exc.response.text[:200]}"
            ) from exc

        return self._parse_response(data)

    def _build_payload(self, messages, tools, system_prompt):
        ollama_messages = [{"role": "system", "content": system_prompt}]
        for m in messages:
            if m.role == "assistant" and m.tool_calls:
                ollama_messages.append({
                    "role": "assistant", "content": m.content or "",
                    "tool_calls": [
                        {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": tc.arguments}}
                        for tc in m.tool_calls
                    ],
                })
            elif m.role == "tool":
                ollama_messages.append({"role": "tool", "content": m.content or ""})
            else:
                ollama_messages.append({"role": m.role, "content": m.content or ""})
        return {"model": self.model, "messages": ollama_messages, "tools": tools, "stream": False, "options": {"temperature": self.temperature}}

    def _parse_response(self, data: dict[str, Any]) -> LLMResponse:
        message = data.get("message", {})
        content = message.get("content") or None
        raw_tool_calls = message.get("tool_calls") or []
        tool_calls: list[ToolCall] = []
        for tc in raw_tool_calls:
            func = tc.get("function", {})
            args = func.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"raw": args}
            tool_calls.append(ToolCall(id=tc.get("id") or str(uuid.uuid4()), name=func.get("name", ""), arguments=args))
        return LLMResponse(
            content=content, tool_calls=tool_calls, model=data.get("model", self.model),
            prompt_tokens=data.get("prompt_eval_count", 0), completion_tokens=data.get("eval_count", 0),
        )
