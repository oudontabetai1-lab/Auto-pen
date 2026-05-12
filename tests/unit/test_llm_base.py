"""Unit tests for LLM base provider utilities."""

from __future__ import annotations

import json
import pytest

from autopen.llm.base import LLMMessage, ToolCall


class TestBuildOpenAIMessages:
    def _make_provider(self):
        from autopen.llm.base import BaseLLMProvider
        class _Concrete(BaseLLMProvider):
            name = "test"
            async def chat_with_tools(self, messages, tools, system_prompt):  # pragma: no cover
                pass
        return _Concrete()

    def test_system_prepended(self):
        p = self._make_provider()
        result = p.build_openai_messages([], "be helpful")
        assert result[0] == {"role": "system", "content": "be helpful"}

    def test_tool_call_arguments_are_valid_json(self):
        """tool_call arguments must be serialized with json.dumps, not str()."""
        p = self._make_provider()
        msg = LLMMessage(
            role="assistant",
            content="thinking",
            tool_calls=[
                ToolCall(id="tc1", name="nmap", arguments={"target": "10.0.0.1", "ports": [22, 80]})
            ],
        )
        result = p.build_openai_messages([msg], "sys")
        # Find the assistant message
        asst = next(m for m in result if m["role"] == "assistant")
        raw_args = asst["tool_calls"][0]["function"]["arguments"]
        # Must be parseable as JSON (not Python repr like "{'target': '10.0.0.1'}")
        parsed = json.loads(raw_args)
        assert parsed["target"] == "10.0.0.1"
        assert parsed["ports"] == [22, 80]

    def test_tool_call_arguments_not_python_repr(self):
        """Confirm single-quoted Python dict repr is NOT produced."""
        p = self._make_provider()
        msg = LLMMessage(
            role="assistant",
            tool_calls=[ToolCall(id="tc1", name="foo", arguments={"key": "value"})],
        )
        result = p.build_openai_messages([msg], "sys")
        asst = next(m for m in result if m["role"] == "assistant")
        raw_args = asst["tool_calls"][0]["function"]["arguments"]
        assert "'" not in raw_args, "Arguments must not contain Python single-quote repr"

    def test_tool_result_message(self):
        p = self._make_provider()
        msg = LLMMessage(role="tool", tool_call_id="tc1", content="scan complete")
        result = p.build_openai_messages([msg], "sys")
        tool_msg = next(m for m in result if m["role"] == "tool")
        assert tool_msg["tool_call_id"] == "tc1"
        assert tool_msg["content"] == "scan complete"

    def test_user_message(self):
        p = self._make_provider()
        msg = LLMMessage(role="user", content="start scan")
        result = p.build_openai_messages([msg], "sys")
        user_msg = next(m for m in result if m["role"] == "user")
        assert user_msg["content"] == "start scan"

    def test_empty_tool_calls_list(self):
        p = self._make_provider()
        result = p.build_openai_messages([], "sys")
        assert len(result) == 1  # just system
