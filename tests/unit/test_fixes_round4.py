"""Tests covering round-4 fixes: OpenAI/Anthropic error wrapping, ConfirmationBroker."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# OpenAI provider error handling
# ---------------------------------------------------------------------------

class TestOpenAIErrorHandling:
    def _make_provider(self):
        from autopen.llm.openai import OpenAIProvider
        return OpenAIProvider(model="gpt-4o", api_key="test-key")

    async def test_api_error_raises_runtime_error(self):
        provider = self._make_provider()

        class FakeAuthError(Exception):
            pass

        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(
                side_effect=FakeAuthError("Invalid API key")
            )
            mock_cls.return_value = mock_client

            with pytest.raises(RuntimeError, match="OpenAI API error"):
                await provider.chat_with_tools([], [], "sys")

    async def test_missing_openai_package_raises_runtime_error(self):
        provider = self._make_provider()
        import sys
        original = sys.modules.get("openai")
        sys.modules["openai"] = None  # type: ignore
        try:
            with pytest.raises(RuntimeError, match="openai package is not installed"):
                await provider.chat_with_tools([], [], "sys")
        finally:
            if original is not None:
                sys.modules["openai"] = original
            else:
                del sys.modules["openai"]

    async def test_arguments_are_json_strings_in_messages(self):
        """build_openai_messages now always produces JSON-string arguments; no dict workaround needed."""
        import json
        from autopen.llm.base import LLMMessage, ToolCall
        from autopen.llm.openai import OpenAIProvider

        provider = OpenAIProvider()
        msg = LLMMessage(
            role="assistant",
            content="thinking",
            tool_calls=[ToolCall(id="tc1", name="nmap", arguments={"target": "10.0.0.1"})],
        )
        built = provider.build_openai_messages([msg], "sys")
        asst = next(m for m in built if m["role"] == "assistant")
        raw_args = asst["tool_calls"][0]["function"]["arguments"]
        assert isinstance(raw_args, str)
        assert json.loads(raw_args)["target"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Anthropic provider error handling
# ---------------------------------------------------------------------------

class TestAnthropicErrorHandling:
    def _make_provider(self):
        from autopen.llm.anthropic import AnthropicProvider
        return AnthropicProvider(model="claude-sonnet-4-6", api_key="test-key")

    async def test_api_error_raises_runtime_error(self):
        provider = self._make_provider()

        class FakeRateLimitError(Exception):
            pass

        with patch("anthropic.AsyncAnthropic") as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create = AsyncMock(
                side_effect=FakeRateLimitError("Rate limit exceeded")
            )
            mock_cls.return_value = mock_client

            with pytest.raises(RuntimeError, match="Anthropic API error"):
                await provider.chat_with_tools([], [], "sys")

    async def test_missing_anthropic_package_raises_runtime_error(self):
        provider = self._make_provider()
        import sys
        original = sys.modules.get("anthropic")
        sys.modules["anthropic"] = None  # type: ignore
        try:
            with pytest.raises(RuntimeError, match="anthropic package is not installed"):
                await provider.chat_with_tools([], [], "sys")
        finally:
            if original is not None:
                sys.modules["anthropic"] = original
            else:
                del sys.modules["anthropic"]


# ---------------------------------------------------------------------------
# ConfirmationBroker
# ---------------------------------------------------------------------------

class TestConfirmationBroker:
    def test_create_returns_pending_confirmation(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create(timeout=10.0)
        assert pc.request_id is not None
        assert pc.timeout == 10.0

    def test_resolve_approves_and_removes(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create()
        result = broker.resolve(pc.request_id, approved=True)
        assert result is True
        assert pc.request_id not in broker._pending

    def test_resolve_denies_correctly(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create()
        broker.resolve(pc.request_id, approved=False)
        assert pc._approved is False

    def test_resolve_unknown_id_returns_false(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        result = broker.resolve("nonexistent-id", approved=True)
        assert result is False

    def test_cancel_all_denies_all_pending(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc1 = broker.create()
        pc2 = broker.create()
        broker.cancel_all()
        assert pc1._approved is False
        assert pc2._approved is False
        assert len(broker._pending) == 0

    async def test_wait_returns_true_when_approved(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create(timeout=5.0)

        async def _approve():
            await asyncio.sleep(0.01)
            broker.resolve(pc.request_id, True)

        asyncio.create_task(_approve())
        result = await pc.wait()
        assert result is True

    async def test_wait_returns_false_when_denied(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create(timeout=5.0)

        async def _deny():
            await asyncio.sleep(0.01)
            broker.resolve(pc.request_id, False)

        asyncio.create_task(_deny())
        result = await pc.wait()
        assert result is False

    async def test_wait_times_out_and_returns_false(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create(timeout=0.05)  # very short timeout
        result = await pc.wait()
        assert result is False

    def test_custom_request_id_is_used(self):
        from autopen.security.confirm import ConfirmationBroker
        broker = ConfirmationBroker()
        pc = broker.create(request_id="my-request-id")
        assert pc.request_id == "my-request-id"
        assert "my-request-id" in broker._pending
