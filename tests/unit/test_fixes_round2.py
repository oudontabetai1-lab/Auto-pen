"""Tests covering round-2 bug fixes: sqlmap success flag, scope wildcard, ollama errors, LLM factory."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# sqlmap success flag
# ---------------------------------------------------------------------------

class TestSqlmapSuccessFlag:
    def _make_tool(self):
        from autopen.tools.sqlmap import SqlmapTool
        return SqlmapTool()

    async def test_success_false_when_rc_nonzero(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", "", 1))):
            result = await tool.execute({"url": "http://example.com/page?id=1"})
        assert result.success is False

    async def test_success_true_when_rc_zero(self):
        tool = self._make_tool()
        out = "not injectable"
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(out, "", 0))):
            result = await tool.execute({"url": "http://example.com/page?id=1"})
        assert result.success is True

    async def test_injectable_flag_in_metadata(self):
        tool = self._make_tool()
        out = "parameter 'id' is vulnerable"
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(out, "", 0))):
            result = await tool.execute({"url": "http://example.com/page?id=1"})
        assert result.metadata["injectable"] is True

    async def test_not_injectable_flag_in_metadata(self):
        tool = self._make_tool()
        out = "all tested parameters do not appear to be injectable"
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(out, "", 0))):
            result = await tool.execute({"url": "http://example.com/page?id=1"})
        assert result.metadata["injectable"] is False


# ---------------------------------------------------------------------------
# Scope wildcard domain matching
# ---------------------------------------------------------------------------

class TestScopeWildcardFixed:
    def _validator(self, *allowed):
        from autopen.security.scope import ScopeValidator
        from autopen.state.models import ScopeConfig
        return ScopeValidator(ScopeConfig(allowed_hosts=list(allowed)))

    def test_wildcard_does_not_match_root_domain(self):
        v = self._validator("*.example.com")
        assert v.validate("example.com") is False

    def test_wildcard_matches_subdomain(self):
        v = self._validator("*.example.com")
        assert v.validate("sub.example.com") is True
        assert v.validate("api.example.com") is True

    def test_wildcard_does_not_match_sibling(self):
        v = self._validator("*.example.com")
        assert v.validate("other.com") is False

    def test_exact_domain_still_matches_itself(self):
        v = self._validator("example.com")
        assert v.validate("example.com") is True

    def test_explicit_root_plus_wildcard(self):
        v = self._validator("example.com", "*.example.com")
        assert v.validate("example.com") is True
        assert v.validate("sub.example.com") is True


# ---------------------------------------------------------------------------
# Ollama error handling
# ---------------------------------------------------------------------------

class TestOllamaErrorHandling:
    def _make_provider(self):
        from autopen.llm.ollama import OllamaProvider
        return OllamaProvider(model="llama3.1", base_url="http://localhost:11434")

    async def test_connect_error_raises_runtime_error(self):
        import httpx
        provider = self._make_provider()
        with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("refused")):
            with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
                await provider.chat_with_tools([], [], "sys")

    async def test_timeout_raises_runtime_error(self):
        import httpx
        provider = self._make_provider()
        with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("timeout")):
            with pytest.raises(RuntimeError, match="timed out"):
                await provider.chat_with_tools([], [], "sys")

    async def test_http_status_error_raises_runtime_error(self):
        import httpx
        provider = self._make_provider()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "model not found"
        err = httpx.HTTPStatusError("404", request=MagicMock(), response=mock_response)
        with patch("httpx.AsyncClient.post", side_effect=err):
            with pytest.raises(RuntimeError, match="404"):
                await provider.chat_with_tools([], [], "sys")


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

class TestLLMFactory:
    def test_ollama_provider_returned(self):
        from autopen.llm.factory import get_provider
        from autopen.llm.ollama import OllamaProvider
        p = get_provider("ollama", "llama3.1")
        assert isinstance(p, OllamaProvider)
        assert p.model == "llama3.1"

    def test_openai_provider_returned(self):
        from autopen.llm.factory import get_provider
        from autopen.llm.openai import OpenAIProvider
        p = get_provider("openai", "gpt-4o", api_key="test-key")
        assert isinstance(p, OpenAIProvider)
        assert p.model == "gpt-4o"

    def test_anthropic_provider_returned(self):
        from autopen.llm.factory import get_provider
        from autopen.llm.anthropic import AnthropicProvider
        p = get_provider("anthropic", "claude-opus-4-7", api_key="test-key")
        assert isinstance(p, AnthropicProvider)

    def test_unknown_provider_raises_value_error(self):
        from autopen.llm.factory import get_provider
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            get_provider("gemini", "gemini-pro")

    def test_provider_name_case_insensitive(self):
        from autopen.llm.factory import get_provider
        from autopen.llm.ollama import OllamaProvider
        p = get_provider("OLLAMA", "llama3.1")
        assert isinstance(p, OllamaProvider)

    def test_kwargs_passed_to_ollama(self):
        from autopen.llm.factory import get_provider
        p = get_provider("ollama", "llama3.1", base_url="http://custom:11434", timeout=60.0)
        assert p.base_url == "http://custom:11434"
        assert p.timeout == 60.0
