"""Round-6 bug fix tests: gobuster failure gate, nmap parse_error, openai JSON decode."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# gobuster — failure gate (rc != 0, no stdout → success=False)
# ---------------------------------------------------------------------------

class TestGobusterFailureGate:
    def _make_tool(self):
        from autopen.tools.gobuster import GobusterTool
        return GobusterTool()

    async def test_success_false_when_rc_nonzero_no_stdout(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", "binary not found", 127))):
            result = await tool.execute({"target": "http://example.com"})
        assert result.success is False

    async def test_error_message_included_in_output(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", "connection refused", 1))):
            result = await tool.execute({"target": "http://example.com"})
        assert "gobuster failed" in result.output

    async def test_success_true_when_rc_nonzero_but_has_stdout(self):
        """Gobuster may exit non-zero but still produce useful output (partial scan)."""
        stdout = "/admin  [Status: 200]\n/login  [Status: 301]\n"
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(stdout, "", 1))):
            result = await tool.execute({"target": "http://example.com"})
        assert result.success is True

    async def test_success_true_when_rc_zero_no_results(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", "", 0))):
            result = await tool.execute({"target": "http://example.com"})
        assert result.success is True

    async def test_error_stored_in_result_error_field(self):
        tool = self._make_tool()
        err = "No such file or directory"
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", err, 2))):
            result = await tool.execute({"target": "http://example.com"})
        assert result.error == err


# ---------------------------------------------------------------------------
# nmap — parse_error → success=False
# ---------------------------------------------------------------------------

class TestNmapParseError:
    def _make_tool(self):
        from autopen.tools.nmap import NmapTool
        return NmapTool()

    async def test_success_false_when_xml_is_malformed(self):
        tool = self._make_tool()
        bad_xml = "<<not valid xml>>"
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(bad_xml, "", 0))):
            result = await tool.execute({"target": "192.168.1.1"})
        assert result.success is False

    async def test_error_message_on_parse_failure(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("bad xml", "", 0))):
            result = await tool.execute({"target": "192.168.1.1"})
        assert "parse" in result.output.lower() or "failed" in result.output.lower()

    async def test_parse_error_flag_in_metadata(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("not-xml", "", 0))):
            result = await tool.execute({"target": "192.168.1.1"})
        assert result.metadata.get("parse_error") is True

    async def test_success_true_when_xml_valid(self):
        tool = self._make_tool()
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"192.168.1.1\" addrtype=\"ipv4\"/>
    <ports>
      <port protocol=\"tcp\" portid=\"80\">
        <state state=\"open\"/>
        <service name=\"http\"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(xml, "", 0))):
            result = await tool.execute({"target": "192.168.1.1"})
        assert result.success is True
        assert result.metadata.get("parse_error") is None

    async def test_success_false_when_rc_nonzero_no_stdout(self):
        tool = self._make_tool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=("", "nmap: not found", 127))):
            result = await tool.execute({"target": "192.168.1.1"})
        assert result.success is False


# ---------------------------------------------------------------------------
# nmap — portid ValueError safety
# ---------------------------------------------------------------------------

class TestNmapPortParsing:
    def _make_tool(self):
        from autopen.tools.nmap import NmapTool
        return NmapTool()

    def test_nonnumeric_portid_does_not_raise(self):
        from autopen.tools.nmap import NmapTool
        tool = NmapTool()
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>
    <ports>
      <port protocol=\"tcp\" portid=\"abc\">
        <state state=\"open\"/>
        <service name=\"http\"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        parsed = tool._parse_xml(xml)
        assert isinstance(parsed, dict)

    def test_missing_portid_defaults_to_zero(self):
        from autopen.tools.nmap import NmapTool
        tool = NmapTool()
        xml = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>
    <ports>
      <port protocol=\"tcp\">
        <state state=\"open\"/>
        <service name=\"http\"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        parsed = tool._parse_xml(xml)
        assert parsed["hosts"][0]["ports"][0]["port"] == 0


# ---------------------------------------------------------------------------
# OpenAI — JSON decode error → empty dict instead of {"raw": ...}
# ---------------------------------------------------------------------------

class TestOpenAIJsonDecodeError:
    def _make_provider(self):
        from autopen.llm.openai import OpenAIProvider
        return OpenAIProvider(model="gpt-4o", api_key="test-key")

    async def test_malformed_json_args_become_empty_dict(self):
        """When tool call args are not valid JSON, arguments should be {} not {"raw": ...}."""
        from unittest.mock import MagicMock, AsyncMock
        provider = self._make_provider()

        mock_tc = MagicMock()
        mock_tc.id = "call_123"
        mock_tc.function.name = "nmap"
        mock_tc.function.arguments = "{not: valid json}"

        mock_msg = MagicMock()
        mock_msg.content = None
        mock_msg.tool_calls = [mock_tc]

        mock_choice = MagicMock()
        mock_choice.message = mock_msg

        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 10
        mock_usage.completion_tokens = 5

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.model = "gpt-4o"
        mock_response.usage = mock_usage

        with patch("openai.AsyncOpenAI") as MockClient:
            instance = MockClient.return_value
            instance.chat.completions.create = AsyncMock(return_value=mock_response)
            result = await provider.chat_with_tools([], [], "sys")

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].arguments == {}
        assert "raw" not in result.tool_calls[0].arguments

    async def test_valid_json_args_are_parsed_correctly(self):
        from unittest.mock import MagicMock, AsyncMock
        import json
        provider = self._make_provider()

        mock_tc = MagicMock()
        mock_tc.id = "call_456"
        mock_tc.function.name = "nmap"
        mock_tc.function.arguments = json.dumps({"target": "192.168.1.1", "ports": "80,443"})

        mock_msg = MagicMock()
        mock_msg.content = "Running nmap."
        mock_msg.tool_calls = [mock_tc]

        mock_choice = MagicMock()
        mock_choice.message = mock_msg

        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 10
        mock_usage.completion_tokens = 5

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.model = "gpt-4o"
        mock_response.usage = mock_usage

        with patch("openai.AsyncOpenAI") as MockClient:
            instance = MockClient.return_value
            instance.chat.completions.create = AsyncMock(return_value=mock_response)
            result = await provider.chat_with_tools([], [], "sys")

        assert result.tool_calls[0].arguments == {"target": "192.168.1.1", "ports": "80,443"}

    async def test_dict_args_passed_through_unchanged(self):
        """If API returns args already as dict (not str), no JSON parsing happens."""
        from unittest.mock import MagicMock, AsyncMock
        provider = self._make_provider()

        mock_tc = MagicMock()
        mock_tc.id = "call_789"
        mock_tc.function.name = "nmap"
        mock_tc.function.arguments = {"target": "10.0.0.1"}  # already a dict

        mock_msg = MagicMock()
        mock_msg.content = None
        mock_msg.tool_calls = [mock_tc]

        mock_choice = MagicMock()
        mock_choice.message = mock_msg

        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 5
        mock_usage.completion_tokens = 3

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.model = "gpt-4o"
        mock_response.usage = mock_usage

        with patch("openai.AsyncOpenAI") as MockClient:
            instance = MockClient.return_value
            instance.chat.completions.create = AsyncMock(return_value=mock_response)
            result = await provider.chat_with_tools([], [], "sys")

        assert result.tool_calls[0].arguments == {"target": "10.0.0.1"}


# ---------------------------------------------------------------------------
# gobuster — output parsing
# ---------------------------------------------------------------------------

class TestGobusterParsing:
    def _make_tool(self):
        from autopen.tools.gobuster import GobusterTool
        return GobusterTool()

    def test_parse_standard_dir_output(self):
        tool = self._make_tool()
        output = """\
===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 200) [Size: 1234]
/login                (Status: 301) [Size: 0] [--> /login/]
/static               (Status: 403) [Size: 291]
===============================================================
"""
        found = tool._parse_output(output)
        paths = [f["path"] for f in found]
        assert "/admin" in paths
        assert "/login" in paths
        assert "/static" in paths

    def test_parse_empty_output_returns_empty_list(self):
        tool = self._make_tool()
        assert tool._parse_output("") == []

    def test_format_output_no_results(self):
        tool = self._make_tool()
        out = tool._format_output([], "http://example.com")
        assert "No paths found" in out

    def test_format_output_with_results(self):
        tool = self._make_tool()
        found = [{"path": "/admin", "status": "200"}, {"path": "/login", "status": "301"}]
        out = tool._format_output(found, "http://example.com")
        assert "2 path(s)" in out
        assert "/admin" in out
