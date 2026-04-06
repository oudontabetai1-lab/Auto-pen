"""Unit tests for tool wrappers (using mocked subprocess)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from autopen.tools.nmap import NmapTool
from autopen.tools.gobuster import GobusterTool
from autopen.tools.base import RiskLevel


class TestNmapTool:
    def test_risk_level(self):
        tool = NmapTool()
        assert tool.risk_level == RiskLevel.MEDIUM

    def test_llm_schema_has_required_fields(self):
        tool = NmapTool()
        schema = tool.to_llm_schema()
        assert schema["name"] == "nmap"
        assert "target" in schema["parameters"]["required"]

    def test_build_command_basic(self):
        tool = NmapTool()
        cmd = tool._build_command("192.168.1.1", "", "version", "")
        assert "192.168.1.1" in cmd
        assert "-sV" in cmd

    def test_build_command_with_ports(self):
        tool = NmapTool()
        cmd = tool._build_command("192.168.1.1", "22,80,443", "basic", "")
        assert "-p" in cmd
        assert "22,80,443" in cmd

    def test_parse_xml_empty(self):
        tool = NmapTool()
        result = tool._parse_xml("<nmaprun></nmaprun>")
        assert result["hosts"] == []

    def test_parse_xml_with_host(self):
        xml = """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.49"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
        tool = NmapTool()
        result = tool._parse_xml(xml)
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "10.0.0.1"
        assert result["hosts"][0]["ports"][0]["port"] == 80
        assert result["hosts"][0]["ports"][0]["service"] == "http"

    @pytest.mark.asyncio
    async def test_execute_with_mocked_subprocess(self):
        xml_output = """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
        tool = NmapTool()
        with patch.object(tool, "_run_command", new=AsyncMock(return_value=(xml_output, "", 0))):
            result = await tool.execute({"target": "192.168.1.1", "scan_type": "version"})

        assert result.success
        assert "192.168.1.1" in result.output or "22" in result.output


class TestGobusterTool:
    def test_risk_level(self):
        tool = GobusterTool()
        assert tool.risk_level == RiskLevel.MEDIUM

    def test_parse_output(self):
        tool = GobusterTool()
        output = "/admin [Status: 301]\n/login [Status: 200]\n"
        found = tool._parse_output(output)
        assert len(found) == 2

    def test_format_output_empty(self):
        tool = GobusterTool()
        msg = tool._format_output([], "http://target.com")
        assert "No paths found" in msg
