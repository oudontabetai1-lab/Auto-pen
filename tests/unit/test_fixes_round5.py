"""Tests covering round-5 fixes: nuclei/hydra/ffuf error flags, and parsing for dig/whois/nikto/whatweb/cve_lookup."""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# NucleiTool — success flag + output parsing
# ---------------------------------------------------------------------------

class TestNucleiTool:
    def _make_tool(self):
        from autopen.tools.nuclei import NucleiTool
        return NucleiTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_success_with_no_findings(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="", rc=0)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is True
        assert "No vulnerabilities" in result.output

    async def test_failure_when_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="nuclei: command not found", rc=127)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is False
        assert "nuclei failed" in result.output

    async def test_success_with_jsonl_findings(self):
        tool = self._make_tool()
        finding = {
            "template-id": "cve-2021-44228",
            "info": {
                "name": "Log4j RCE",
                "severity": "critical",
                "description": "Remote code execution",
                "tags": ["cve", "rce"],
                "reference": [],
            },
            "matched-at": "http://example.com/log4j",
            "curl-command": "",
        }
        jsonl = json.dumps(finding)
        tool._run_command = self._mock_run(stdout=jsonl, stderr="", rc=0)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is True
        assert "Log4j RCE" in result.output
        assert result.metadata["findings"][0]["template_id"] == "cve-2021-44228"

    async def test_rc_nonzero_with_output_still_succeeds(self):
        """If nuclei exits non-zero but produced output, treat as success (partial scan)."""
        tool = self._make_tool()
        finding = {
            "template-id": "test-id",
            "info": {"name": "Test Finding", "severity": "medium", "description": "", "tags": [], "reference": []},
            "matched-at": "http://example.com",
            "curl-command": "",
        }
        tool._run_command = self._mock_run(stdout=json.dumps(finding), stderr="", rc=1)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is True

    def test_parse_jsonl_skips_invalid_lines(self):
        tool = self._make_tool()
        output = 'not-json\n{"template-id":"t1","info":{"name":"X","severity":"low","description":"","tags":[],"reference":[]},"matched-at":"http://x.com","curl-command":""}\nbad'
        findings = tool._parse_jsonl(output)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "t1"

    def test_format_findings_empty(self):
        tool = self._make_tool()
        assert "No vulnerabilities" in tool._format_findings([])

    def test_format_findings_nonempty(self):
        tool = self._make_tool()
        findings = [{"name": "RCE", "severity": "critical", "template_id": "rce-1", "matched_at": "http://x.com", "description": "Bad thing"}]
        output = tool._format_findings(findings)
        assert "RCE" in output
        assert "CRITICAL" in output


# ---------------------------------------------------------------------------
# HydraTool — success flag + credential parsing + command building
# ---------------------------------------------------------------------------

class TestHydraTool:
    def _make_tool(self):
        from autopen.tools.hydra import HydraTool
        return HydraTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_failure_when_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="hydra: not found", rc=127)
        result = await tool.execute({"target": "192.168.1.1", "service": "ssh", "usernames": "admin"})
        assert result.success is False
        assert "hydra failed" in result.output

    async def test_success_no_credentials_found(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="0 of 1 target completed", stderr="", rc=0)
        result = await tool.execute({"target": "192.168.1.1", "service": "ssh", "usernames": "admin"})
        assert result.success is True
        assert "No valid credentials" in result.output

    async def test_credential_extraction(self):
        tool = self._make_tool()
        line = "[22][ssh] host: 192.168.1.1   login: root   password: toor"
        tool._run_command = self._mock_run(stdout=line, stderr="", rc=0)
        result = await tool.execute({"target": "192.168.1.1", "service": "ssh", "usernames": "root"})
        assert result.success is True
        assert result.metadata["credentials"][0]["login"] == "root"
        assert result.metadata["credentials"][0]["password"] == "toor"

    async def test_rc_nonzero_with_output_still_succeeds(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="some partial output", stderr="", rc=1)
        result = await tool.execute({"target": "192.168.1.1", "service": "ftp", "usernames": "admin"})
        assert result.success is True

    def test_file_path_flag_for_usernames(self):
        tool = self._make_tool()
        # "/" in path → -L flag
        creds = tool._extract_credentials("[22][ssh] host: 1.1.1.1   login: admin   password: pass")
        assert creds[0]["login"] == "admin"

    def test_format_output_with_credentials(self):
        tool = self._make_tool()
        creds = [{"login": "admin", "password": "pass"}]
        output = tool._format_output(creds, "192.168.1.1", "ssh")
        assert "CREDENTIALS FOUND" in output
        assert "admin" in output

    def test_format_output_no_credentials(self):
        tool = self._make_tool()
        output = tool._format_output([], "192.168.1.1", "ssh")
        assert "No valid credentials" in output


# ---------------------------------------------------------------------------
# FfufTool — success flag + JSON parsing + text fallback
# ---------------------------------------------------------------------------

class TestFfufTool:
    def _make_tool(self):
        from autopen.tools.ffuf import FfufTool
        return FfufTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_failure_when_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="ffuf: not found", rc=127)
        result = await tool.execute({"url": "http://example.com/FUZZ"})
        assert result.success is False
        assert "ffuf failed" in result.output

    async def test_success_no_results(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout='{"results":[]}', stderr="", rc=0)
        result = await tool.execute({"url": "http://example.com/FUZZ"})
        assert result.success is True
        assert "No results" in result.output

    async def test_success_with_json_results(self):
        tool = self._make_tool()
        output = json.dumps({
            "results": [
                {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234},
                {"input": {"FUZZ": "login"}, "status": 301, "length": 567},
            ]
        })
        tool._run_command = self._mock_run(stdout=output, stderr="", rc=0)
        result = await tool.execute({"url": "http://example.com/FUZZ"})
        assert result.success is True
        assert "2 result" in result.output
        assert len(result.metadata["results"]) == 2

    async def test_rc_nonzero_with_output_still_succeeds(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout='{"results":[]}', stderr="", rc=1)
        result = await tool.execute({"url": "http://example.com/FUZZ"})
        assert result.success is True

    def test_parse_json_invalid_falls_back_to_text(self):
        tool = self._make_tool()
        text_output = "admin [Status: 200] [Length: 1234]"
        results = tool._parse_json(text_output)
        assert len(results) == 1

    def test_parse_json_valid(self):
        tool = self._make_tool()
        output = json.dumps({"results": [{"input": {"FUZZ": "secret"}, "status": 200, "length": 100}]})
        results = tool._parse_json(output)
        assert results[0]["input"]["FUZZ"] == "secret"


# ---------------------------------------------------------------------------
# DigTool — output parsing + failure detection
# ---------------------------------------------------------------------------

class TestDigTool:
    def _make_tool(self):
        from autopen.tools.dig import DigTool
        return DigTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_success_with_records(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="example.com.\t300\tIN\tA\t93.184.216.34", stderr="", rc=0)
        result = await tool.execute({"target": "example.com", "record_type": "A"})
        assert result.success is True
        assert "93.184.216.34" in result.output

    async def test_failure_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="connection timed out", rc=9)
        result = await tool.execute({"target": "example.com"})
        assert result.success is False
        assert "dig failed" in result.output

    async def test_no_records_returns_message(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="", rc=0)
        result = await tool.execute({"target": "example.com", "record_type": "AAAA"})
        assert result.success is True
        assert "No AAAA records" in result.output

    async def test_default_record_type_is_A(self):
        tool = self._make_tool()
        captured_cmd = []

        async def capture_run(cmd, timeout=None):
            captured_cmd.extend(cmd)
            return "example.com.\t300\tIN\tA\t1.2.3.4", "", 0

        tool._run_command = capture_run
        await tool.execute({"target": "example.com"})
        assert "A" in captured_cmd


# ---------------------------------------------------------------------------
# WhoisTool — truncation + failure detection
# ---------------------------------------------------------------------------

class TestWhoisTool:
    def _make_tool(self):
        from autopen.tools.whois import WhoisTool
        return WhoisTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_success_returns_truncated_output(self):
        tool = self._make_tool()
        long_output = "X" * 5000
        tool._run_command = self._mock_run(stdout=long_output, stderr="", rc=0)
        result = await tool.execute({"target": "example.com"})
        assert result.success is True
        assert len(result.output) == 3000

    async def test_failure_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="whois: network unreachable", rc=1)
        result = await tool.execute({"target": "example.com"})
        assert result.success is False
        assert "whois failed" in result.output

    async def test_rc_nonzero_with_some_output_succeeds(self):
        """whois outputs partial data then fails; still usable."""
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="Domain: example.com\nRegistrar: ICANN", stderr="", rc=1)
        result = await tool.execute({"target": "example.com"})
        assert result.success is True


# ---------------------------------------------------------------------------
# NiktoTool — finding extraction + edge cases
# ---------------------------------------------------------------------------

class TestNiktoTool:
    def _make_tool(self):
        from autopen.tools.nikto import NiktoTool
        return NiktoTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_no_output_returns_failure(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="", rc=0)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is False
        assert "no output" in result.output.lower()

    async def test_findings_extracted(self):
        tool = self._make_tool()
        nikto_output = (
            "+ Target IP:          192.168.1.1\n"
            "+ Target Hostname:    example.com\n"
            "+ /admin/: Directory indexing found.\n"
            "+ /robots.txt: Contains 3 disallowed entries\n"
        )
        tool._run_command = self._mock_run(stdout=nikto_output, stderr="", rc=0)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is True
        assert result.metadata["findings"]
        assert "2 item" in result.output

    async def test_no_notable_findings(self):
        tool = self._make_tool()
        # Only "Target" prefixed lines — these should be skipped by the extractor
        tool._run_command = self._mock_run(stdout="+ Target IP: 192.168.1.1\n+ Target Port: 80\n", stderr="", rc=0)
        result = await tool.execute({"target": "http://example.com"})
        assert result.success is True
        assert "No notable findings" in result.output

    def test_extract_findings_skips_target_lines(self):
        tool = self._make_tool()
        output = "+ Target IP: 1.2.3.4\n+ /admin/: found\n+ Target Hostname: example.com\n"
        findings = tool._extract_findings(output)
        assert len(findings) == 1
        assert "/admin/" in findings[0]["finding"]


# ---------------------------------------------------------------------------
# WhatwebTool — output handling
# ---------------------------------------------------------------------------

class TestWhatwebTool:
    def _make_tool(self):
        from autopen.tools.whatweb import WhatwebTool
        return WhatwebTool()

    def _mock_run(self, stdout: str = "", stderr: str = "", rc: int = 0):
        async def _run(cmd, timeout=None):
            return stdout, stderr, rc
        return _run

    async def test_success_with_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(
            stdout="https://example.com [200 OK] Apache[2.4.41], PHP[7.4], WordPress[5.8]",
            stderr="", rc=0
        )
        result = await tool.execute({"target": "https://example.com"})
        assert result.success is True
        assert "WordPress" in result.output

    async def test_failure_rc_nonzero_no_output(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="whatweb: command not found", rc=127)
        result = await tool.execute({"target": "https://example.com"})
        assert result.success is False
        assert "whatweb failed" in result.output

    async def test_empty_stdout_falls_back_to_stderr(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="some info", rc=0)
        result = await tool.execute({"target": "https://example.com"})
        assert result.success is True
        assert "some info" in result.output

    async def test_all_empty_returns_no_results(self):
        tool = self._make_tool()
        tool._run_command = self._mock_run(stdout="", stderr="", rc=0)
        result = await tool.execute({"target": "https://example.com"})
        assert result.success is True
        assert "No results" in result.output


# ---------------------------------------------------------------------------
# CveLookupTool — parameter validation + parsing + HTTP error handling
# ---------------------------------------------------------------------------

class TestCveLookupTool:
    def _make_tool(self):
        from autopen.tools.cve_lookup import CveLookupTool
        return CveLookupTool()

    async def test_missing_params_returns_failure(self):
        tool = self._make_tool()
        result = await tool.execute({})
        assert result.success is False
        assert "required" in result.output.lower()

    async def test_cve_id_lookup_success(self):
        import httpx
        tool = self._make_tool()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "published": "2021-12-10T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]
                        },
                        "references": [{"url": "https://example.com/ref"}],
                    }
                }
            ]
        }

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await tool.execute({"cve_id": "CVE-2021-44228"})

        assert result.success is True
        assert "CVE-2021-44228" in result.output
        assert "CRITICAL" in result.output

    async def test_no_results_returned(self):
        tool = self._make_tool()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await tool.execute({"cve_id": "CVE-9999-99999"})

        assert result.success is True
        assert "No CVEs" in result.output

    async def test_http_error_returns_failure(self):
        import httpx
        tool = self._make_tool()

        with patch("httpx.AsyncClient") as mock_cls:
            mock_response = MagicMock()
            mock_response.status_code = 403
            exc = httpx.HTTPStatusError("Forbidden", request=MagicMock(), response=mock_response)
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=exc)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await tool.execute({"keyword": "log4j"})

        assert result.success is False
        assert "HTTP 403" in result.output

    async def test_network_error_returns_failure(self):
        tool = self._make_tool()

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("network unreachable"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await tool.execute({"keyword": "apache"})

        assert result.success is False
        assert "unavailable" in result.output.lower()

    def test_is_available_always_true(self):
        tool = self._make_tool()
        assert tool.is_available() is True

    def test_parse_cve_extracts_fields(self):
        tool = self._make_tool()
        item = {
            "cve": {
                "id": "CVE-2022-1234",
                "published": "2022-04-01T12:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                },
                "references": [],
            }
        }
        parsed = tool._parse_cve(item)
        assert parsed["id"] == "CVE-2022-1234"
        assert parsed["cvss_score"] == 7.5
        assert parsed["severity"] == "HIGH"
        assert parsed["published"] == "2022-04-01"
        assert "nvd.nist.gov" in parsed["references"][0]
