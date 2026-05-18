"""Unit tests for ReportGenerator."""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime


def _make_session(sid="sess-1", target="10.0.0.1", profile="network", status="completed"):
    s = MagicMock()
    s.id = sid
    s.target = target
    s.profile = profile
    s.status = status
    s.authorization_token = "authorized for testing"
    s.llm_provider = "ollama"
    s.llm_model = "llama3.1"
    s.step_count = 5
    s.created_at = datetime(2024, 1, 1, 12, 0, 0)
    s.updated_at = datetime(2024, 1, 1, 12, 30, 0)
    return s


def _make_finding(severity="high", title="Open SSH", target="10.0.0.1", cvss=7.5):
    f = MagicMock(spec=["severity", "title", "target", "tool_name", "description",
                         "evidence", "remediation", "cvss_score", "cvss_vector",
                         "timestamp", "id"])
    f.severity = severity
    f.title = title
    f.target = target
    f.tool_name = "nmap"
    f.description = "SSH service running"
    f.evidence = ""
    f.remediation = "Restrict access"
    f.cvss_score = cvss
    f.cvss_vector = None
    f.timestamp = datetime(2024, 1, 1, 12, 0, 0)
    f.id = "finding-1"
    return f


def _make_log(action="tool_completed", tool_name="nmap", risk_level="low"):
    log = MagicMock()
    log.action = action
    log.tool_name = tool_name
    log.risk_level = risk_level
    log.timestamp = datetime(2024, 1, 1, 12, 0, 0)
    return log


def _make_generator(session=None, findings=None, logs=None):
    from autopen.reporting.generator import ReportGenerator
    manager = MagicMock()
    manager.get_session.return_value = session or _make_session()
    manager.list_findings.return_value = findings if findings is not None else []
    manager.list_audit_logs.return_value = logs if logs is not None else []
    gen = ReportGenerator(manager)
    return gen


class TestReportGeneratorMarkdown:
    def test_contains_header(self):
        gen = _make_generator()
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "# Penetration Test Report" in md

    def test_contains_target(self):
        gen = _make_generator()
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "10.0.0.1" in md

    def test_contains_authorization(self):
        gen = _make_generator()
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        # Token is masked (H2). Verify the masked fingerprint shows up,
        # never the plaintext token.
        assert "auth-token sha256:" in md
        assert "authorized for testing" not in md

    def test_no_findings_message(self):
        gen = _make_generator(findings=[])
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "No findings recorded" in md

    def test_finding_included(self):
        finding = _make_finding(severity="high", title="Open SSH")
        gen = _make_generator(findings=[finding])
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "Open SSH" in md
        assert "HIGH" in md

    def test_severity_counts_in_summary(self):
        findings = [
            _make_finding(severity="critical", title="RCE"),
            _make_finding(severity="high", title="SQLi"),
            _make_finding(severity="medium", title="XSS"),
        ]
        gen = _make_generator(findings=findings)
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "3" in md  # total findings count

    def test_session_not_found_returns_error(self):
        from autopen.reporting.generator import ReportGenerator
        manager = MagicMock()
        manager.get_session.return_value = None
        gen = ReportGenerator(manager)
        md = gen.generate_markdown("nonexistent")
        assert "Error" in md or "not found" in md.lower()

    def test_finding_with_evidence(self):
        finding = _make_finding()
        finding.evidence = "PORT   STATE SERVICE\n22/tcp open  ssh"
        gen = _make_generator(findings=[finding])
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "22/tcp" in md

    def test_audit_log_tools_shown(self):
        log = _make_log(tool_name="nmap")
        gen = _make_generator(logs=[log])
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            md = gen.generate_markdown("sess-1")
        assert "nmap" in md


class TestReportGeneratorJson:
    def test_json_has_session_key(self):
        gen = _make_generator()
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            raw = gen.generate_json("sess-1")
        data = json.loads(raw)
        assert "session" in data

    def test_json_has_findings_key(self):
        gen = _make_generator()
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            raw = gen.generate_json("sess-1")
        data = json.loads(raw)
        assert "findings" in data

    def test_json_finding_fields(self):
        finding = _make_finding(severity="high", title="Open SSH")
        gen = _make_generator(findings=[finding])
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            raw = gen.generate_json("sess-1")
        data = json.loads(raw)
        f = data["findings"][0]
        assert f["severity"] == "high"
        assert f["title"] == "Open SSH"

    def test_json_session_not_found(self):
        from autopen.reporting.generator import ReportGenerator
        manager = MagicMock()
        manager.get_session.return_value = None
        gen = ReportGenerator(manager)
        raw = gen.generate_json("nonexistent")
        data = json.loads(raw)
        assert "error" in data

    def test_json_summary_counts(self):
        findings = [
            _make_finding(severity="high"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
        ]
        gen = _make_generator(findings=findings)
        with patch("autopen.reporting.cve_enricher.CveEnricher.enrich_sync", return_value={}):
            raw = gen.generate_json("sess-1")
        data = json.loads(raw)
        assert data["summary"]["total_findings"] == 3
