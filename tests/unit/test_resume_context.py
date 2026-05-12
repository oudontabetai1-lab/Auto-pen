"""Unit tests for session resume context and related fixes."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock


class TestAutoConfirmMedium:
    def test_medium_needs_confirmation_when_disabled(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        c = HumanConfirmation(auto_confirm_medium=False)
        assert c.needs_confirmation(RiskLevel.MEDIUM) is True

    def test_medium_no_confirmation_when_enabled(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        c = HumanConfirmation(auto_confirm_medium=True)
        assert c.needs_confirmation(RiskLevel.MEDIUM) is False

    def test_high_always_needs_confirmation(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        for flag in (True, False):
            c = HumanConfirmation(auto_confirm_medium=flag)
            assert c.needs_confirmation(RiskLevel.HIGH) is True

    def test_critical_always_needs_confirmation(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        c = HumanConfirmation(auto_confirm_medium=True)
        assert c.needs_confirmation(RiskLevel.CRITICAL) is True

    def test_low_never_needs_confirmation(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        for flag in (True, False):
            c = HumanConfirmation(auto_confirm_medium=flag)
            assert c.needs_confirmation(RiskLevel.LOW) is False

    def test_default_is_auto_confirm_medium_true(self):
        from autopen.security.confirm import HumanConfirmation
        from autopen.tools.base import RiskLevel

        c = HumanConfirmation()
        assert c.needs_confirmation(RiskLevel.MEDIUM) is False


class TestBuildResumeContext:
    def _make_manager(self, logs, findings):
        manager = MagicMock()
        manager.list_audit_logs.return_value = logs
        manager.list_findings.return_value = findings
        return manager

    def _make_log(self, action, tool_name=None, result_summary=""):
        log = MagicMock()
        log.action = action
        log.tool_name = tool_name
        log.result_summary = result_summary
        return log

    def _make_finding(self, severity, title, target):
        f = MagicMock()
        f.severity = severity
        f.title = title
        f.target = target
        return f

    def _make_agent(self, manager):
        from autopen.agent.loop import AgentLoop
        agent = AgentLoop.__new__(AgentLoop)
        agent.manager = manager
        return agent

    def _make_session(self, step_count):
        s = MagicMock()
        s.id = "test-session-id"
        s.step_count = step_count
        return s

    def test_includes_step_count(self):
        manager = self._make_manager([], [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(5))
        assert "5 steps" in ctx

    def test_includes_completed_tool(self):
        logs = [self._make_log("tool_completed", "nmap", "Open ports: 22, 80")]
        manager = self._make_manager(logs, [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(1))
        assert "nmap" in ctx
        assert "Open ports" in ctx

    def test_includes_denied_tool(self):
        logs = [self._make_log("human_denied", "sqlmap")]
        manager = self._make_manager(logs, [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(1))
        assert "sqlmap" in ctx
        assert "DENIED" in ctx

    def test_includes_scope_violation(self):
        logs = [self._make_log("scope_violation_blocked", "nmap")]
        manager = self._make_manager(logs, [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(1))
        assert "BLOCKED" in ctx

    def test_includes_finding(self):
        findings = [self._make_finding("high", "Open SSH", "10.0.0.1")]
        manager = self._make_manager([], findings)
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(2))
        assert "Open SSH" in ctx
        assert "HIGH" in ctx

    def test_no_findings_shows_none(self):
        manager = self._make_manager([], [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(1))
        assert "none" in ctx.lower()

    def test_instructs_not_to_repeat(self):
        manager = self._make_manager([], [])
        agent = self._make_agent(manager)
        ctx = agent._build_resume_context(self._make_session(1))
        assert "Do NOT repeat" in ctx or "not repeat" in ctx.lower()


class TestDuckDuckGoFallback:
    def test_primary_parser_returns_results(self):
        from autopen.tools.duckduckgo import _parse_results
        html = '''
        <td class="result-link"><a href="https://example.com">Example</a></td>
        '''
        results, parser = _parse_results(html, 10)
        assert parser == "primary"
        assert len(results) == 1
        assert "example.com" in results[0]

    def test_fallback_parser_activates_when_primary_fails(self):
        from autopen.tools.duckduckgo import _parse_results
        html = '<a href="https://example.com/page">Some Page</a>'
        results, parser = _parse_results(html, 10)
        assert parser == "fallback"
        assert len(results) == 1
        assert "example.com" in results[0]

    def test_fallback_excludes_duckduckgo_links(self):
        from autopen.tools.duckduckgo import _parse_results
        html = '<a href="https://duckduckgo.com/search">DDG</a><a href="https://other.com">Other</a>'
        results, parser = _parse_results(html, 10)
        assert all("duckduckgo.com" not in r for r in results)

    def test_fallback_deduplicates(self):
        from autopen.tools.duckduckgo import _parse_results
        html = (
            '<a href="https://example.com">A</a>'
            '<a href="https://example.com">B</a>'
        )
        results, parser = _parse_results(html, 10)
        assert len(results) == 1

    def test_no_results_returns_empty(self):
        from autopen.tools.duckduckgo import _parse_results
        results, parser = _parse_results("<html><body>nothing</body></html>", 10)
        assert results == []

    def test_max_results_respected(self):
        from autopen.tools.duckduckgo import _parse_results
        links = "".join(f'<a href="https://site{i}.com">Site {i}</a>' for i in range(20))
        results, _ = _parse_results(links, 5)
        assert len(results) == 5
