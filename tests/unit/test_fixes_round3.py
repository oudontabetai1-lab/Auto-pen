"""Tests covering round-3 fixes: returncode masking, registry safety, approved_by_human."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# BaseTool._run_command — signal-killed process returns -1 not 0
# ---------------------------------------------------------------------------

class TestRunCommandReturnCode:
    def _make_tool(self):
        from autopen.tools.nmap import NmapTool
        return NmapTool()

    async def test_signal_killed_returns_minus_one(self):
        """Process killed by signal has returncode=None; should map to -1, not 0."""
        tool = self._make_tool()

        mock_proc = MagicMock()
        mock_proc.returncode = None
        mock_proc.communicate = AsyncMock(return_value=(b"out", b"err"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            stdout, stderr, rc = await tool._run_command(["nmap", "127.0.0.1"])

        assert rc == -1

    async def test_zero_returncode_preserved(self):
        tool = self._make_tool()

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"output", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            _, _, rc = await tool._run_command(["nmap", "127.0.0.1"])

        assert rc == 0

    async def test_nonzero_returncode_preserved(self):
        tool = self._make_tool()

        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            _, _, rc = await tool._run_command(["nmap", "127.0.0.1"])

        assert rc == 2

    async def test_timeout_returns_minus_one(self):
        tool = self._make_tool()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        # After kill, communicate should return empty bytes
        async def _communicate_after_kill():
            return b"", b""
        mock_proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError(), (b"", b"")])

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            _, stderr, rc = await tool._run_command(["nmap", "127.0.0.1"], timeout=0.001)

        assert rc == -1
        assert "timed out" in stderr


# ---------------------------------------------------------------------------
# ToolRegistry.available_tools — is_available() exceptions don't crash it
# ---------------------------------------------------------------------------

class TestRegistryAvailableTools:
    def test_is_available_exception_skips_tool(self):
        from autopen.tools.registry import ToolRegistry
        from autopen.tools.base import BaseTool, RiskLevel, ToolResult

        class GoodTool(BaseTool):
            name = "good"
            description = "works"
            risk_level = RiskLevel.LOW
            async def execute(self, params): ...  # pragma: no cover
            def is_available(self): return True

        class BrokenTool(BaseTool):
            name = "broken"
            description = "raises"
            risk_level = RiskLevel.LOW
            async def execute(self, params): ...  # pragma: no cover
            def is_available(self): raise OSError("filesystem error")

        registry = ToolRegistry.__new__(ToolRegistry)
        registry._tools = {"good": GoodTool(), "broken": BrokenTool()}
        registry._config = {}

        available = registry.available_tools()
        names = [t.name for t in available]
        assert "good" in names
        assert "broken" not in names

    def test_all_available_exceptions_returns_empty_list(self):
        from autopen.tools.registry import ToolRegistry
        from autopen.tools.base import BaseTool, RiskLevel

        class FailTool(BaseTool):
            name = "fail"
            description = "always fails"
            risk_level = RiskLevel.LOW
            async def execute(self, params): ...  # pragma: no cover
            def is_available(self): raise RuntimeError("no binary")

        registry = ToolRegistry.__new__(ToolRegistry)
        registry._tools = {"fail": FailTool()}
        registry._config = {}

        assert registry.available_tools() == []


# ---------------------------------------------------------------------------
# AgentLoop — approved_by_human reflects actual confirmation, not risk level
# ---------------------------------------------------------------------------

class TestApprovedByHuman:
    def _make_agent(self):
        from autopen.agent.loop import AgentLoop
        agent = AgentLoop.__new__(AgentLoop)
        agent.session_id = "test-session"
        agent._event_emitter = None

        agent.manager = MagicMock()
        agent.manager.log_action = MagicMock()

        agent.scope_validator = MagicMock()
        agent.scope_validator.assert_in_scope = MagicMock()  # never raises

        return agent

    def _make_tool(self, risk_level, name="test_tool"):
        from autopen.tools.base import BaseTool, RiskLevel, ToolResult

        class _T(BaseTool):
            async def execute(self, params):
                return ToolResult(tool_name=self.name, success=True, output="done")

        t = _T.__new__(_T)
        t.name = name
        t.description = "test"
        t.risk_level = risk_level
        t.parameters_schema = {}
        t.binary = ""
        return t

    async def test_low_risk_approved_by_human_is_false(self):
        from autopen.tools.base import RiskLevel
        agent = self._make_agent()
        tool = self._make_tool(RiskLevel.LOW)

        confirmation = MagicMock()
        confirmation.needs_confirmation.return_value = False
        agent.confirmation = confirmation

        agent.registry = MagicMock()
        agent.registry.get.return_value = tool

        result = await agent._handle_tool_call(
            MagicMock(name="test_tool", arguments={}, id="tc1"),
            reasoning="test"
        )

        # For low-risk tools, approved_by_human should be False in tool_executing log
        executing_call = next(
            c for c in agent.manager.log_action.call_args_list
            if c.kwargs.get("action") == "tool_executing"
        )
        assert executing_call.kwargs["approved_by_human"] is False

    async def test_high_risk_approved_sets_true(self):
        from autopen.tools.base import RiskLevel
        agent = self._make_agent()
        tool = self._make_tool(RiskLevel.HIGH)

        confirmation = MagicMock()
        confirmation.needs_confirmation.return_value = True
        confirmation.ask = AsyncMock(return_value=True)  # approved
        agent.confirmation = confirmation

        agent.registry = MagicMock()
        agent.registry.get.return_value = tool

        result = await agent._handle_tool_call(
            MagicMock(name="test_tool", arguments={}, id="tc1"),
            reasoning="test"
        )

        executing_call = next(
            c for c in agent.manager.log_action.call_args_list
            if c.kwargs.get("action") == "tool_executing"
        )
        assert executing_call.kwargs["approved_by_human"] is True

    async def test_medium_risk_with_confirmation_sets_true(self):
        """MEDIUM tools with auto_confirm_medium=False should also set approved_by_human=True."""
        from autopen.tools.base import RiskLevel
        agent = self._make_agent()
        tool = self._make_tool(RiskLevel.MEDIUM)

        confirmation = MagicMock()
        confirmation.needs_confirmation.return_value = True  # medium with confirm required
        confirmation.ask = AsyncMock(return_value=True)
        agent.confirmation = confirmation

        agent.registry = MagicMock()
        agent.registry.get.return_value = tool

        await agent._handle_tool_call(
            MagicMock(name="test_tool", arguments={}, id="tc1"),
            reasoning="test"
        )

        executing_call = next(
            c for c in agent.manager.log_action.call_args_list
            if c.kwargs.get("action") == "tool_executing"
        )
        assert executing_call.kwargs["approved_by_human"] is True
