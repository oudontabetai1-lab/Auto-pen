"""Unit tests for the record_finding virtual tool and agent integration."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from autopen.tools.record_finding import RecordFindingTool
from autopen.tools.base import RiskLevel


class TestRecordFindingTool:
    def test_is_available(self):
        tool = RecordFindingTool()
        assert tool.is_available() is True

    def test_risk_level(self):
        tool = RecordFindingTool()
        assert tool.risk_level == RiskLevel.LOW

    def test_name(self):
        assert RecordFindingTool.name == "record_finding"

    def test_schema_has_required_fields(self):
        tool = RecordFindingTool()
        schema = tool.to_llm_schema()
        required = schema["parameters"]["required"]
        assert "title" in required
        assert "severity" in required
        assert "description" in required
        assert "target" in required

    def test_schema_severity_enum(self):
        tool = RecordFindingTool()
        schema = tool.to_llm_schema()
        severity_prop = schema["parameters"]["properties"]["severity"]
        assert "enum" in severity_prop
        assert "critical" in severity_prop["enum"]
        assert "high" in severity_prop["enum"]

    @pytest.mark.asyncio
    async def test_direct_execute_returns_error(self):
        tool = RecordFindingTool()
        result = await tool.execute({"title": "test", "severity": "high", "description": "x", "target": "10.0.0.1"})
        assert result.success is False
        assert "agent loop" in result.output.lower() or "not implemented" in result.output.lower()


class TestRecordFindingInRegistry:
    def test_record_finding_in_registry(self):
        from autopen.tools.registry import ToolRegistry
        registry = ToolRegistry()
        tool = registry.get("record_finding")
        assert tool is not None
        assert tool.is_available()

    def test_record_finding_in_llm_schemas(self):
        from autopen.tools.registry import ToolRegistry
        registry = ToolRegistry()
        schemas = registry.get_llm_schemas(only_available=True)
        names = [s["name"] for s in schemas]
        assert "record_finding" in names
