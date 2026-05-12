"""Record-finding tool — lets the LLM persist a finding to the database."""

from __future__ import annotations

from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class RecordFindingTool(BaseTool):
    """
    Virtual tool (no binary) that the LLM calls to persist a finding.

    The agent loop intercepts calls to this tool and routes them to
    SessionManager.add_finding() instead of executing a subprocess.
    """

    name = "record_finding"
    description = (
        "Record a security finding discovered during the assessment. "
        "Call this whenever you identify a vulnerability, misconfiguration, or noteworthy observation. "
        "Always record findings immediately after discovery — do not wait until the end."
    )
    risk_level = RiskLevel.LOW
    binary = ""
    parameters_schema = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short, descriptive title (e.g. 'SQL Injection in /login endpoint')",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "Severity level: critical | high | medium | low | info",
            },
            "description": {
                "type": "string",
                "description": "Detailed description of the finding — what it is and why it matters",
            },
            "target": {
                "type": "string",
                "description": "The specific host, URL, or endpoint affected",
            },
            "evidence": {
                "type": "string",
                "description": "Raw evidence: tool output, HTTP request/response, payload, screenshot text, etc.",
                "default": "",
            },
            "remediation": {
                "type": "string",
                "description": "Recommended remediation steps",
                "default": "",
            },
            "cvss_score": {
                "type": "number",
                "description": "CVSS v3.1 base score (0.0 - 10.0). Leave unset to auto-derive from severity.",
            },
        },
        "required": ["title", "severity", "description", "target"],
    }

    def is_available(self) -> bool:
        return True

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        # This should never be called directly — the agent loop intercepts
        # record_finding calls and delegates to SessionManager.add_finding().
        # If somehow called directly, return a clear error.
        return ToolResult(
            tool_name=self.name,
            success=False,
            output=(
                "record_finding must be handled by the agent loop, "
                "not executed as a subprocess tool."
            ),
            error="Not implemented as subprocess",
        )
