"""nuclei wrapper — template-based vulnerability scanner."""

from __future__ import annotations

import json
import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class NucleiTool(BaseTool):
    name = "nuclei"
    description = (
        "Fast template-based vulnerability scanner. "
        "Covers CVEs, misconfigurations, default credentials, exposed panels, and more. "
        "Use after initial recon to scan for known vulnerabilities."
    )
    risk_level = RiskLevel.MEDIUM
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or IP (e.g. 'https://example.com', '192.168.1.1')",
            },
            "severity": {
                "type": "string",
                "description": "Filter by severity: critical,high,medium,low,info (comma-separated)",
                "default": "critical,high,medium",
            },
            "tags": {
                "type": "string",
                "description": "Filter templates by tags (e.g. 'cve,rce,sqli')",
                "default": "",
            },
            "templates": {
                "type": "string",
                "description": "Specific template path or directory",
                "default": "",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Max requests per second",
                "default": 50,
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "nuclei") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        severity = params.get("severity", "critical,high,medium")
        tags = params.get("tags", "")
        templates = params.get("templates", "")
        rate_limit = params.get("rate_limit", 50)

        cmd = [
            self.binary,
            "-u", target,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-jsonl",           # JSONL output for easy parsing
            "-silent",
            "-no-color",
        ]
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            cmd.extend(["-t", templates])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=600)
        duration = time.monotonic() - t0

        if rc != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"nuclei failed: {stderr or 'unknown error'}",
                raw_output=stderr,
                error=stderr,
                duration_seconds=duration,
            )

        findings = self._parse_jsonl(stdout)
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_findings(findings),
            raw_output=stdout,
            metadata={"findings": findings},
            duration_seconds=duration,
        )

    def _parse_jsonl(self, output: str) -> list[dict[str, Any]]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(
                    {
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "matched_at": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "tags": data.get("info", {}).get("tags", []),
                        "reference": data.get("info", {}).get("reference", []),
                        "curl_command": data.get("curl-command", ""),
                    }
                )
            except json.JSONDecodeError:
                continue
        return findings

    def _format_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "nuclei: No vulnerabilities found."
        lines = [f"nuclei found {len(findings)} vulnerability/ies:"]
        for f in findings:
            lines.append(
                f"  [{f['severity'].upper()}] {f['name']} ({f['template_id']}) @ {f['matched_at']}"
            )
            if f.get("description"):
                lines.append(f"    {f['description'][:200]}")
        return "\n".join(lines)
