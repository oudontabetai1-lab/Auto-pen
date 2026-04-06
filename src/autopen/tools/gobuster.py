"""gobuster wrapper — directory/file and DNS brute-forcing."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class GobusterTool(BaseTool):
    name = "gobuster"
    description = (
        "Directory and file brute-forcing tool for web applications. "
        "Also supports DNS subdomain and vhost enumeration. "
        "Use during enumeration phase to discover hidden content."
    )
    risk_level = RiskLevel.MEDIUM
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL (e.g. 'http://192.168.1.1') or domain for DNS mode",
            },
            "mode": {
                "type": "string",
                "enum": ["dir", "dns", "vhost"],
                "description": "Scan mode: dir=directory brute-force, dns=subdomain enum, vhost=virtual host enum",
                "default": "dir",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist file",
                "default": "/usr/share/wordlists/dirb/common.txt",
            },
            "extensions": {
                "type": "string",
                "description": "File extensions to search (e.g. 'php,html,txt')",
                "default": "",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 20,
            },
            "status_codes": {
                "type": "string",
                "description": "HTTP status codes to include (default: 200,204,301,302,307,401,403)",
                "default": "200,204,301,302,307,401,403",
            },
            "cookie": {
                "type": "string",
                "description": "HTTP cookie for authenticated scanning",
                "default": "",
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "gobuster") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = params.get("extensions", "")
        threads = params.get("threads", 20)
        status_codes = params.get("status_codes", "200,204,301,302,307,401,403")
        cookie = params.get("cookie", "")

        cmd = [
            self.binary, mode,
            "-u" if mode in ("dir", "vhost") else "-d", target,
            "-w", wordlist,
            "-t", str(threads),
            "--no-color",
        ]
        if mode == "dir":
            cmd.extend(["-s", status_codes])
            if extensions:
                cmd.extend(["-x", extensions])
            if cookie:
                cmd.extend(["-c", cookie])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=300)
        duration = time.monotonic() - t0

        found = self._parse_output(stdout)
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_output(found, target),
            raw_output=stdout,
            metadata={"found": found},
            duration_seconds=duration,
        )

    def _parse_output(self, output: str) -> list[dict[str, str]]:
        found = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("/usr"):
                continue
            if "/" in line or line.startswith("Found:"):
                parts = line.split()
                if parts:
                    found.append({"path": parts[0], "status": parts[1] if len(parts) > 1 else ""})
        return found

    def _format_output(self, found: list[dict[str, str]], target: str) -> str:
        if not found:
            return f"gobuster: No paths found on {target}"
        lines = [f"gobuster found {len(found)} path(s) on {target}:"]
        for f in found:
            lines.append(f"  {f['path']}  {f['status']}")
        return "\n".join(lines)
