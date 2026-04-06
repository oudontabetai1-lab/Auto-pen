"""ffuf wrapper — web fuzzer for directories, parameters, and headers."""

from __future__ import annotations

import json
import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class FfufTool(BaseTool):
    name = "ffuf"
    description = (
        "High-speed web fuzzer. Use FUZZ keyword in URL, headers, or POST data. "
        "Suitable for directory/file discovery, parameter fuzzing, and virtual host enumeration. "
        "Faster than gobuster for large wordlists."
    )
    risk_level = RiskLevel.MEDIUM
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL with FUZZ placeholder (e.g. 'http://site.com/FUZZ', 'http://site.com/page?id=FUZZ')",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist file",
                "default": "/usr/share/wordlists/dirb/common.txt",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE"],
                "description": "HTTP method",
                "default": "GET",
            },
            "data": {
                "type": "string",
                "description": "POST body with FUZZ keyword",
                "default": "",
            },
            "headers": {
                "type": "object",
                "description": "Additional HTTP headers as key-value pairs",
                "default": {},
            },
            "filter_codes": {
                "type": "string",
                "description": "HTTP status codes to FILTER OUT (e.g. '404,403')",
                "default": "404",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent threads",
                "default": 40,
            },
            "extensions": {
                "type": "string",
                "description": "File extensions (e.g. 'php,html')",
                "default": "",
            },
        },
        "required": ["url"],
    }

    def __init__(self, binary: str = "ffuf") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        url = params["url"]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        method = params.get("method", "GET")
        data = params.get("data", "")
        headers: dict[str, str] = params.get("headers", {})
        filter_codes = params.get("filter_codes", "404")
        threads = params.get("threads", 40)
        extensions = params.get("extensions", "")

        cmd = [
            self.binary,
            "-u", url,
            "-w", wordlist,
            "-X", method,
            "-t", str(threads),
            "-fc", filter_codes,
            "-o", "/dev/stdout",
            "-of", "json",
            "-noninteractive",
        ]
        if data:
            cmd.extend(["-d", data])
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        if extensions:
            cmd.extend(["-e", extensions])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=300)
        duration = time.monotonic() - t0

        results = self._parse_json(stdout)
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_results(results, url),
            raw_output=stdout,
            metadata={"results": results},
            duration_seconds=duration,
        )

    def _parse_json(self, output: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(output)
            return data.get("results", [])
        except json.JSONDecodeError:
            pass
        # fallback: parse text output
        results = []
        for line in output.splitlines():
            if "[Status:" in line:
                results.append({"input": {"FUZZ": line.split()[0]}, "status": 0, "length": 0})
        return results

    def _format_results(self, results: list[dict[str, Any]], url: str) -> str:
        if not results:
            return f"ffuf: No results found on {url}"
        lines = [f"ffuf found {len(results)} result(s):"]
        for r in results:
            fuzz_val = r.get("input", {}).get("FUZZ", r.get("url", ""))
            status = r.get("status", "")
            length = r.get("length", "")
            lines.append(f"  {fuzz_val}  [Status: {status}, Length: {length}]")
        return "\n".join(lines)
