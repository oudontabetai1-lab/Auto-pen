"""DuckDuckGo wrapper — passive OSINT search via lite HTML interface."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import quote_plus

import httpx

from autopen.tools.base import BaseTool, RiskLevel, ToolResult

# DDG lite renders results as table rows; each result link lives inside a
# <td class="result-link"> cell.  We match the <a href="..."> within that
# cell.  Using two separate patterns is more robust than a single greedy
# regex that relies on the exact attribute name/order on the <a> tag.
_TD_RESULT_RE = re.compile(
    r'<td[^>]+class="result-link"[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


class DuckDuckGoTool(BaseTool):
    name = "duckduckgo"
    description = (
        "Passive OSINT search using DuckDuckGo. No API key required. "
        "Retrieves web search results for a query, useful for gathering public intelligence "
        "about a target without direct interaction."
    )
    risk_level = RiskLevel.LOW
    parameters_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query (e.g. 'site:example.com filetype:pdf')",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results to return",
                "default": 10,
            },
        },
        "required": ["query"],
    }

    def is_available(self) -> bool:
        return True

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        query = params["query"]
        max_results = params.get("max_results", 10)
        url = f"https://lite.duckduckgo.com/lite/?q={quote_plus(query)}"
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                html = response.text
        except httpx.HTTPError as exc:
            duration = time.monotonic() - t0
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"DuckDuckGo request failed: {exc}",
                error=str(exc),
                duration_seconds=duration,
            )
        duration = time.monotonic() - t0

        matches = _TD_RESULT_RE.findall(html)
        results = []
        for href, raw_title in matches[:max_results]:
            title = _TAG_RE.sub("", raw_title).strip()
            results.append(f"{len(results) + 1}. [{title}] {href}")

        output = "\n".join(results) if results else "No results found."
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=output,
            raw_output=html,
            metadata={"result_count": len(results), "query": query},
            duration_seconds=duration,
        )
