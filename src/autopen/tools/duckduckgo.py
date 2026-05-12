"""DuckDuckGo wrapper — passive OSINT search via lite HTML interface."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import quote_plus

import httpx

from autopen.tools.base import BaseTool, RiskLevel, ToolResult

# Primary: DDG lite table rows — <td class="result-link"> containing <a href="...">
_TD_RESULT_RE = re.compile(
    r'<td[^>]+class="(?:[^"]*\s)?result-link(?:\s[^"]*)?"\s*[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL,
)
# Fallback: any external <a href="https://..."> that doesn't look like a DDG UI link
_FALLBACK_HREF_RE = re.compile(
    r'<a[^>]+href="(https?://(?!duckduckgo\.com)[^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _parse_results(html: str, max_results: int) -> tuple[list[str], str]:
    """Return (result_lines, parser_used)."""
    matches = _TD_RESULT_RE.findall(html)
    if matches:
        lines = []
        for href, raw_title in matches[:max_results]:
            title = _TAG_RE.sub("", raw_title).strip() or href
            lines.append(f"{len(lines) + 1}. [{title}] {href}")
        return lines, "primary"

    # HTML structure may have changed — try the fallback
    fallback = _FALLBACK_HREF_RE.findall(html)
    seen: set[str] = set()
    lines = []
    for href, raw_title in fallback:
        if href in seen or len(lines) >= max_results:
            break
        seen.add(href)
        title = _TAG_RE.sub("", raw_title).strip() or href
        lines.append(f"{len(lines) + 1}. [{title}] {href}")
    return lines, "fallback"


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

        results, parser = _parse_results(html, max_results)

        if results:
            output = "\n".join(results)
            if parser == "fallback":
                output = "[note: using fallback parser — DDG HTML structure may have changed]\n" + output
        else:
            output = "No results found."

        return ToolResult(
            tool_name=self.name,
            success=True,
            output=output,
            raw_output=html,
            metadata={"result_count": len(results), "query": query, "parser": parser},
            duration_seconds=duration,
        )
