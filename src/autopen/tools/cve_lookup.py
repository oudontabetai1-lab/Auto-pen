"""CVE lookup tool — queries NIST NVD API v2 for vulnerability details."""

from __future__ import annotations

import time
from typing import Any

import httpx

from autopen.tools.base import BaseTool, RiskLevel, ToolResult

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveLookupTool(BaseTool):
    name = "cve_lookup"
    description = (
        "Look up CVE details from NIST NVD for a given CVE ID or keyword. "
        "Returns severity, CVSS score, description, and references."
    )
    risk_level = RiskLevel.LOW
    binary = ""
    parameters_schema = {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE identifier (e.g. 'CVE-2021-44228')",
            },
            "keyword": {
                "type": "string",
                "description": "Keyword to search CVEs (returns up to 5 results)",
            },
        },
    }

    def is_available(self) -> bool:
        return True

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        cve_id = params.get("cve_id", "").strip()
        keyword = params.get("keyword", "").strip()

        if not cve_id and not keyword:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output="Either 'cve_id' or 'keyword' parameter is required.",
                error="Missing parameters",
            )

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if cve_id:
                    response = await client.get(NVD_API_URL, params={"cveId": cve_id.upper()})
                else:
                    response = await client.get(
                        NVD_API_URL,
                        params={"keywordSearch": keyword, "resultsPerPage": 5},
                    )
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            duration = time.monotonic() - t0
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"NVD API request failed: HTTP {exc.response.status_code}",
                error=str(exc),
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = time.monotonic() - t0
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"NVD API unavailable: {exc}",
                error=str(exc),
                duration_seconds=duration,
            )

        duration = time.monotonic() - t0
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            query = cve_id or keyword
            return ToolResult(
                tool_name=self.name,
                success=True,
                output=f"No CVEs found for: {query}",
                duration_seconds=duration,
            )

        lines: list[str] = []
        parsed: list[dict[str, Any]] = []
        for item in vulnerabilities:
            entry = self._parse_cve(item)
            parsed.append(entry)
            lines.append(self._format_entry(entry))

        return ToolResult(
            tool_name=self.name,
            success=True,
            output="\n\n".join(lines),
            metadata={"cves": parsed},
            duration_seconds=duration,
        )

    def _parse_cve(self, item: dict[str, Any]) -> dict[str, Any]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")[:10] if cve.get("published") else ""

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        cvss_score: float | None = None
        severity: str = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "")
                break

        references = [
            ref["url"]
            for ref in cve.get("references", [])
            if ref.get("url")
        ]
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if nvd_url not in references:
            references.insert(0, nvd_url)

        return {
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": published,
            "references": references[:5],
        }

    def _format_entry(self, entry: dict[str, Any]) -> str:
        lines = [entry["id"]]
        if entry["severity"] and entry["cvss_score"] is not None:
            lines.append(f"  Severity: {entry['severity']} (CVSS {entry['cvss_score']})")
        elif entry["severity"]:
            lines.append(f"  Severity: {entry['severity']}")
        if entry["published"]:
            lines.append(f"  Published: {entry['published']}")
        if entry["description"]:
            desc = entry["description"]
            if len(desc) > 300:
                desc = desc[:297] + "..."
            lines.append(f"  Description: {desc}")
        for ref in entry["references"][:3]:
            lines.append(f"  References: {ref}")
        return "\n".join(lines)
