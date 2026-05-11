"""CVE enricher — extracts CVE IDs from text and fetches details from NVD."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import httpx

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD public rate limit: 5 requests / 30 s without API key
_NVD_RATE_DELAY = 0.6  # seconds between requests


class CveEnricher:
    """Extracts CVE IDs from text and fetches details from NVD."""

    def extract_cve_ids(self, text: str) -> list[str]:
        """Return unique CVE IDs found in text, uppercased."""
        matches = CVE_PATTERN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for m in matches:
            upper = m.upper()
            if upper not in seen:
                seen.add(upper)
                result.append(upper)
        return result

    # ------------------------------------------------------------------
    # Synchronous API (used by ReportGenerator which is called from
    # synchronous contexts and may already be inside a running event loop)
    # ------------------------------------------------------------------

    def enrich_sync(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Blocking version of enrich() — safe to call from synchronous code."""
        if not cve_ids:
            return {}
        results: dict[str, dict[str, Any]] = {}
        with httpx.Client(timeout=10.0) as client:
            for i, cve_id in enumerate(cve_ids):
                results[cve_id] = self._fetch_cve_sync(client, cve_id)
                # Respect NVD public rate limit between requests
                if i < len(cve_ids) - 1:
                    time.sleep(_NVD_RATE_DELAY)
        return results

    def _fetch_cve_sync(self, client: httpx.Client, cve_id: str) -> dict[str, Any]:
        """Fetch a single CVE synchronously. Returns a normalised dict."""
        try:
            response = client.get(NVD_API_URL, params={"cveId": cve_id})
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {
                "id": cve_id,
                "description": "",
                "cvss_score": None,
                "severity": "",
                "published": "",
                "references": [],
                "error": str(exc),
            }
        return self._parse_nvd_response(cve_id, data)

    # ------------------------------------------------------------------
    # Async API (used directly when running inside an async context)
    # ------------------------------------------------------------------

    async def enrich(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return dict of CVE ID -> NVD data dict for each CVE ID."""
        if not cve_ids:
            return {}
        results: dict[str, dict[str, Any]] = {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            for i, cve_id in enumerate(cve_ids):
                data = await self._fetch_cve(client, cve_id)
                results[cve_id] = data
                # Respect NVD public rate limit between requests
                if i < len(cve_ids) - 1:
                    await asyncio.sleep(_NVD_RATE_DELAY)
        return results

    async def _fetch_cve(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        """Fetch single CVE from NVD. Return normalised dict."""
        try:
            response = await client.get(NVD_API_URL, params={"cveId": cve_id})
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {
                "id": cve_id,
                "description": "",
                "cvss_score": None,
                "severity": "",
                "published": "",
                "references": [],
                "error": str(exc),
            }
        return self._parse_nvd_response(cve_id, data)

    # ------------------------------------------------------------------
    # Shared parsing logic
    # ------------------------------------------------------------------

    def _parse_nvd_response(self, cve_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Parse a raw NVD API response into a normalised dict."""
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {
                "id": cve_id,
                "description": "Not found in NVD.",
                "cvss_score": None,
                "severity": "",
                "published": "",
                "references": [],
            }

        cve = vulnerabilities[0].get("cve", {})
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

        references = [ref["url"] for ref in cve.get("references", []) if ref.get("url")]
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
