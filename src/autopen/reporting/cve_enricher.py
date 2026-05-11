"""CVE enricher — extracts CVE IDs from text and fetches details from NVD."""

from __future__ import annotations

import asyncio
import re

import httpx

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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

    async def enrich(self, cve_ids: list[str]) -> dict[str, dict]:
        """Return dict of CVE ID -> NVD data dict for each CVE ID."""
        if not cve_ids:
            return {}
        results: dict[str, dict] = {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            for cve_id in cve_ids:
                data = await self._fetch_cve(client, cve_id)
                results[cve_id] = data
                await asyncio.sleep(0.5)
        return results

    async def _fetch_cve(self, client: httpx.AsyncClient, cve_id: str) -> dict:
        """Fetch single CVE from NVD. Return dict with keys: id, description, cvss_score, severity, published, references."""
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
