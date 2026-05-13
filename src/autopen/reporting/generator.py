"""Report generator — produces Markdown and JSON reports from session data."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from autopen.reporting.cve_enricher import CveEnricher
from autopen.reporting.cvss import (
    SEVERITY_EMOJI,
    default_score_for_severity,
    sort_findings_by_severity,
)
from autopen.state.manager import SessionManager
from autopen.state.models import DBFinding, Severity


class ReportGenerator:
    """Generates pentest reports from a completed (or in-progress) session."""

    def __init__(self, manager: SessionManager) -> None:
        self.manager = manager

    def generate_markdown(self, session_id: str) -> str:
        session = self.manager.get_session(session_id)
        if not session:
            return f"# Error: Session {session_id} not found"

        findings = sort_findings_by_severity(self.manager.list_findings(session_id))
        audit_logs = self.manager.list_audit_logs(session_id)

        lines: list[str] = []

        # ── Header ────────────────────────────────────────
        lines += [
            "# Penetration Test Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Session ID:** `{session.id}`",
            f"**Target:** `{session.target}`",
            f"**Profile:** {session.profile.upper()}",
            f"**Status:** {session.status.upper()}",
            f"**LLM:** {session.llm_provider}/{session.llm_model}",
            f"**Steps Executed:** {session.step_count}",
            "",
            "---",
            "",
        ]

        # ── Authorization ──────────────────────────────────
        lines += [
            "## Authorization",
            "",
            f"> {session.authorization_token}",
            "",
        ]

        # ── Executive Summary ──────────────────────────────
        counts = self._count_by_severity(findings)
        lines += [
            "## Executive Summary",
            "",
            f"A security assessment was conducted against `{session.target}` "
            f"using the **{session.profile.upper()}** profile. "
            f"The assessment identified **{len(findings)}** finding(s):",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev.upper()} | {counts.get(sev, 0)} |")

        lines += ["", "---", ""]

        # ── Findings ───────────────────────────────────────
        lines += ["## Findings", ""]
        if not findings:
            lines.append("_No findings recorded._")
        else:
            for i, finding in enumerate(findings, 1):
                emoji = SEVERITY_EMOJI.get(finding.severity, "")
                cvss = finding.cvss_score or default_score_for_severity(finding.severity)
                lines += [
                    f"### {i}. {emoji} [{finding.severity.upper()}] {finding.title}",
                    "",
                    f"- **Severity:** {finding.severity.upper()}",
                    f"- **CVSS Score:** {cvss}",
                    f"- **Target:** `{finding.target}`",
                    f"- **Discovered by:** `{finding.tool_name}`",
                    f"- **Timestamp:** {finding.timestamp.strftime('%Y-%m-%d %H:%M UTC')}",
                    "",
                    "**Description:**",
                    "",
                    finding.description,
                    "",
                ]
                if finding.evidence:
                    lines += [
                        "**Evidence:**",
                        "",
                        "```",
                        finding.evidence[:2000],
                        "```",
                        "",
                    ]
                if finding.remediation:
                    lines += [
                        "**Remediation:**",
                        "",
                        finding.remediation,
                        "",
                    ]
                lines += ["---", ""]

        # ── CVE References ──────────────────────────────
        all_text = " ".join(
            (f.description or "") + " " + (f.evidence or "") for f in findings
        )
        enricher = CveEnricher()
        cve_ids = enricher.extract_cve_ids(all_text)
        if cve_ids:
            cve_data = enricher.enrich_sync(cve_ids)
            lines += ["## CVE References", ""]
            for cve_id, info in cve_data.items():
                lines.append(f"### {cve_id}")
                lines.append("")
                if info.get("severity") and info.get("cvss_score") is not None:
                    lines.append(f"- **Severity:** {info['severity']} (CVSS {info['cvss_score']})")
                if info.get("published"):
                    lines.append(f"- **Published:** {info['published']}")
                if info.get("description"):
                    lines.append(f"- **Description:** {info['description']}")
                for ref in info.get("references", [])[:3]:
                    lines.append(f"- **Reference:** {ref}")
                lines.append("")
            lines += ["---", ""]

        # ── Tools Used ────────────────────────────────────
        tools_used = sorted({log.tool_name for log in audit_logs if log.tool_name})
        lines += [
            "## Tools Used",
            "",
            ", ".join(f"`{t}`" for t in tools_used) if tools_used else "_None_",
            "",
            "---",
            "",
        ]

        # ── Audit Log Summary ──────────────────────────────
        lines += [
            "## Audit Log Summary",
            "",
            f"Total actions: {len(audit_logs)}",
            "",
            "| Timestamp | Tool | Action | Risk |",
            "|-----------|------|--------|------|",
        ]
        for log in audit_logs[-50:]:  # last 50 entries
            ts = log.timestamp.strftime("%H:%M:%S")
            lines.append(
                f"| {ts} | {log.tool_name or '-'} | {log.action} | {log.risk_level} |"
            )

        lines += ["", "---", "", "_Report generated by Auto-pen_"]

        return "\n".join(lines)

    def generate_json(self, session_id: str) -> str:
        session = self.manager.get_session(session_id)
        if not session:
            return json.dumps({"error": f"Session {session_id} not found"})

        findings = sort_findings_by_severity(self.manager.list_findings(session_id))

        all_text = " ".join(
            (f.description or "") + " " + (f.evidence or "") for f in findings
        )
        enricher = CveEnricher()
        cve_ids = enricher.extract_cve_ids(all_text)
        cve_references: dict[str, Any] = enricher.enrich_sync(cve_ids) if cve_ids else {}

        data: dict[str, Any] = {
            "session": {
                "id": session.id,
                "target": session.target,
                "profile": session.profile,
                "status": session.status,
                "llm_provider": session.llm_provider,
                "llm_model": session.llm_model,
                "step_count": session.step_count,
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat(),
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity_raw(findings),
            },
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "tool_name": f.tool_name,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score or default_score_for_severity(f.severity),
                    "cvss_vector": f.cvss_vector,
                    "target": f.target,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in findings
            ],
            "cve_references": cve_references,
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------

    def _count_by_severity(self, findings: list[DBFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _count_by_severity_raw(self, findings: list[DBFinding]) -> dict[str, int]:
        return self._count_by_severity(findings)
