"""Unit tests for reporting modules."""

from __future__ import annotations

import pytest

from autopen.reporting.cvss import (
    SEVERITY_EMOJI,
    SEVERITY_ORDER,
    default_score_for_severity,
    severity_from_score,
    sort_findings_by_severity,
)
from autopen.state.models import Severity


class TestSeverityFromScore:
    def test_critical(self):
        assert severity_from_score(9.0) == Severity.CRITICAL
        assert severity_from_score(10.0) == Severity.CRITICAL

    def test_high(self):
        assert severity_from_score(7.0) == Severity.HIGH
        assert severity_from_score(8.9) == Severity.HIGH

    def test_medium(self):
        assert severity_from_score(4.0) == Severity.MEDIUM
        assert severity_from_score(6.9) == Severity.MEDIUM

    def test_low(self):
        assert severity_from_score(0.1) == Severity.LOW
        assert severity_from_score(3.9) == Severity.LOW

    def test_info(self):
        assert severity_from_score(0.0) == Severity.INFO


class TestDefaultScore:
    def test_critical_midpoint(self):
        score = default_score_for_severity(Severity.CRITICAL)
        assert 9.0 <= score <= 10.0

    def test_info_is_zero(self):
        assert default_score_for_severity(Severity.INFO) == 0.0

    def test_unknown_severity(self):
        assert default_score_for_severity("unknown") == 0.0


class TestSeverityEmoji:
    def test_all_severities_have_emoji(self):
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            assert sev in SEVERITY_EMOJI
            assert SEVERITY_EMOJI[sev]


class TestSortFindingsBySeverity:
    def _make_finding(self, severity):
        class FakeFinding:
            pass
        f = FakeFinding()
        f.severity = severity
        return f

    def test_sorts_critical_first(self):
        findings = [
            self._make_finding(Severity.LOW),
            self._make_finding(Severity.CRITICAL),
            self._make_finding(Severity.MEDIUM),
        ]
        sorted_f = sort_findings_by_severity(findings)
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[-1].severity == Severity.LOW

    def test_empty_list(self):
        assert sort_findings_by_severity([]) == []


class TestCveEnricher:
    def test_extract_cve_ids_empty(self):
        from autopen.reporting.cve_enricher import CveEnricher
        enricher = CveEnricher()
        assert enricher.extract_cve_ids("no CVEs here") == []

    def test_extract_cve_ids_single(self):
        from autopen.reporting.cve_enricher import CveEnricher
        enricher = CveEnricher()
        ids = enricher.extract_cve_ids("Found CVE-2021-44228 in log4j")
        assert ids == ["CVE-2021-44228"]

    def test_extract_cve_ids_dedup(self):
        from autopen.reporting.cve_enricher import CveEnricher
        enricher = CveEnricher()
        ids = enricher.extract_cve_ids("CVE-2021-44228 and CVE-2021-44228 again")
        assert ids == ["CVE-2021-44228"]

    def test_extract_cve_ids_multiple(self):
        from autopen.reporting.cve_enricher import CveEnricher
        enricher = CveEnricher()
        ids = enricher.extract_cve_ids("CVE-2021-44228 CVE-2014-0160 cve-2017-5638")
        assert len(ids) == 3
        assert all(i.startswith("CVE-") for i in ids)

    def test_extract_cve_ids_case_insensitive(self):
        from autopen.reporting.cve_enricher import CveEnricher
        enricher = CveEnricher()
        ids = enricher.extract_cve_ids("cve-2021-44228")
        assert ids == ["CVE-2021-44228"]
