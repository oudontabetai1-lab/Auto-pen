"""CVSS v3.1 scoring helpers."""

from __future__ import annotations

from autopen.state.models import Severity


# Approximate CVSS base score ranges by severity
SEVERITY_SCORE_RANGES: dict[str, tuple[float, float]] = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.INFO:     (0.0, 0.0),
}


def severity_from_score(score: float) -> Severity:
    """Map a CVSS score to a Severity enum value."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def default_score_for_severity(severity: str) -> float:
    """Return the midpoint score for a given severity label (for display purposes)."""
    ranges = SEVERITY_SCORE_RANGES.get(severity, (0.0, 0.0))
    return round((ranges[0] + ranges[1]) / 2, 1)


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def sort_findings_by_severity(findings: list) -> list:
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )
