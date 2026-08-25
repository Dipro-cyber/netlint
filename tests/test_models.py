"""
Tests for core data models (ConfigFile, Finding, AnalysisResult, Severity).
"""

from pathlib import Path

import pytest

from netlint.models.config_file import ConfigFile
from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult


# ---------------------------------------------------------------------------
# ConfigFile
# ---------------------------------------------------------------------------


def test_config_file_lines_auto_derived() -> None:
    """Lines should be derived from raw_text automatically."""
    cfg = ConfigFile(
        file_path=Path("/tmp/test.cfg"),
        raw_text="line one\nline two\nline three",
        vendor="cisco-ios",
        lines=(),
    )
    assert cfg.lines == ("line one", "line two", "line three")


def test_config_file_is_immutable() -> None:
    """ConfigFile must be frozen (immutable)."""
    cfg = ConfigFile(
        file_path=Path("/tmp/test.cfg"),
        raw_text="hostname R1",
        vendor="cisco-ios",
        lines=(),
    )
    with pytest.raises(Exception):
        cfg.raw_text = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_finding_creation() -> None:
    """A Finding should store all fields correctly."""
    f = Finding(
        rule_id="NET001",
        severity=Severity.CRITICAL,
        category=RuleCategory.NETWORK,
        title="Duplicate IP",
        message="Duplicate IP address detected",
        recommendation="Assign unique IPs.",
        file=Path("/tmp/router.cfg"),
        line_number=42,
        configuration_line="ip address 10.0.0.1 255.255.255.0",
    )
    assert f.rule_id == "NET001"
    assert f.severity == Severity.CRITICAL
    assert f.line_number == 42
    assert f.category == RuleCategory.NETWORK


def test_finding_optional_fields_default_none() -> None:
    f = Finding(
        rule_id="X001",
        severity=Severity.INFO,
        category=RuleCategory.NETWORK,
        title="T",
        message="M",
        recommendation="R",
        file=Path("/tmp/t.cfg"),
    )
    assert f.line_number is None
    assert f.configuration_line is None


def test_finding_is_immutable() -> None:
    f = Finding(
        rule_id="X001",
        severity=Severity.INFO,
        category=RuleCategory.NETWORK,
        title="T",
        message="M",
        recommendation="R",
        file=Path("/tmp/t.cfg"),
    )
    with pytest.raises(Exception):
        f.message = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------


def _finding(severity: Severity, rule_id: str = "T001") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=RuleCategory.NETWORK,
        title="T",
        message="M",
        recommendation="R",
        file=Path("/tmp/router.cfg"),
    )


def test_lint_result_no_issues() -> None:
    """A result with no findings should report correctly."""
    result = AnalysisResult(file_path=Path("/tmp/router.cfg"))
    assert not result.has_findings
    assert result.critical_count == 0
    assert result.high_count == 0


def test_lint_result_counts() -> None:
    """Per-severity counts should aggregate correctly."""
    findings = (
        _finding(Severity.CRITICAL, "T001"),
        _finding(Severity.CRITICAL, "T002"),
        _finding(Severity.HIGH,     "T003"),
        _finding(Severity.MEDIUM,   "T004"),
        _finding(Severity.LOW,      "T005"),
        _finding(Severity.INFO,     "T006"),
    )
    result = AnalysisResult(file_path=Path("/tmp/router.cfg"), findings=findings)
    assert result.has_findings
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.medium_count == 1
    assert result.low_count == 1
    assert result.info_count == 1


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_values() -> None:
    """Severity enum values should be stable strings."""
    assert Severity.INFO == "info"
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"


def test_severity_weights_ordered() -> None:
    assert Severity.INFO.weight < Severity.LOW.weight
    assert Severity.LOW.weight < Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight < Severity.HIGH.weight
    assert Severity.HIGH.weight < Severity.CRITICAL.weight
