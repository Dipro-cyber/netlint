"""
AnalysisResult — the aggregate output of a full analysis run.

Replaces the old ``LintResult`` with richer typed fields.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from netlint.models.finding import Finding, Severity


class AnalysisResult(BaseModel):
    """
    All findings from analyzing one configuration file.

    ``findings`` is always sorted: CRITICAL first, then by line number.
    """

    file_path: Path
    findings: tuple[Finding, ...] = ()
    vendor: str = "cisco-ios"
    parser_warnings: tuple[str, ...] = ()

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings at exactly *severity*."""
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: str) -> list[Finding]:
        """Return all findings in the given category string."""
        return [f for f in self.findings if f.category.value == category.lower()]

    # Keep old name for any code still using LintResult
    @property
    def has_issues(self) -> bool:
        return self.has_findings

    @property
    def error_count(self) -> int:
        return self.critical_count + self.high_count
