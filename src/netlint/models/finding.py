"""
Finding model — the output produced by every lint rule.

A Finding is richer than a bare LintIssue: it carries category, title,
and recommendation so the output layer can present a self-contained
human-readable report without consulting the originating rule.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """
    Severity levels, ordered from lowest to highest impact.

    The integer ``weight`` property lets findings be sorted numerically.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]


_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------


class RuleCategory(StrEnum):
    """Logical grouping for rules — used in reports and the `rules` command."""

    SECURITY = "security"
    NETWORK = "network"
    VLAN = "vlan"
    ROUTING = "routing"
    INTERFACE = "interface"
    ACL = "acl"
    MANAGEMENT = "management"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single problem discovered by a lint rule.

    All fields are immutable after construction.  ``line_number`` and
    ``configuration_line`` may be ``None`` when the problem is structural
    rather than tied to a specific config line (e.g. a missing hostname).
    """

    rule_id: str
    """Unique rule identifier, e.g. ``'SEC001'``."""

    severity: Severity
    """How serious the problem is."""

    category: RuleCategory
    """Which logical category this finding belongs to."""

    title: str
    """Short one-line summary of the problem (≤ 80 chars)."""

    message: str
    """Full human-readable description of the specific problem found."""

    recommendation: str
    """Actionable remediation advice."""

    file: Path
    """Path to the configuration file where the problem was found."""

    line_number: int | None = None
    """1-based line number in the original file, when available."""

    configuration_line: str | None = None
    """The exact configuration line that triggered the finding."""

    model_config = {"frozen": True}

    def sort_key(self) -> tuple[int, int]:
        """
        Returns a tuple suitable for sorting findings.

        Primary:   severity descending (CRITICAL first).
        Secondary: line_number ascending (problems at the top of the file first).
        """
        return (-self.severity.weight, self.line_number or 0)
