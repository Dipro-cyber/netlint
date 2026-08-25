"""
New-risk detection — determines which findings in the new config are
genuinely *new* (not present in the old config).

Algorithm
---------
A finding is considered "new" when its fingerprint does not appear in
the old config's finding set.

Fingerprint
-----------
A finding is identified by ``(rule_id, message)``.  We deliberately
exclude ``file`` and ``line_number``:

* ``file`` is different by definition (old vs new path).
* ``line_number`` changes whenever any line is inserted/deleted above
  the affected stanza; using it would produce false positives on any
  config that was simply reformatted.

The ``message`` field typically includes the affected interface name,
IP address, or VLAN ID, which gives enough specificity to distinguish
"duplicate IP on Gi0/0" from "duplicate IP on Gi0/1".

Result
------
:class:`DiffRiskResult` carries:
- ``new_findings``     — findings present in new but not in old
- ``resolved_findings`` — findings present in old but gone in new
- ``persisting_findings`` — findings present in both
- ``deployment_recommendation`` — DO NOT DEPLOY / REVIEW BEFORE DEPLOYING / SAFE TO DEPLOY
"""

from __future__ import annotations

from dataclasses import dataclass

from netlint.models.finding import Finding, Severity
from netlint.models.result import AnalysisResult


def _fingerprint(f: Finding) -> tuple[str, str]:
    """Return a stable identity for *f* that survives file/line changes."""
    return (f.rule_id, f.message)


@dataclass(frozen=True)
class DiffRiskResult:
    """Risk comparison between an old and a new configuration."""

    old_result: AnalysisResult
    new_result: AnalysisResult

    new_findings: tuple[Finding, ...]
    """Findings that appear in new but not in old."""

    resolved_findings: tuple[Finding, ...]
    """Findings that were in old but are gone in new (improvements)."""

    persisting_findings: tuple[Finding, ...]
    """Findings present in both configs (unchanged problems)."""

    deployment_recommendation: str
    """Human-readable deployment guidance."""

    recommendation_style: str
    """Rich markup style for the recommendation string."""

    @property
    def has_new_risks(self) -> bool:
        return len(self.new_findings) > 0

    @property
    def new_critical_count(self) -> int:
        return sum(1 for f in self.new_findings if f.severity == Severity.CRITICAL)

    @property
    def new_high_count(self) -> int:
        return sum(1 for f in self.new_findings if f.severity == Severity.HIGH)


def compare_results(
    old_result: AnalysisResult,
    new_result: AnalysisResult,
) -> DiffRiskResult:
    """
    Compare *old_result* and *new_result* and return a :class:`DiffRiskResult`.

    This function is pure: given the same inputs it always produces the
    same output.
    """
    old_fps = {_fingerprint(f): f for f in old_result.findings}
    new_fps = {_fingerprint(f): f for f in new_result.findings}

    old_keys = set(old_fps)
    new_keys = set(new_fps)

    new_findings = tuple(
        sorted(
            (new_fps[k] for k in new_keys - old_keys),
            key=lambda f: f.sort_key(),
        )
    )
    resolved_findings = tuple(
        sorted(
            (old_fps[k] for k in old_keys - new_keys),
            key=lambda f: f.sort_key(),
        )
    )
    persisting_findings = tuple(
        sorted(
            (new_fps[k] for k in old_keys & new_keys),
            key=lambda f: f.sort_key(),
        )
    )

    recommendation, style = _recommend(new_findings)

    return DiffRiskResult(
        old_result=old_result,
        new_result=new_result,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persisting_findings=persisting_findings,
        deployment_recommendation=recommendation,
        recommendation_style=style,
    )


def _recommend(new_findings: tuple[Finding, ...]) -> tuple[str, str]:
    """
    Derive a deployment recommendation from the new findings.

    Returns (recommendation_text, rich_style).
    """
    if not new_findings:
        return "SAFE TO DEPLOY", "bold green"

    max_sev = max(f.severity.weight for f in new_findings)

    if max_sev >= Severity.HIGH.weight:
        return "DO NOT DEPLOY", "bold red"

    if max_sev >= Severity.MEDIUM.weight:
        return "REVIEW BEFORE DEPLOYING", "bold yellow"

    return "SAFE TO DEPLOY (minor issues found)", "bold green"
