"""
Network configuration risk-scoring system.

Score convention
----------------
100 = no detected risk (clean configuration)
  0 = extremely risky (maximum penalty reached)

This is intentionally the *opposite* of a penalty counter: the score
represents how much safety budget remains after deducting points for
each finding.

Algorithm — step by step
-------------------------
1.  Start with a perfect score of 100.

2.  For every finding, deduct a *severity penalty*:

        Severity   Penalty
        --------   -------
        CRITICAL      30
        HIGH          18
        MEDIUM         8
        LOW            3
        INFO           1

    The CRITICAL penalty is 10× that of INFO and ~1.7× that of HIGH,
    ensuring that a single CRITICAL finding has substantially more
    impact than several LOW findings.

3.  Apply *diminishing returns* for repeated findings at the same
    severity level.  The second finding of the same severity contributes
    80 % of a full penalty, the third 64 %, the fourth 51 %, and so on
    (each successive finding is multiplied by a decay factor of 0.8).
    This prevents pathological configs (e.g. 50 duplicate IPs) from
    collapsing the score to zero when there is really only one *type* of
    problem — while still ensuring that genuinely diverse problems drive
    the score lower.

    The first finding of each severity level always contributes its
    full penalty (decay exponent 0, so multiplier = 1.0).

4.  Sum all discounted penalties, round to the nearest integer, and
    clamp the result to [0, 100].

5.  Subtract the clamped penalty sum from 100:

        score = max(0, 100 - total_penalty)

Determinism guarantee
---------------------
The algorithm depends only on the *counts* of findings at each severity
level, not on their order, file path, rule ID, or message content.
Given the same set of severities the output is always identical.

Risk levels
-----------
The numeric score is mapped to a human-readable risk level:

    Score    Level
    -----    -----
    100      CLEAN
    80–99    LOW
    60–79    MEDIUM
    40–59    HIGH
    1–39     CRITICAL
    0        CRITICAL

Examples
--------
Zero findings:
    score = 100,  level = CLEAN

One CRITICAL finding:
    penalty = 30 × 1.0 = 30
    score   = 100 − 30 = 70  → HIGH

One CRITICAL + one HIGH:
    penalty = 30 + 18 = 48
    score   = 100 − 48 = 52  → HIGH (near boundary)

Two CRITICAL findings:
    penalty = 30×1.0 + 30×0.8 = 30 + 24 = 54
    score   = 100 − 54 = 46  → HIGH

Four CRITICAL findings:
    penalty = 30×1.0 + 30×0.8 + 30×0.64 + 30×0.512
            = 30 + 24 + 19.2 + 15.36 = 88.56 → clamped to 88 → ≈ 88
    score   = 100 − 88 = 12  → CRITICAL

Ten LOW findings vs one CRITICAL:
    Ten LOW:  3×(1+0.8+0.64+0.51+0.41+0.33+0.26+0.21+0.17+0.13)
            = 3 × 4.47 ≈ 13.4  → score ≈ 87  → LOW
    One CRITICAL: 30            → score = 70  → HIGH
    The single CRITICAL is riskier — correct.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence

from netlint.models.finding import Severity
from netlint.models.result import AnalysisResult

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

#: Base penalty deducted for a single finding at each severity level.
SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 30.0,
    Severity.HIGH:     18.0,
    Severity.MEDIUM:    8.0,
    Severity.LOW:       3.0,
    Severity.INFO:      1.0,
}

#: Decay factor applied to each successive finding of the same severity.
#: Value must be in (0, 1).  0.8 means each repeat contributes 80 % of
#: the previous one (geometric decay).
DECAY_FACTOR: float = 0.8

# ---------------------------------------------------------------------------
# Risk level bands  (score thresholds, inclusive)
# ---------------------------------------------------------------------------

#: (min_score, max_score, label, Rich style)
RISK_BANDS: list[tuple[int, int, str, str]] = [
    (100, 100, "CLEAN",    "bold green"),
    (80,   99, "LOW",      "bold green"),
    (60,   79, "MEDIUM",   "bold yellow"),
    (40,   59, "HIGH",     "bold red"),
    (0,    39, "CRITICAL", "bold red"),
]


# ---------------------------------------------------------------------------
# Public data class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskScore:
    """
    The complete risk-scoring result for one analysis run.

    All attributes are read-only after construction.
    """

    score: int
    """Numeric risk score in [0, 100]. Higher is safer."""

    level: str
    """Human-readable risk level: CLEAN | LOW | MEDIUM | HIGH | CRITICAL."""

    style: str
    """Rich markup style string for the level label."""

    critical_count: int
    """Number of CRITICAL findings."""

    high_count: int
    """Number of HIGH findings."""

    medium_count: int
    """Number of MEDIUM findings."""

    low_count: int
    """Number of LOW findings."""

    info_count: int
    """Number of INFO findings."""

    total_findings: int
    """Total number of findings across all severities."""

    penalty_applied: float
    """Raw (pre-clamp) penalty sum, for diagnostic purposes."""


# ---------------------------------------------------------------------------
# Scoring function
# ---------------------------------------------------------------------------


def score_result(result: AnalysisResult) -> RiskScore:
    """
    Compute and return the :class:`RiskScore` for *result*.

    This is the primary public entry point.  The function is pure and
    deterministic: given the same ``AnalysisResult`` it always returns
    the same ``RiskScore``.
    """
    return score_findings(result.findings)


def score_findings(findings: Sequence) -> RiskScore:
    """
    Compute :class:`RiskScore` from an arbitrary sequence of
    :class:`~netlint.models.finding.Finding` objects.

    Separating this from :func:`score_result` makes unit testing
    straightforward — tests can pass a plain list of findings without
    constructing a full ``AnalysisResult``.
    """
    # Count findings per severity
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1

    # Calculate total discounted penalty
    total_penalty: float = 0.0
    for sev, count in counts.items():
        base = SEVERITY_PENALTY[sev]
        for i in range(count):
            # i=0 → multiplier 1.0, i=1 → 0.8, i=2 → 0.64, …
            total_penalty += base * (DECAY_FACTOR ** i)

    clamped_penalty = min(total_penalty, 100.0)
    score = max(0, round(100.0 - clamped_penalty))

    level, style = _classify(score)

    return RiskScore(
        score=score,
        level=level,
        style=style,
        critical_count=counts[Severity.CRITICAL],
        high_count=counts[Severity.HIGH],
        medium_count=counts[Severity.MEDIUM],
        low_count=counts[Severity.LOW],
        info_count=counts[Severity.INFO],
        total_findings=sum(counts.values()),
        penalty_applied=total_penalty,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _classify(score: int) -> tuple[str, str]:
    """Return *(label, style)* for *score*."""
    for lo, hi, label, style in RISK_BANDS:
        if lo <= score <= hi:
            return label, style
    # Unreachable with a clamped [0,100] score, but be safe
    return "CRITICAL", "bold red"
