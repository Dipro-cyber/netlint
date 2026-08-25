"""
Thin compatibility shim — delegates to
:mod:`netlint.analyzer.scoring`.

The terminal formatter imports ``compute_risk_score``, ``risk_label``,
and ``risk_style`` from this module.  All three now delegate to the
canonical scoring implementation so there is a single source of truth.
"""

from __future__ import annotations

from netlint.analyzer.scoring import RiskScore, score_result
from netlint.models.result import AnalysisResult

# Re-export so external code that imports from output.risk still works.
__all__ = ["compute_risk_score", "risk_label", "risk_style", "RiskScore"]


def compute_risk_score(result: AnalysisResult) -> int:
    """Return the numeric risk score (0–100) for *result*."""
    return score_result(result).score


def risk_label(score: int) -> str:
    """Return the human-readable risk label for a given *score*."""
    from netlint.analyzer.scoring import _classify
    label, _ = _classify(score)
    return label


def risk_style(score: int) -> str:
    """Return the Rich markup style string for a given *score*."""
    from netlint.analyzer.scoring import _classify
    _, style = _classify(score)
    return style
