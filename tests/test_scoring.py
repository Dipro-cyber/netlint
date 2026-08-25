"""
Tests for src/netlint/analyzer/scoring.py

Covers
------
- Zero findings → score 100, level CLEAN
- Only INFO findings
- Only LOW findings
- Only MEDIUM findings
- Only HIGH findings
- Only CRITICAL findings
- Mixed findings
- Diminishing returns: second finding of same severity costs less
- Many LOW findings vs one CRITICAL — CRITICAL must score lower
- Score clamped at 0 (never goes negative)
- Score clamped at 100 maximum
- Determinism — same inputs always produce same output
- RiskScore field values
- Risk-level band boundaries
- Per-severity counts on RiskScore
- score_result() delegates correctly to score_findings()
- The output/risk.py shim returns consistent values
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netlint.analyzer.scoring import (
    DECAY_FACTOR,
    SEVERITY_PENALTY,
    RiskScore,
    score_findings,
    score_result,
    _classify,
)
from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(severity: Severity, rule_id: str = "TST001") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=RuleCategory.NETWORK,
        title="Test finding",
        message="Test message",
        recommendation="Test recommendation",
        file=Path("/tmp/test.cfg"),
    )


def _findings(*severities: Severity) -> list[Finding]:
    return [_finding(sev, f"T{i:03d}") for i, sev in enumerate(severities)]


def _result(*severities: Severity) -> AnalysisResult:
    return AnalysisResult(
        file_path=Path("/tmp/test.cfg"),
        findings=tuple(_findings(*severities)),
    )


# ---------------------------------------------------------------------------
# Zero findings
# ---------------------------------------------------------------------------


class TestZeroFindings:
    def test_score_is_100(self):
        rs = score_findings([])
        assert rs.score == 100

    def test_level_is_clean(self):
        rs = score_findings([])
        assert rs.level == "CLEAN"

    def test_all_counts_zero(self):
        rs = score_findings([])
        assert rs.critical_count == 0
        assert rs.high_count == 0
        assert rs.medium_count == 0
        assert rs.low_count == 0
        assert rs.info_count == 0

    def test_total_findings_zero(self):
        rs = score_findings([])
        assert rs.total_findings == 0

    def test_penalty_zero(self):
        rs = score_findings([])
        assert rs.penalty_applied == 0.0


# ---------------------------------------------------------------------------
# Single finding at each severity
# ---------------------------------------------------------------------------


class TestSingleFinding:
    def test_one_info_score(self):
        rs = score_findings(_findings(Severity.INFO))
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.INFO]))
        assert rs.score == expected

    def test_one_info_level(self):
        rs = score_findings(_findings(Severity.INFO))
        assert rs.level in ("CLEAN", "LOW")

    def test_one_low_score(self):
        rs = score_findings(_findings(Severity.LOW))
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.LOW]))
        assert rs.score == expected

    def test_one_medium_score(self):
        rs = score_findings(_findings(Severity.MEDIUM))
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.MEDIUM]))
        assert rs.score == expected

    def test_one_high_score(self):
        rs = score_findings(_findings(Severity.HIGH))
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.HIGH]))
        assert rs.score == expected

    def test_one_critical_score(self):
        rs = score_findings(_findings(Severity.CRITICAL))
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.CRITICAL]))
        assert rs.score == expected

    def test_severity_ordering(self):
        """Higher severity must always produce a lower (worse) score."""
        info_score = score_findings(_findings(Severity.INFO)).score
        low_score = score_findings(_findings(Severity.LOW)).score
        med_score = score_findings(_findings(Severity.MEDIUM)).score
        high_score = score_findings(_findings(Severity.HIGH)).score
        crit_score = score_findings(_findings(Severity.CRITICAL)).score

        assert info_score > low_score
        assert low_score > med_score
        assert med_score > high_score
        assert high_score > crit_score

    def test_one_critical_substantially_worse_than_one_low(self):
        """CRITICAL must have substantially more impact than LOW."""
        low_score = score_findings(_findings(Severity.LOW)).score
        crit_score = score_findings(_findings(Severity.CRITICAL)).score
        assert low_score - crit_score >= 20

    def test_one_critical_count(self):
        rs = score_findings(_findings(Severity.CRITICAL))
        assert rs.critical_count == 1
        assert rs.high_count == 0

    def test_one_high_count(self):
        rs = score_findings(_findings(Severity.HIGH))
        assert rs.high_count == 1
        assert rs.critical_count == 0


# ---------------------------------------------------------------------------
# Diminishing returns
# ---------------------------------------------------------------------------


class TestDiminishingReturns:
    def test_second_critical_costs_less_than_first(self):
        one = score_findings(_findings(Severity.CRITICAL))
        two = score_findings(_findings(Severity.CRITICAL, Severity.CRITICAL))
        # First finding drops score by PENALTY; second by PENALTY * DECAY
        first_drop = 100 - one.score
        second_drop = one.score - two.score
        assert second_drop < first_drop

    def test_second_critical_drop_matches_decay_factor(self):
        """Second CRITICAL penalty = first_penalty * DECAY_FACTOR."""
        base = SEVERITY_PENALTY[Severity.CRITICAL]
        one_score = score_findings(_findings(Severity.CRITICAL)).score
        two_score = score_findings(_findings(Severity.CRITICAL, Severity.CRITICAL)).score
        expected_second_drop = round(base * DECAY_FACTOR)
        actual_second_drop = one_score - two_score
        assert abs(actual_second_drop - expected_second_drop) <= 1  # allow rounding

    def test_diminishing_across_five_criticals(self):
        """Each successive CRITICAL finding must reduce the score by
        a strictly smaller amount than the previous one."""
        scores = [
            score_findings(_findings(*([Severity.CRITICAL] * n))).score
            for n in range(1, 6)
        ]
        drops = [100 - scores[0]] + [scores[i - 1] - scores[i] for i in range(1, len(scores))]
        for i in range(1, len(drops)):
            assert drops[i] < drops[i - 1], (
                f"Drop at index {i} ({drops[i]}) is not less than "
                f"drop at index {i-1} ({drops[i-1]})"
            )

    def test_decay_is_independent_per_severity(self):
        """Decay counters are independent: two CRITICALs and two HIGHs
        each apply their own decay independently."""
        two_crit = score_findings(_findings(Severity.CRITICAL, Severity.CRITICAL))
        two_high = score_findings(_findings(Severity.HIGH, Severity.HIGH))
        mixed = score_findings(
            _findings(Severity.CRITICAL, Severity.CRITICAL, Severity.HIGH, Severity.HIGH)
        )
        expected_penalty = (
            SEVERITY_PENALTY[Severity.CRITICAL] * (1 + DECAY_FACTOR)
            + SEVERITY_PENALTY[Severity.HIGH] * (1 + DECAY_FACTOR)
        )
        expected_score = max(0, round(100 - min(expected_penalty, 100)))
        assert mixed.score == expected_score


# ---------------------------------------------------------------------------
# Many LOW vs one CRITICAL
# ---------------------------------------------------------------------------


class TestManyLowVsOneCritical:
    def test_one_critical_worse_than_ten_low(self):
        """One CRITICAL finding must produce a lower score than ten LOWs."""
        ten_low = score_findings(_findings(*([Severity.LOW] * 10)))
        one_crit = score_findings(_findings(Severity.CRITICAL))
        assert one_crit.score < ten_low.score

    def test_one_critical_worse_than_twenty_low(self):
        twenty_low = score_findings(_findings(*([Severity.LOW] * 20)))
        one_crit = score_findings(_findings(Severity.CRITICAL))
        assert one_crit.score < twenty_low.score

    def test_one_critical_worse_than_one_high(self):
        """One CRITICAL must always score lower than one HIGH."""
        one_high = score_findings(_findings(Severity.HIGH))
        one_crit = score_findings(_findings(Severity.CRITICAL))
        assert one_crit.score < one_high.score

    def test_critical_penalty_substantially_larger_than_low(self):
        """The CRITICAL penalty must be substantially more than LOW.
        Concretely: 1 CRITICAL must score lower than 9 LOWs
        (demonstrating the non-linear gap between severity levels)."""
        nine_low = score_findings(_findings(*([Severity.LOW] * 9)))
        one_crit = score_findings(_findings(Severity.CRITICAL))
        assert one_crit.score < nine_low.score


# ---------------------------------------------------------------------------
# Mixed findings
# ---------------------------------------------------------------------------


class TestMixedFindings:
    def test_mixed_score_lower_than_any_individual(self):
        """A mix of severities must score lower than any single severity alone."""
        mixed = score_findings(_findings(
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
        ))
        just_critical = score_findings(_findings(Severity.CRITICAL))
        assert mixed.score < just_critical.score

    def test_mixed_counts(self):
        rs = score_findings(_findings(
            Severity.CRITICAL, Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ))
        assert rs.critical_count == 2
        assert rs.high_count == 1
        assert rs.medium_count == 3
        assert rs.low_count == 1
        assert rs.info_count == 1
        assert rs.total_findings == 8

    def test_mixed_penalty_sums_correctly(self):
        """Verify penalty arithmetic for a known two-finding mix."""
        # 1 CRITICAL + 1 HIGH (no repeats, so no decay applies)
        penalty = SEVERITY_PENALTY[Severity.CRITICAL] + SEVERITY_PENALTY[Severity.HIGH]
        expected = max(0, round(100 - penalty))
        rs = score_findings(_findings(Severity.CRITICAL, Severity.HIGH))
        assert rs.score == expected


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------


class TestScoreClamping:
    def test_score_never_below_zero(self):
        """100 CRITICAL findings: penalty far exceeds 100, score must be 0."""
        rs = score_findings(_findings(*([Severity.CRITICAL] * 100)))
        assert rs.score == 0

    def test_score_never_above_100(self):
        rs = score_findings([])
        assert rs.score == 100

    def test_score_in_range(self):
        for count in range(0, 15):
            rs = score_findings(_findings(*([Severity.CRITICAL] * count)))
            assert 0 <= rs.score <= 100


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_same_output(self):
        findings = _findings(Severity.CRITICAL, Severity.HIGH, Severity.LOW)
        rs1 = score_findings(findings)
        rs2 = score_findings(findings)
        assert rs1.score == rs2.score
        assert rs1.level == rs2.level

    def test_order_independence(self):
        """Score must not depend on the order findings are listed."""
        f1 = _findings(Severity.CRITICAL, Severity.HIGH, Severity.LOW)
        f2 = _findings(Severity.LOW, Severity.CRITICAL, Severity.HIGH)
        f3 = _findings(Severity.HIGH, Severity.LOW, Severity.CRITICAL)
        scores = {score_findings(f).score for f in (f1, f2, f3)}
        assert len(scores) == 1  # all produce the same score


# ---------------------------------------------------------------------------
# Risk-level bands
# ---------------------------------------------------------------------------


class TestRiskLevelBands:
    def test_100_is_clean(self):
        label, _ = _classify(100)
        assert label == "CLEAN"

    def test_99_is_low(self):
        label, _ = _classify(99)
        assert label == "LOW"

    def test_80_is_low(self):
        label, _ = _classify(80)
        assert label == "LOW"

    def test_79_is_medium(self):
        label, _ = _classify(79)
        assert label == "MEDIUM"

    def test_60_is_medium(self):
        label, _ = _classify(60)
        assert label == "MEDIUM"

    def test_59_is_high(self):
        label, _ = _classify(59)
        assert label == "HIGH"

    def test_40_is_high(self):
        label, _ = _classify(40)
        assert label == "HIGH"

    def test_39_is_critical(self):
        label, _ = _classify(39)
        assert label == "CRITICAL"

    def test_0_is_critical(self):
        label, _ = _classify(0)
        assert label == "CRITICAL"

    def test_all_scores_have_a_band(self):
        for s in range(0, 101):
            label, style = _classify(s)
            assert label in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert style  # non-empty string


# ---------------------------------------------------------------------------
# RiskScore dataclass
# ---------------------------------------------------------------------------


class TestRiskScoreDataclass:
    def test_frozen(self):
        rs = score_findings([])
        with pytest.raises(Exception):
            rs.score = 50  # type: ignore[misc]

    def test_style_non_empty(self):
        for sev in Severity:
            rs = score_findings(_findings(sev))
            assert rs.style

    def test_level_non_empty(self):
        for sev in Severity:
            rs = score_findings(_findings(sev))
            assert rs.level


# ---------------------------------------------------------------------------
# score_result() integration with AnalysisResult
# ---------------------------------------------------------------------------


class TestScoreResult:
    def test_delegates_to_score_findings(self):
        result = _result(Severity.CRITICAL, Severity.HIGH)
        rs_via_result = score_result(result)
        rs_direct = score_findings(list(result.findings))
        assert rs_via_result.score == rs_direct.score
        assert rs_via_result.level == rs_direct.level

    def test_counts_match_analysis_result(self):
        result = _result(
            Severity.CRITICAL,
            Severity.HIGH, Severity.HIGH,
            Severity.MEDIUM,
        )
        rs = score_result(result)
        assert rs.critical_count == result.critical_count
        assert rs.high_count == result.high_count
        assert rs.medium_count == result.medium_count
        assert rs.low_count == result.low_count
        assert rs.info_count == result.info_count


# ---------------------------------------------------------------------------
# output/risk.py compatibility shim
# ---------------------------------------------------------------------------


class TestOutputRiskShim:
    def test_compute_risk_score_returns_int(self):
        from netlint.output.risk import compute_risk_score
        result = _result(Severity.HIGH)
        assert isinstance(compute_risk_score(result), int)

    def test_compute_risk_score_matches_scoring_module(self):
        from netlint.output.risk import compute_risk_score
        result = _result(Severity.CRITICAL, Severity.HIGH)
        assert compute_risk_score(result) == score_result(result).score

    def test_risk_label_clean(self):
        from netlint.output.risk import risk_label
        assert risk_label(100) == "CLEAN"

    def test_risk_label_critical(self):
        from netlint.output.risk import risk_label
        assert risk_label(0) == "CRITICAL"

    def test_risk_style_non_empty(self):
        from netlint.output.risk import risk_style
        for score in (0, 39, 40, 59, 60, 79, 80, 99, 100):
            assert risk_style(score)
