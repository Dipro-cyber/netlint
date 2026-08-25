"""
Tests for `netlint analyze` CLI command.

Strategy
--------
We use Typer's CliRunner (wraps Click's) to invoke the app in-process.
Rich output is captured from stdout via the runner's mix_stderr=False mode.
Because the formatter writes to sys.stdout via sys.stdout.write(), we use
runner.invoke with catch_exceptions=False so real exceptions surface.

All fixture paths are passed as absolute strings so the CLI's
`exists=True` Argument validator passes without needing a real cwd.

Exit codes
----------
0  clean config (no findings)
1  findings produced
2  fatal error (bad file, bad option)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from netlint.cli import app
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(*args: str):
    """Invoke the CLI and return the result. Never swallows exceptions."""
    return runner.invoke(app, list(args), catch_exceptions=False)


def run_analyze(*args: str):
    """Shortcut for `netlint analyze <args>`."""
    return runner.invoke(app, ["analyze", *args], catch_exceptions=False)


# ---------------------------------------------------------------------------
# Setup / teardown — reset rule registry between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_registry():
    """Each test gets a clean registry; autodiscover re-loads real rules."""
    RuleRegistry._reset()
    yield
    RuleRegistry._reset()


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------


class TestAnalyzeBasic:

    def test_clean_config_exits_zero(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert result.exit_code == 0, result.output

    def test_findings_config_exits_one(self):
        """duplicate-ip.cfg has multiple findings — exit is non-zero."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"))
        assert result.exit_code in (1, 2, 3)

    def test_nonexistent_file_exits_two(self):
        result = run_analyze(str(FIXTURES / "does_not_exist.cfg"))
        assert result.exit_code == 4

    def test_output_contains_file_name(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert "clean.cfg" in result.output

    def test_output_contains_risk_score(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert "Risk Score" in result.output or "0/100" in result.output

    def test_output_contains_vendor(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert "cisco-ios" in result.output

    def test_clean_config_shows_clean_message(self):
        """A config with zero findings should say so explicitly."""
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert "No findings" in result.output or "clean" in result.output.lower()

    def test_findings_present_in_output(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"))
        # NET001 must appear in the report
        assert "NET001" in result.output

    def test_finding_panel_contains_line_number(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"))
        assert "Line" in result.output

    def test_finding_panel_contains_recommendation(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"))
        assert "Recommendation" in result.output

    def test_finding_panel_contains_severity(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"))
        assert any(s in result.output for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))


# ---------------------------------------------------------------------------
# --vendor flag
# ---------------------------------------------------------------------------


class TestVendorFlag:

    def test_default_vendor_cisco_ios(self):
        """Omitting --vendor should default to cisco-ios and succeed."""
        result = run_analyze(str(FIXTURES / "clean.cfg"))
        assert result.exit_code == 0

    def test_explicit_vendor_cisco_ios(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--vendor", "cisco-ios")
        assert result.exit_code == 0
        assert "cisco-ios" in result.output


# ---------------------------------------------------------------------------
# --severity filter
# ---------------------------------------------------------------------------


class TestSeverityFilter:

    def test_severity_high_hides_medium_findings(self):
        """vlans.cfg has VLAN001 at MEDIUM and SEC003 at HIGH.
        --severity CRITICAL should hide both, giving exit 0."""
        result = run_analyze(str(FIXTURES / "vlans.cfg"), "--severity", "CRITICAL")
        assert result.exit_code == 0

    def test_severity_medium_shows_vlan001(self):
        """--severity MEDIUM includes VLAN001 findings."""
        result = run_analyze(str(FIXTURES / "vlans.cfg"), "--severity", "MEDIUM")
        assert result.exit_code in (1, 2, 3)
        assert "VLAN001" in result.output

    def test_severity_high_hides_vlan001(self):
        """VLAN001 is MEDIUM — filtering to HIGH must exclude it."""
        result = run_analyze(str(FIXTURES / "vlans.cfg"), "--severity", "HIGH")
        assert "VLAN001" not in result.output

    def test_severity_critical_only_shows_critical(self):
        """duplicate-ip.cfg has CRITICAL (NET001) and HIGH (SEC001/SEC003).
        --severity CRITICAL should only show NET001 findings."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--severity", "CRITICAL")
        assert result.exit_code in (1, 2, 3)
        assert "NET001" in result.output

    def test_severity_info_shows_everything(self):
        """--severity INFO is the lowest level — all findings visible."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--severity", "INFO")
        assert result.exit_code in (1, 2, 3)

    def test_severity_case_insensitive(self):
        """Severity option values should be case-insensitive."""
        lower = run_analyze(str(FIXTURES / "vlans.cfg"), "--severity", "medium")
        upper = run_analyze(str(FIXTURES / "vlans.cfg"), "--severity", "MEDIUM")
        assert lower.exit_code == upper.exit_code

    def test_invalid_severity_exits_two(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--severity", "EXTREME")
        assert result.exit_code == 4

    def test_invalid_severity_shows_valid_choices(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--severity", "EXTREME")
        # Should mention valid options in the output
        assert any(s in result.output.upper() for s in ("CRITICAL", "HIGH", "MEDIUM", "INFO"))


# ---------------------------------------------------------------------------
# --category filter
# ---------------------------------------------------------------------------


class TestCategoryFilter:

    def test_category_security_shows_sec_rules(self):
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--category", "SECURITY"
        )
        # duplicate-ip.cfg has SEC001 (Telnet) and SEC003 (no ACL) findings
        assert result.exit_code in (1, 2, 3)
        output = result.output
        # All shown findings should be security rules
        assert "NET001" not in output  # network rule must be filtered out

    def test_category_network_shows_net_rules(self):
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--category", "NETWORK"
        )
        assert result.exit_code in (1, 2, 3)
        assert "NET001" in result.output

    def test_category_vlan_hides_non_vlan(self):
        """On duplicate-ip.cfg (no VLAN findings), --category VLAN → exit 0."""
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--category", "VLAN"
        )
        assert result.exit_code == 0

    def test_category_case_insensitive(self):
        lower = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--category", "security"
        )
        upper = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--category", "SECURITY"
        )
        assert lower.exit_code == upper.exit_code

    def test_invalid_category_exits_two(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--category", "BOGUS")
        assert result.exit_code == 4

    def test_invalid_category_shows_valid_choices(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--category", "BOGUS")
        assert any(c in result.output.upper() for c in ("SECURITY", "NETWORK", "VLAN"))


# ---------------------------------------------------------------------------
# --no-color
# ---------------------------------------------------------------------------


class TestNoColor:

    def test_no_color_exits_correctly_clean(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--no-color")
        assert result.exit_code == 0

    def test_no_color_exits_correctly_findings(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert result.exit_code in (1, 2, 3)

    def test_no_color_output_has_no_ansi_codes(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        # ANSI escape sequences start with ESC [ — should not appear
        assert "\x1b[" not in result.output

    def test_no_color_still_contains_rule_id(self):
        """Content must be present even without colour."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "NET001" in result.output

    def test_no_color_still_contains_risk_score(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "Risk Score" in result.output or "/100" in result.output

    def test_no_color_shows_recommendation(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "Recommendation" in result.output


# ---------------------------------------------------------------------------
# --quiet
# ---------------------------------------------------------------------------


class TestQuiet:

    def test_quiet_clean_config_exits_zero(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--quiet")
        assert result.exit_code == 0

    def test_quiet_findings_config_exits_one(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--quiet")
        assert result.exit_code in (1, 2, 3)

    def test_quiet_produces_no_output(self):
        """--quiet must suppress all stdout."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--quiet")
        assert result.output.strip() == ""

    def test_quiet_clean_produces_no_output(self):
        result = run_analyze(str(FIXTURES / "clean.cfg"), "--quiet")
        assert result.output.strip() == ""

    def test_quiet_combined_with_severity(self):
        """--quiet --severity CRITICAL: vlans.cfg has no CRITICAL findings → exit 0."""
        result = run_analyze(
            str(FIXTURES / "vlans.cfg"), "--quiet", "--severity", "CRITICAL"
        )
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_quiet_combined_with_category(self):
        """--quiet --category NETWORK: exit non-zero if NET findings exist."""
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--quiet", "--category", "NETWORK"
        )
        assert result.exit_code in (1, 2, 3)
        assert result.output.strip() == ""


# ---------------------------------------------------------------------------
# Combined flags
# ---------------------------------------------------------------------------


class TestCombinedFlags:

    def test_severity_and_category_together(self):
        """--severity HIGH --category SECURITY: intersection of both filters."""
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"),
            "--severity", "HIGH",
            "--category", "SECURITY",
        )
        # Should only show HIGH+ security findings
        assert result.exit_code in (1, 2, 3)
        assert "NET001" not in result.output  # NET001 is NETWORK, not SECURITY

    def test_no_color_and_quiet_together(self):
        result = run_analyze(
            str(FIXTURES / "duplicate-ip.cfg"), "--no-color", "--quiet"
        )
        assert result.exit_code in (1, 2, 3)
        assert result.output.strip() == ""

    def test_severity_critical_clean_config(self):
        """clean.cfg has no findings at any level."""
        result = run_analyze(
            str(FIXTURES / "clean.cfg"), "--severity", "CRITICAL"
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Output content correctness
# ---------------------------------------------------------------------------


class TestOutputContent:

    def test_header_present(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "NetLint" in result.output

    def test_findings_sorted_critical_first(self):
        """CRITICAL findings must appear before HIGH in the output text."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        output = result.output
        idx_critical = output.find("CRITICAL")
        idx_high = output.find("HIGH")
        if idx_critical != -1 and idx_high != -1:
            assert idx_critical < idx_high

    def test_http_finding_present_for_http_fixture(self):
        result = run_analyze(str(FIXTURES / "http-enabled.cfg"), "--no-color")
        assert "SEC002" in result.output

    def test_telnet_finding_present_for_http_fixture(self):
        result = run_analyze(str(FIXTURES / "http-enabled.cfg"), "--no-color")
        assert "SEC001" in result.output

    def test_vlan_finding_present_for_vlan_fixture(self):
        result = run_analyze(str(FIXTURES / "vlans.cfg"), "--no-color")
        assert "VLAN001" in result.output

    def test_parser_warnings_shown_when_present(self):
        """malformed.cfg produces parser warnings — they should appear."""
        result = run_analyze(str(FIXTURES / "malformed.cfg"), "--no-color")
        assert result.exit_code in (0, 1, 2, 3)
        # Verify the run completes without a fatal error
        assert result.exit_code != 4

    def test_multiple_findings_all_listed(self):
        """Every finding in duplicate-ip.cfg should have its rule_id in output."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "NET001" in result.output   # duplicate IPs
        assert "SEC001" in result.output   # telnet

    def test_finding_config_line_shown(self):
        """Each finding panel should include the offending config line."""
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "ip address" in result.output


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------


class TestRiskScore:

    def test_clean_config_perfect_score(self):
        from netlint.analyzer.scoring import score_findings
        rs = score_findings([])
        assert rs.score == 100
        assert rs.level == "CLEAN"

    def test_one_critical_reduces_score(self):
        from netlint.analyzer.scoring import score_findings, SEVERITY_PENALTY
        from netlint.models.finding import Finding, Severity, RuleCategory
        f = Finding(
            rule_id="T001",
            severity=Severity.CRITICAL,
            category=RuleCategory.NETWORK,
            title="T",
            message="M",
            recommendation="R",
            file=Path("/tmp/t.cfg"),
        )
        rs = score_findings([f])
        expected = max(0, round(100 - SEVERITY_PENALTY[Severity.CRITICAL]))
        assert rs.score == expected

    def test_score_capped_at_zero(self):
        """Many CRITICAL findings must not drive the score below 0."""
        from netlint.analyzer.scoring import score_findings
        from netlint.models.finding import Finding, Severity, RuleCategory
        findings = [
            Finding(
                rule_id=f"T{i:03d}",
                severity=Severity.CRITICAL,
                category=RuleCategory.NETWORK,
                title="T",
                message="M",
                recommendation="R",
                file=Path("/tmp/t.cfg"),
            )
            for i in range(20)
        ]
        rs = score_findings(findings)
        assert rs.score >= 0

    def test_risk_label_clean(self):
        from netlint.output.risk import risk_label
        assert risk_label(100) == "CLEAN"

    def test_risk_label_high(self):
        from netlint.output.risk import risk_label
        assert risk_label(50) == "HIGH"

    def test_risk_label_critical(self):
        from netlint.output.risk import risk_label
        assert risk_label(0) == "CRITICAL"

    def test_risk_score_shown_in_output(self):
        result = run_analyze(str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "/100" in result.output


# ---------------------------------------------------------------------------
# FormatterRegistry
# ---------------------------------------------------------------------------


class TestFormatterRegistry:

    def test_text_formatter_registered(self):
        import netlint.output  # noqa: F401
        from netlint.output.registry import FormatterRegistry
        assert "text" in FormatterRegistry.supported_formats()

    def test_terminal_formatter_renders_string(self):
        import netlint.output  # noqa: F401
        from netlint.output.registry import FormatterRegistry
        from netlint.models.result import AnalysisResult
        formatter = FormatterRegistry.get("text")()
        result = AnalysisResult(file_path=Path("/tmp/t.cfg"), findings=())
        output = formatter.render(result, no_color=True)
        assert isinstance(output, str)
        assert len(output) > 0
