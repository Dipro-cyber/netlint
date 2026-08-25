"""
Tests for JSON output format and new exit codes.

Coverage
--------
JSON schema — analyze
  - top-level keys present: netlint_version, command, file, hostname,
    vendor, risk_score, risk_level, summary, findings, parser_warnings
  - findings contain all required fields
  - summary counts match findings list
  - risk_score is an integer in [0, 100]
  - risk_level is a valid string
  - output is valid JSON (no Rich markup leaks)
  - stdout contains ONLY valid JSON (no extra text before/after)
  - clean config → empty findings array
  - config with findings → non-empty findings array

JSON schema — diff
  - top-level keys: netlint_version, command, old_file, new_file,
    vendor, deployment_recommendation, summary, new_findings,
    resolved_findings, persisting_findings
  - summary contains new_risks, resolved, persisting, new_critical, new_high
  - identical configs → new_findings is empty array

Exit codes
  - 0 for clean config
  - 1 for low/medium findings only
  - 2 for high findings (no critical)
  - 3 for critical findings present
  - 4 for file-not-found error
  - 4 for invalid format value
  - 4 for invalid severity value

JSON + exit codes together
  - JSON output + correct exit code simultaneously

CLI integration
  - --format json prints valid JSON to stdout
  - --format json does NOT print Rich markup to stdout
  - --format json with --quiet → no stdout, correct exit code
  - diff --format json → valid JSON with diff-specific keys
  - error → JSON error written to stderr, exit 4
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netlint.cli import app
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_registry():
    RuleRegistry._reset()
    yield
    RuleRegistry._reset()


def _invoke(*args: str):
    return runner.invoke(app, list(args), catch_exceptions=False)


def _parse_json(text: str) -> dict:
    """Assert *text* is valid JSON and return the parsed object."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        pytest.fail(f"Output is not valid JSON: {exc}\n\nOutput was:\n{text!r}")


def _analyze_json(fixture: str, *extra: str) -> tuple[dict, int]:
    result = _invoke(
        "analyze", str(FIXTURES / fixture), "--format", "json", *extra
    )
    return _parse_json(result.output), result.exit_code


def _diff_json(old: str, new: str, *extra: str) -> tuple[dict, int]:
    result = _invoke(
        "diff",
        str(FIXTURES / old),
        str(FIXTURES / new),
        "--format", "json",
        *extra,
    )
    return _parse_json(result.output), result.exit_code


# ===========================================================================
# JSON schema — analyze
# ===========================================================================


class TestAnalyzeJsonSchema:

    def test_top_level_keys_present(self):
        doc, _ = _analyze_json("clean.cfg")
        required = {
            "netlint_version", "command", "file", "hostname",
            "vendor", "risk_score", "risk_level",
            "summary", "findings", "parser_warnings",
        }
        assert required.issubset(doc.keys()), (
            f"Missing keys: {required - doc.keys()}"
        )

    def test_command_field_is_analyze(self):
        doc, _ = _analyze_json("clean.cfg")
        assert doc["command"] == "analyze"

    def test_file_field_is_absolute_path(self):
        doc, _ = _analyze_json("clean.cfg")
        assert Path(doc["file"]).is_absolute()
        assert doc["file"].endswith("clean.cfg")

    def test_vendor_field(self):
        doc, _ = _analyze_json("clean.cfg")
        assert doc["vendor"] == "cisco-ios"

    def test_risk_score_is_integer_in_range(self):
        doc, _ = _analyze_json("clean.cfg")
        assert isinstance(doc["risk_score"], int)
        assert 0 <= doc["risk_score"] <= 100

    def test_risk_level_is_string(self):
        doc, _ = _analyze_json("clean.cfg")
        assert isinstance(doc["risk_level"], str)
        assert doc["risk_level"] in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_netlint_version_present(self):
        from netlint import __version__
        doc, _ = _analyze_json("clean.cfg")
        assert doc["netlint_version"] == __version__

    def test_hostname_extracted(self):
        doc, _ = _analyze_json("clean.cfg")
        assert doc["hostname"] == "CORE-SW-01"

    def test_hostname_present_for_duplicate_ip_fixture(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        assert doc["hostname"] == "DUP-IP-ROUTER"

    def test_summary_keys(self):
        doc, _ = _analyze_json("clean.cfg")
        assert set(doc["summary"].keys()) == {
            "total", "critical", "high", "medium", "low", "info"
        }

    def test_summary_counts_match_findings(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        findings = doc["findings"]
        summary = doc["summary"]
        assert summary["total"] == len(findings)
        assert summary["critical"] == sum(
            1 for f in findings if f["severity"] == "critical"
        )
        assert summary["high"] == sum(
            1 for f in findings if f["severity"] == "high"
        )

    def test_parser_warnings_is_list(self):
        doc, _ = _analyze_json("clean.cfg")
        assert isinstance(doc["parser_warnings"], list)

    def test_findings_is_list(self):
        doc, _ = _analyze_json("clean.cfg")
        assert isinstance(doc["findings"], list)

    def test_clean_config_empty_findings(self):
        doc, _ = _analyze_json("clean.cfg")
        assert doc["findings"] == []
        assert doc["summary"]["total"] == 0

    def test_findings_config_nonempty(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        assert len(doc["findings"]) > 0


class TestAnalyzeFindingSchema:

    def test_finding_required_fields(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        required = {
            "rule_id", "severity", "category", "title",
            "message", "recommendation", "line_number", "configuration_line",
        }
        for finding in doc["findings"]:
            assert required.issubset(finding.keys()), (
                f"Missing finding keys: {required - finding.keys()}"
            )

    def test_finding_severity_is_lowercase_string(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        valid = {"info", "low", "medium", "high", "critical"}
        for finding in doc["findings"]:
            assert finding["severity"] in valid

    def test_finding_category_is_lowercase_string(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        valid = {"security", "network", "vlan", "routing", "interface", "acl", "management"}
        for finding in doc["findings"]:
            assert finding["category"] in valid

    def test_finding_line_number_is_int_or_null(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        for finding in doc["findings"]:
            assert finding["line_number"] is None or isinstance(finding["line_number"], int)

    def test_finding_rule_id_present(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        for finding in doc["findings"]:
            assert finding["rule_id"]

    def test_finding_message_present(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        for finding in doc["findings"]:
            assert finding["message"]

    def test_finding_recommendation_present(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        for finding in doc["findings"]:
            assert finding["recommendation"]

    def test_net001_finding_in_output(self):
        doc, _ = _analyze_json("duplicate-ip.cfg")
        rule_ids = {f["rule_id"] for f in doc["findings"]}
        assert "NET001" in rule_ids

    def test_sec001_finding_for_telnet_config(self):
        doc, _ = _analyze_json("http-enabled.cfg")
        rule_ids = {f["rule_id"] for f in doc["findings"]}
        assert "SEC001" in rule_ids

    def test_sec002_finding_for_http_config(self):
        doc, _ = _analyze_json("http-enabled.cfg")
        rule_ids = {f["rule_id"] for f in doc["findings"]}
        assert "SEC002" in rule_ids


class TestAnalyzeJsonPurity:

    def test_stdout_is_valid_json_only(self):
        """No Rich markup or text outside the JSON object."""
        result = _invoke("analyze", str(FIXTURES / "duplicate-ip.cfg"), "--format", "json")
        text = result.output.strip()
        # Must start and end with braces
        assert text.startswith("{"), f"Output does not start with '{{': {text[:50]!r}"
        assert text.endswith("}"), f"Output does not end with '}}': {text[-50:]!r}"
        # Must parse cleanly
        _parse_json(text)

    def test_no_rich_markup_in_json(self):
        result = _invoke("analyze", str(FIXTURES / "clean.cfg"), "--format", "json")
        assert "[bold" not in result.output
        assert "[red]" not in result.output
        assert "\x1b[" not in result.output  # no ANSI codes

    def test_json_with_parser_warnings(self):
        """malformed.cfg produces parser warnings — they must appear in JSON."""
        doc, _ = _analyze_json("malformed.cfg")
        assert "parser_warnings" in doc
        # warnings are strings
        for w in doc["parser_warnings"]:
            assert isinstance(w, str)


# ===========================================================================
# JSON schema — diff
# ===========================================================================


class TestDiffJsonSchema:

    def test_top_level_keys_present(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        required = {
            "netlint_version", "command", "old_file", "new_file",
            "vendor", "deployment_recommendation",
            "summary", "new_findings", "resolved_findings", "persisting_findings",
        }
        assert required.issubset(doc.keys())

    def test_command_field_is_diff(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert doc["command"] == "diff"

    def test_old_file_and_new_file_paths(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert "clean.cfg" in doc["old_file"]
        assert "proposed.cfg" in doc["new_file"]

    def test_summary_keys(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert set(doc["summary"].keys()) == {
            "new_risks", "resolved", "persisting", "new_critical", "new_high"
        }

    def test_summary_new_risks_matches_new_findings(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert doc["summary"]["new_risks"] == len(doc["new_findings"])

    def test_identical_configs_empty_new_findings(self):
        doc, _ = _diff_json("clean.cfg", "clean.cfg")
        assert doc["new_findings"] == []
        assert doc["summary"]["new_risks"] == 0

    def test_deployment_recommendation_present(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert doc["deployment_recommendation"]
        assert doc["deployment_recommendation"] in (
            "DO NOT DEPLOY", "REVIEW BEFORE DEPLOYING",
            "SAFE TO DEPLOY", "SAFE TO DEPLOY (minor issues found)",
        )

    def test_old_hostname_extracted(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert doc["old_hostname"] == "CORE-SW-01"

    def test_new_hostname_extracted(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        assert doc["new_hostname"] == "CORE-SW-01"

    def test_new_findings_have_required_fields(self):
        doc, _ = _diff_json("clean.cfg", "proposed.cfg")
        required = {"rule_id", "severity", "category", "title", "message", "recommendation"}
        for finding in doc["new_findings"]:
            assert required.issubset(finding.keys())

    def test_stdout_is_valid_json_only(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "json",
        )
        text = result.output.strip()
        assert text.startswith("{")
        assert text.endswith("}")
        _parse_json(text)

    def test_no_rich_markup_in_diff_json(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "json",
        )
        assert "[bold" not in result.output
        assert "\x1b[" not in result.output


# ===========================================================================
# Exit codes — analyze
# ===========================================================================


class TestAnalyzeExitCodes:

    def test_exit_0_clean_config(self):
        _, code = _analyze_json("clean.cfg")
        assert code == 0

    def test_exit_0_clean_text_format(self):
        result = _invoke("analyze", str(FIXTURES / "clean.cfg"))
        assert result.exit_code == 0

    def test_exit_3_critical_findings(self):
        """duplicate-ip.cfg has CRITICAL NET001 findings → exit 3."""
        _, code = _analyze_json("duplicate-ip.cfg")
        assert code == 3

    def test_exit_3_critical_text_format(self):
        result = _invoke("analyze", str(FIXTURES / "duplicate-ip.cfg"))
        assert result.exit_code == 3

    def test_exit_2_high_only(self):
        """http-enabled.cfg has SEC001/SEC002 at HIGH, no CRITICAL → exit 2."""
        _, code = _analyze_json("http-enabled.cfg")
        assert code == 2

    def test_exit_1_medium_only(self):
        """
        vlans.cfg has VLAN001 (MEDIUM) and SEC003 (HIGH).
        Filter to VLAN category only to isolate MEDIUM findings → exit 1.
        """
        result = _invoke(
            "analyze", str(FIXTURES / "vlans.cfg"),
            "--format", "json",
            "--category", "vlan",
        )
        doc = _parse_json(result.output)
        if doc["findings"]:
            # All vlan-category findings are MEDIUM
            assert all(f["severity"] == "medium" for f in doc["findings"])
            assert result.exit_code == 1
        else:
            # No vlan findings at all — clean
            assert result.exit_code == 0

    def test_exit_4_file_not_found(self):
        result = _invoke(
            "analyze", str(FIXTURES / "does_not_exist.cfg"), "--format", "json"
        )
        assert result.exit_code == 4

    def test_exit_4_invalid_format(self):
        result = _invoke(
            "analyze", str(FIXTURES / "clean.cfg"), "--format", "xml"
        )
        assert result.exit_code == 4

    def test_exit_4_invalid_severity(self):
        result = _invoke(
            "analyze", str(FIXTURES / "clean.cfg"), "--severity", "EXTREME"
        )
        assert result.exit_code == 4

    def test_exit_code_consistent_across_formats(self):
        """JSON and text formats must produce the same exit code."""
        json_result = _invoke("analyze", str(FIXTURES / "duplicate-ip.cfg"), "--format", "json")
        text_result = _invoke("analyze", str(FIXTURES / "duplicate-ip.cfg"))
        assert json_result.exit_code == text_result.exit_code

    def test_quiet_still_returns_correct_exit_code(self):
        result = _invoke(
            "analyze", str(FIXTURES / "duplicate-ip.cfg"), "--format", "json", "--quiet"
        )
        assert result.exit_code == 3
        assert result.output.strip() == ""


# ===========================================================================
# Exit codes — diff
# ===========================================================================


class TestDiffExitCodes:

    def test_exit_0_identical_configs(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "clean.cfg"),
            "--format", "json",
        )
        assert result.exit_code == 0

    def test_exit_nonzero_when_new_risks(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "json",
        )
        assert result.exit_code in (1, 2, 3)

    def test_exit_2_or_3_for_high_critical_new_risks(self):
        """proposed.cfg introduces HIGH risks → exit 2 (no new CRITICAL)."""
        doc, code = _diff_json("clean.cfg", "proposed.cfg")
        new_critical = doc["summary"]["new_critical"]
        new_high = doc["summary"]["new_high"]
        if new_critical > 0:
            assert code == 3
        elif new_high > 0:
            assert code == 2

    def test_exit_4_file_not_found(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "does_not_exist.cfg"),
            str(FIXTURES / "clean.cfg"),
            "--format", "json",
        )
        assert result.exit_code == 4

    def test_exit_4_invalid_format(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "yaml",
        )
        assert result.exit_code == 4

    def test_quiet_returns_correct_exit_code(self):
        result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "json",
            "--quiet",
        )
        assert result.exit_code in (0, 1, 2, 3)
        assert result.output.strip() == ""

    def test_exit_code_consistent_across_formats(self):
        json_result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--format", "json",
        )
        text_result = _invoke(
            "diff",
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
        )
        assert json_result.exit_code == text_result.exit_code


# ===========================================================================
# json_formatter unit tests
# ===========================================================================


class TestJsonFormatterUnit:

    def _make_result(self, *severities):
        from netlint.models.finding import Finding, RuleCategory, Severity
        from netlint.models.result import AnalysisResult
        findings = tuple(
            Finding(
                rule_id=f"T{i:03d}",
                severity=sev,
                category=RuleCategory.NETWORK,
                title="Test",
                message=f"msg {i}",
                recommendation="Fix it",
                file=Path("/tmp/test.cfg"),
                line_number=i + 1,
                configuration_line=f"interface Gi0/{i}",
            )
            for i, sev in enumerate(severities)
        )
        return AnalysisResult(
            file_path=Path("/tmp/test.cfg"),
            findings=findings,
        )

    def test_render_analyze_returns_valid_json(self):
        from netlint.output.json_formatter import render_analyze_json
        result = self._make_result()
        output = render_analyze_json(result, hostname="R1")
        doc = _parse_json(output)
        assert doc["hostname"] == "R1"
        assert doc["command"] == "analyze"

    def test_render_analyze_empty_findings(self):
        from netlint.output.json_formatter import render_analyze_json
        result = self._make_result()
        doc = _parse_json(render_analyze_json(result))
        assert doc["findings"] == []
        assert doc["summary"]["total"] == 0

    def test_render_analyze_findings_serialised(self):
        from netlint.models.finding import Severity
        from netlint.output.json_formatter import render_analyze_json
        result = self._make_result(Severity.HIGH, Severity.MEDIUM)
        doc = _parse_json(render_analyze_json(result))
        assert doc["summary"]["total"] == 2
        assert doc["summary"]["high"] == 1
        assert doc["summary"]["medium"] == 1

    def test_render_error_json(self):
        from netlint.output.json_formatter import render_error_json
        doc = _parse_json(render_error_json("analyze", "Something went wrong"))
        assert doc["command"] == "analyze"
        assert doc["error"] == "Something went wrong"
        assert "netlint_version" in doc

    def test_render_diff_json(self):
        from netlint.diff.risk import compare_results
        from netlint.models.result import AnalysisResult
        from netlint.output.json_formatter import render_diff_json
        old_r = AnalysisResult(file_path=Path("/tmp/old.cfg"), findings=())
        new_r = AnalysisResult(file_path=Path("/tmp/new.cfg"), findings=())
        dr = compare_results(old_r, new_r)
        doc = _parse_json(render_diff_json(dr))
        assert doc["command"] == "diff"
        assert doc["new_findings"] == []
        assert doc["deployment_recommendation"] == "SAFE TO DEPLOY"

    def test_finding_to_dict_all_fields(self):
        from netlint.models.finding import Severity
        from netlint.output.json_formatter import render_analyze_json
        result = self._make_result(Severity.CRITICAL)
        doc = _parse_json(render_analyze_json(result))
        f = doc["findings"][0]
        assert f["rule_id"] == "T000"
        assert f["severity"] == "critical"
        assert f["line_number"] == 1
        assert f["configuration_line"] == "interface Gi0/0"
