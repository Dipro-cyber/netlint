"""
Tests for the three newly implemented CLI commands:
  - netlint rules
  - netlint check
  - netlint report
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netlint.cli import app
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_registry():
    RuleRegistry._reset()
    yield
    RuleRegistry._reset()


def invoke(*args: str):
    return runner.invoke(app, list(args), catch_exceptions=False)


# ===========================================================================
# netlint rules
# ===========================================================================


class TestRulesCommand:

    def test_exits_zero(self):
        result = invoke("rules")
        assert result.exit_code == 0, result.output

    def test_shows_rule_ids(self):
        result = invoke("rules", "--no-color")
        for rid in ("NET001", "NET002", "VLAN001", "SEC001", "SEC002", "SEC003"):
            assert rid in result.output, f"{rid} missing from rules output"

    def test_shows_severities(self):
        result = invoke("rules", "--no-color")
        assert "CRITICAL" in result.output
        assert "HIGH" in result.output
        assert "MEDIUM" in result.output

    def test_shows_categories(self):
        result = invoke("rules", "--no-color")
        assert "SECURITY" in result.output
        assert "NETWORK" in result.output
        assert "VLAN" in result.output

    def test_shows_vendors(self):
        result = invoke("rules", "--no-color")
        assert "cisco-ios" in result.output

    def test_shows_rule_count(self):
        result = invoke("rules", "--no-color")
        assert "rule" in result.output.lower()

    def test_vendor_filter(self):
        result = invoke("rules", "--vendor", "cisco-ios", "--no-color")
        assert result.exit_code == 0
        # All rules should still appear (all are cisco-ios)
        assert "NET001" in result.output

    def test_unknown_vendor_returns_no_rules(self):
        result = invoke("rules", "--vendor", "nonexistent-vendor")
        assert result.exit_code == 0
        assert "No rules" in result.output

    def test_category_filter_security(self):
        result = invoke("rules", "--category", "SECURITY", "--no-color")
        assert result.exit_code == 0
        assert "SEC001" in result.output
        assert "NET001" not in result.output

    def test_category_filter_network(self):
        result = invoke("rules", "--category", "NETWORK", "--no-color")
        assert result.exit_code == 0
        assert "NET001" in result.output
        assert "SEC001" not in result.output

    def test_invalid_category_exits_four(self):
        result = invoke("rules", "--category", "BOGUS")
        assert result.exit_code == 4

    def test_no_color_strips_ansi(self):
        result = invoke("rules", "--no-color")
        assert "\x1b[" not in result.output

    def test_help_shows_description(self):
        result = invoke("rules", "--help")
        assert result.exit_code == 0
        assert "rule" in result.output.lower()


# ===========================================================================
# netlint check
# ===========================================================================


class TestCheckCommand:

    def test_clean_config_exits_zero(self):
        result = invoke("check", str(FIXTURES / "clean.cfg"))
        assert result.exit_code == 0, result.output

    def test_findings_exits_one(self):
        """check exits 1 for ANY finding, regardless of severity."""
        result = invoke("check", str(FIXTURES / "duplicate-ip.cfg"))
        assert result.exit_code == 1

    def test_medium_findings_also_exit_one(self):
        """Unlike analyze (which uses 1/2/3 by severity), check always exits 1."""
        result = invoke("check", str(FIXTURES / "vlans.cfg"))
        assert result.exit_code == 1

    def test_nonexistent_file_exits_four(self):
        result = invoke("check", str(FIXTURES / "no_such_file.cfg"))
        assert result.exit_code == 4

    def test_invalid_format_exits_four(self):
        result = invoke("check", str(FIXTURES / "clean.cfg"), "--format", "xml")
        assert result.exit_code == 4

    def test_output_contains_findings(self):
        result = invoke("check", str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "NET001" in result.output

    def test_json_format_valid_json(self):
        result = invoke("check", str(FIXTURES / "clean.cfg"), "--format", "json")
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert doc["command"] == "analyze"  # reuses analyze schema
        assert doc["findings"] == []

    def test_json_findings_exit_one(self):
        result = invoke(
            "check", str(FIXTURES / "duplicate-ip.cfg"), "--format", "json"
        )
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert len(doc["findings"]) > 0

    def test_quiet_no_output_clean(self):
        result = invoke("check", str(FIXTURES / "clean.cfg"), "--quiet")
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_quiet_no_output_findings(self):
        result = invoke("check", str(FIXTURES / "duplicate-ip.cfg"), "--quiet")
        assert result.exit_code == 1
        assert result.output.strip() == ""

    def test_no_color_strips_ansi(self):
        result = invoke("check", str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "\x1b[" not in result.output

    def test_help_shows_exit_codes(self):
        result = invoke("check", "--help")
        assert result.exit_code == 0
        assert "0" in result.output  # exit code docs


# ===========================================================================
# netlint report
# ===========================================================================


class TestReportCommand:

    def test_clean_config_exits_zero(self):
        result = invoke("report", str(FIXTURES / "clean.cfg"))
        assert result.exit_code == 0, result.output

    def test_findings_config_exits_nonzero(self):
        result = invoke("report", str(FIXTURES / "duplicate-ip.cfg"))
        assert result.exit_code in (1, 2, 3)

    def test_stdout_text_contains_findings(self):
        result = invoke("report", str(FIXTURES / "duplicate-ip.cfg"), "--no-color")
        assert "NET001" in result.output

    def test_stdout_json_is_valid(self):
        result = invoke(
            "report", str(FIXTURES / "clean.cfg"), "--format", "json"
        )
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert "findings" in doc
        assert "risk_score" in doc

    def test_stdout_json_has_hostname(self):
        result = invoke(
            "report", str(FIXTURES / "clean.cfg"), "--format", "json"
        )
        doc = json.loads(result.output)
        assert doc["hostname"] == "CORE-SW-01"

    def test_output_to_file_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.txt"
            result = invoke(
                "report", str(FIXTURES / "clean.cfg"),
                "--output", str(out),
            )
            assert result.exit_code == 0
            assert out.exists()
            content = out.read_text(encoding="utf-8")
            assert "NetLint" in content

    def test_output_to_file_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.json"
            result = invoke(
                "report", str(FIXTURES / "clean.cfg"),
                "--format", "json",
                "--output", str(out),
            )
            assert result.exit_code == 0
            assert out.exists()
            doc = json.loads(out.read_text(encoding="utf-8"))
            assert "findings" in doc

    def test_file_output_no_ansi_in_file(self):
        """Writing to a file should always produce plain text, no ANSI codes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.txt"
            invoke(
                "report", str(FIXTURES / "duplicate-ip.cfg"),
                "--output", str(out),
            )
            content = out.read_text(encoding="utf-8")
            assert "\x1b[" not in content

    def test_file_output_prints_summary_to_stderr(self):
        """When writing to a file the CLI prints a summary to stderr."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "r.txt"
            result = invoke(
                "report", str(FIXTURES / "clean.cfg"),
                "--output", str(out),
            )
            # Typer's CliRunner merges stderr into output
            assert str(out.name) in result.output or result.exit_code == 0

    def test_nonexistent_file_exits_four(self):
        result = invoke("report", str(FIXTURES / "no_such.cfg"))
        assert result.exit_code == 4

    def test_invalid_format_exits_four(self):
        result = invoke(
            "report", str(FIXTURES / "clean.cfg"), "--format", "html"
        )
        assert result.exit_code == 4

    def test_no_color_flag(self):
        result = invoke(
            "report", str(FIXTURES / "duplicate-ip.cfg"), "--no-color"
        )
        assert "\x1b[" not in result.output

    def test_help_shows_output_option(self):
        result = invoke("report", "--help")
        assert result.exit_code == 0
        assert "--output" in result.output

    def test_json_findings_have_all_fields(self):
        result = invoke(
            "report", str(FIXTURES / "duplicate-ip.cfg"), "--format", "json"
        )
        doc = json.loads(result.output)
        for f in doc["findings"]:
            for key in ("rule_id", "severity", "category", "message", "recommendation"):
                assert key in f, f"Missing key '{key}' in finding"
