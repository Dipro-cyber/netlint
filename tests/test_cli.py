"""
Tests for the CLI entry point.

Uses Typer's built-in test runner (which wraps Click's CliRunner)
to invoke commands without spawning a subprocess.
"""

from typer.testing import CliRunner

from netlint import __version__
from netlint.cli import app

runner = CliRunner()


def test_help_exits_zero() -> None:
    """netlint --help should succeed and mention key sub-commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_help_lists_subcommands() -> None:
    """--help output should list all planned sub-commands."""
    result = runner.invoke(app, ["--help"])
    output = result.output
    for command in ("analyze", "check", "diff", "rules", "report"):
        assert command in output, f"Expected '{command}' in help output"


def test_version_flag() -> None:
    """--version should print the current version string and exit 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_analyze_not_implemented() -> None:
    """analyze should exit non-zero until implemented."""
    result = runner.invoke(app, ["analyze", "router.cfg"])
    assert result.exit_code != 0


def test_check_not_implemented() -> None:
    """check should exit non-zero until implemented."""
    result = runner.invoke(app, ["check", "router.cfg"])
    assert result.exit_code != 0


def test_diff_not_implemented() -> None:
    """diff should exit non-zero until implemented."""
    result = runner.invoke(app, ["diff", "old.cfg", "new.cfg"])
    assert result.exit_code != 0


def test_rules_not_implemented() -> None:
    """rules is now implemented — exits 0 and lists rules."""
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0


def test_report_not_implemented() -> None:
    """report is now implemented — exits non-zero when file not found."""
    result = runner.invoke(app, ["report", "router.cfg"])
    assert result.exit_code != 0
