"""
CLI entry point for netlint.

Exit codes
----------
0  — clean: no findings at any severity
1  — low / medium findings only
2  — at least one HIGH finding (no CRITICAL)
3  — at least one CRITICAL finding
4  — fatal error (file not found, parse error, bad arguments)

The granular exit codes let CI scripts distinguish "review required"
(exit 1-2) from "do not deploy" (exit 3) without parsing output.

When --format json is specified all output on stdout is valid JSON.
Error messages are always written to stderr.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from netlint import __version__
from netlint.models.result import AnalysisResult

app = typer.Typer(
    name="netlint",
    help=(
        "NetLint — static analyzer for network device configuration files.\n\n"
        "Analyze Cisco IOS (and other vendor) configs before deployment to catch\n"
        "duplicate IPs, overlapping subnets, insecure protocols, ACL issues, and more."
    ),
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

_err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_VALID_FORMATS = ("text", "json")


def _exit_code_for_result(result: AnalysisResult) -> int:
    """
    Return the appropriate exit code for an AnalysisResult.

    0  clean
    1  low/medium findings only
    2  high findings (no critical)
    3  critical findings present
    """
    if result.critical_count > 0:
        return 3
    if result.high_count > 0:
        return 2
    if result.has_findings:
        return 1
    return 0


def _hostname_from_parsed(config_file: Path, vendor: str) -> str | None:
    """Parse the config and return the hostname, or None on any failure."""
    try:
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        parsed = CiscoIosParser().parse_text(
            config_file.read_text(encoding="utf-8").splitlines()
        )
        return parsed.hostname
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        Console().print(
            f"[bold green]netlint[/bold green] version [cyan]{__version__}[/cyan]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the netlint version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """NetLint — static analyzer for network device configuration files."""
    _ = version


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    config_file: Annotated[
        Path,
        typer.Argument(
            help="Path to the network device configuration file.",
            resolve_path=True,
        ),
    ],
    vendor: Annotated[
        str,
        typer.Option("--vendor", "-V", help="Vendor format (default: cisco-ios)."),
    ] = "cisco-ios",
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity", "-s",
            help="Only show findings at or above this severity. "
                 "Choices: INFO, LOW, MEDIUM, HIGH, CRITICAL.",
            metavar="LEVEL",
        ),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option(
            "--category", "-c",
            help="Only show findings in this category. "
                 "Choices: SECURITY, NETWORK, VLAN, ROUTING, INTERFACE, ACL, MANAGEMENT.",
            metavar="CAT",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: text (default) or json.",
        ),
    ] = "text",
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colour output (text format only)."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet", "-q",
            help="Suppress all stdout output. Exit code still reflects findings.",
        ),
    ] = False,
) -> None:
    """
    Analyze a configuration file and report all detected issues.

    Exit codes: 0=clean  1=low/medium  2=high  3=critical  4=error

    Examples:

        netlint analyze router.cfg

        netlint analyze router.cfg --format json

        netlint analyze router.cfg --severity HIGH

        netlint analyze router.cfg --category SECURITY

        netlint analyze router.cfg --no-color --quiet
    """
    from netlint.analyzer.analyzer import Analyzer
    from netlint.exceptions import ParseError
    from netlint.models.finding import RuleCategory, Severity

    use_json = format.lower() == "json"

    # --- Validate format ---------------------------------------------------
    if format.lower() not in _VALID_FORMATS:
        msg = f"Invalid format '{format}'. Valid choices: {', '.join(_VALID_FORMATS)}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("analyze", msg))
        else:
            _err_console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=4) from None

    # --- Validate severity -------------------------------------------------
    min_severity: Severity | None = None
    if severity is not None:
        try:
            min_severity = Severity(severity.lower())
        except ValueError:
            valid = ", ".join(s.value.upper() for s in Severity)
            _err = f"Invalid severity '{severity}'. Valid choices: {valid}"
            if use_json:
                from netlint.output.json_formatter import render_error_json
                _err_console.print(render_error_json("analyze", _err))
            else:
                _err_console.print(f"[red]Error:[/red] {_err}")
            raise typer.Exit(code=4) from None

    # --- Validate category -------------------------------------------------
    filter_category: RuleCategory | None = None
    if category is not None:
        try:
            filter_category = RuleCategory(category.lower())
        except ValueError:
            valid = ", ".join(c.value.upper() for c in RuleCategory)
            _err = f"Invalid category '{category}'. Valid choices: {valid}"
            if use_json:
                from netlint.output.json_formatter import render_error_json
                _err_console.print(render_error_json("analyze", _err))
            else:
                _err_console.print(f"[red]Error:[/red] {_err}")
            raise typer.Exit(code=4) from None

    # --- Run analysis ------------------------------------------------------
    try:
        result: AnalysisResult = Analyzer().run(config_file, vendor=vendor)
    except FileNotFoundError:
        _err = f"File not found: {config_file}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("analyze", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None
    except ParseError as exc:
        _err = f"Parse error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("analyze", _err))
        else:
            _err_console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(code=4) from None
    except Exception as exc:  # noqa: BLE001
        _err = f"Unexpected error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("analyze", _err))
        else:
            _err_console.print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=4) from None

    # --- Apply filters -----------------------------------------------------
    findings = list(result.findings)
    if min_severity is not None:
        findings = [f for f in findings if f.severity.weight >= min_severity.weight]
    if filter_category is not None:
        findings = [f for f in findings if f.category == filter_category]

    filtered_result = AnalysisResult(
        file_path=result.file_path,
        findings=tuple(findings),
        vendor=result.vendor,
        parser_warnings=result.parser_warnings,
    )

    # --- Render output -----------------------------------------------------
    if not quiet:
        if use_json:
            from netlint.output.json_formatter import render_analyze_json
            hostname = _hostname_from_parsed(config_file, vendor)
            typer.echo(render_analyze_json(filtered_result, hostname=hostname), nl=False)
        else:
            import netlint.output  # noqa: F401 — triggers formatter registration
            from netlint.output.terminal import TerminalFormatter
            typer.echo(
                TerminalFormatter().render(filtered_result, no_color=no_color),
                nl=False,
            )

    raise typer.Exit(code=_exit_code_for_result(filtered_result))


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@app.command()
def check(
    config_file: Annotated[
        Path,
        typer.Argument(
            help="Path to the network device configuration file.",
            resolve_path=True,
        ),
    ],
    vendor: Annotated[
        str,
        typer.Option("--vendor", "-V", help="Vendor format (default: cisco-ios)."),
    ] = "cisco-ios",
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: text (default) or json.",
        ),
    ] = "text",
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colour output (text format only)."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet", "-q",
            help="Suppress all output. Exit 0 if clean, exit 1 if any findings.",
        ),
    ] = False,
) -> None:
    """
    Check a configuration file; exit non-zero if ANY finding is detected.

    Designed for CI/CD pipelines where any finding should fail the build.
    Unlike ``analyze``, exit code is simply 0 (clean) or 1 (findings) —
    severity is not reflected in the exit code.

    Exit codes: 0=clean  1=findings  4=error

    Examples:

        netlint check router.cfg

        netlint check router.cfg --format json

        netlint check router.cfg --quiet && echo "Clean!"
    """
    from netlint.analyzer.analyzer import Analyzer
    from netlint.exceptions import ParseError

    use_json = format.lower() == "json"

    if format.lower() not in _VALID_FORMATS:
        _err = f"Invalid format '{format}'. Valid choices: {', '.join(_VALID_FORMATS)}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("check", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None

    try:
        result = Analyzer().run(config_file, vendor=vendor)
    except FileNotFoundError:
        _err = f"File not found: {config_file}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("check", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None
    except ParseError as exc:
        _err = f"Parse error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("check", _err))
        else:
            _err_console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(code=4) from None
    except Exception as exc:  # noqa: BLE001
        _err = f"Unexpected error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("check", _err))
        else:
            _err_console.print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=4) from None

    if not quiet:
        if use_json:
            from netlint.output.json_formatter import render_analyze_json
            hostname = _hostname_from_parsed(config_file, vendor)
            typer.echo(render_analyze_json(result, hostname=hostname), nl=False)
        else:
            import netlint.output  # noqa: F401
            from netlint.output.terminal import TerminalFormatter
            typer.echo(
                TerminalFormatter().render(result, no_color=no_color),
                nl=False,
            )

    # Simple binary exit: 0=clean, 1=any findings (CI-friendly)
    raise typer.Exit(code=1 if result.has_findings else 0)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@app.command()
def diff(
    old_config: Annotated[
        Path,
        typer.Argument(
            help="Path to the original (production) configuration file.",
            resolve_path=True,
        ),
    ],
    new_config: Annotated[
        Path,
        typer.Argument(
            help="Path to the proposed (new) configuration file.",
            resolve_path=True,
        ),
    ],
    vendor: Annotated[
        str,
        typer.Option("--vendor", "-V", help="Vendor format (default: cisco-ios)."),
    ] = "cisco-ios",
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: text (default) or json.",
        ),
    ] = "text",
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colour output (text format only)."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet", "-q",
            help="Suppress all stdout output. Exit code still reflects new risks.",
        ),
    ] = False,
) -> None:
    """
    Compare two configuration files and identify newly introduced risks.

    Exit codes: 0=no new risks  1=low/medium new risks  2=high new risks
                3=critical new risks  4=error

    Examples:

        netlint diff production.cfg proposed.cfg

        netlint diff production.cfg proposed.cfg --format json

        netlint diff production.cfg proposed.cfg --no-color

        netlint diff production.cfg proposed.cfg --quiet
    """
    from netlint.analyzer.analyzer import Analyzer
    from netlint.diff.differ import ConfigDiffer
    from netlint.diff.risk import compare_results
    from netlint.exceptions import ParseError
    from netlint.parser.cisco_ios.parser import CiscoIosParser
    from netlint.parser.registry import ParserRegistry
    from netlint.rules.registry import RuleRegistry

    use_json = format.lower() == "json"

    if format.lower() not in _VALID_FORMATS:
        _err = f"Invalid format '{format}'. Valid choices: {', '.join(_VALID_FORMATS)}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("diff", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None

    ParserRegistry.autodiscover()
    RuleRegistry.autodiscover()

    analyzer = Analyzer()
    try:
        old_result = analyzer.run(old_config, vendor=vendor)
        new_result = analyzer.run(new_config, vendor=vendor)
    except FileNotFoundError as exc:
        _err = f"File not found: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("diff", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None
    except ParseError as exc:
        _err = f"Parse error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("diff", _err))
        else:
            _err_console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(code=4) from None
    except Exception as exc:  # noqa: BLE001
        _err = f"Unexpected error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("diff", _err))
        else:
            _err_console.print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=4) from None

    # Parse both configs for the structural diff
    parser = CiscoIosParser()
    old_parsed = parser.parse_text(
        old_config.read_text(encoding="utf-8").splitlines()
    )
    new_parsed = parser.parse_text(
        new_config.read_text(encoding="utf-8").splitlines()
    )

    config_diff = ConfigDiffer().diff(
        old_parsed, new_parsed,
        old_path=str(old_config),
        new_path=str(new_config),
    )
    diff_risk = compare_results(old_result, new_result)

    if not quiet:
        if use_json:
            from netlint.output.json_formatter import render_diff_json
            typer.echo(
                render_diff_json(
                    diff_risk,
                    old_hostname=old_parsed.hostname,
                    new_hostname=new_parsed.hostname,
                    vendor=vendor,
                ),
                nl=False,
            )
        else:
            from netlint.output.diff_formatter import DiffFormatter
            typer.echo(
                DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=no_color),
                nl=False,
            )

    # Exit code based on *new* findings only
    new_findings_result = AnalysisResult(
        file_path=new_result.file_path,
        findings=diff_risk.new_findings,
        vendor=vendor,
    )
    raise typer.Exit(code=_exit_code_for_result(new_findings_result))


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@app.command()
def rules(
    vendor: Annotated[
        str,
        typer.Option("--vendor", "-V", help="Filter rules by vendor (default: show all)."),
    ] = "",
    category: Annotated[
        str | None,
        typer.Option(
            "--category", "-c",
            help="Filter by category: SECURITY, NETWORK, VLAN, ROUTING, INTERFACE, ACL, MANAGEMENT.",
            metavar="CAT",
        ),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colour output."),
    ] = False,
) -> None:
    """
    List all available lint rules with IDs, severities, categories, and titles.

    Examples:

        netlint rules

        netlint rules --vendor cisco-ios

        netlint rules --category SECURITY
    """
    from io import StringIO

    from rich.console import Console as RichConsole
    from rich.table import Table
    from rich.text import Text
    from rich import box as rich_box

    from netlint.models.finding import RuleCategory, Severity
    from netlint.parser.registry import ParserRegistry
    from netlint.rules.registry import RuleRegistry

    ParserRegistry.autodiscover()
    RuleRegistry.autodiscover()

    # Severity → colour
    _sev_style: dict[str, str] = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "cyan",
        "info":     "dim",
    }

    # Category → colour
    _cat_style: dict[str, str] = {
        "security":   "bold magenta",
        "network":    "bold blue",
        "vlan":       "bold cyan",
        "routing":    "bold green",
        "interface":  "yellow",
        "acl":        "bold red",
        "management": "white",
    }

    # Validate category filter
    filter_cat: RuleCategory | None = None
    if category:
        try:
            filter_cat = RuleCategory(category.lower())
        except ValueError:
            valid = ", ".join(c.value.upper() for c in RuleCategory)
            _err_console.print(
                f"[red]Error:[/red] Invalid category '{category}'. Valid: {valid}"
            )
            raise typer.Exit(code=4) from None

    all_rules = RuleRegistry.all_rules()

    # Apply filters
    if vendor:
        all_rules = [r for r in all_rules if vendor in getattr(r, "vendors", ())]
    if filter_cat:
        all_rules = [
            r for r in all_rules
            if getattr(r, "category", None) == filter_cat
        ]

    if not all_rules:
        _err_console.print("[yellow]No rules match the given filters.[/yellow]")
        raise typer.Exit(code=0) from None

    buf = StringIO()
    console = RichConsole(file=buf, no_color=no_color, highlight=False,
                          markup=True, width=100)

    console.rule("[bold]NetLint — Available Rules[/bold]")
    console.print()

    table = Table(
        box=rich_box.ROUNDED,
        show_header=True,
        header_style="bold",
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("Rule ID", style="bold", no_wrap=True, min_width=8)
    table.add_column("Severity", no_wrap=True, min_width=8)
    table.add_column("Category", no_wrap=True, min_width=10)
    table.add_column("Vendors", no_wrap=True, min_width=10)
    table.add_column("Title")

    for rule_cls in sorted(all_rules, key=lambda r: getattr(r, "rule_id", "")):
        rule_id   = getattr(rule_cls, "rule_id",     "—")
        sev       = getattr(rule_cls, "severity",    None)
        cat       = getattr(rule_cls, "category",    None)
        title     = getattr(rule_cls, "title",       "—")
        vendors   = getattr(rule_cls, "vendors",     ())

        sev_val   = sev.value   if sev else "—"
        cat_val   = cat.value   if cat else "—"
        sev_style = _sev_style.get(sev_val, "")
        cat_style = _cat_style.get(cat_val, "")

        table.add_row(
            rule_id,
            Text(sev_val.upper(),   style=sev_style),
            Text(cat_val.upper(),   style=cat_style),
            ", ".join(vendors),
            title,
        )

    console.print(table)
    console.print()
    console.print(f"  [dim]{len(all_rules)} rule(s) listed.[/dim]")

    typer.echo(buf.getvalue(), nl=False)
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    config_file: Annotated[
        Path,
        typer.Argument(
            help="Path to the network device configuration file.",
            resolve_path=True,
        ),
    ],
    vendor: Annotated[
        str,
        typer.Option("--vendor", "-V", help="Vendor format (default: cisco-ios)."),
    ] = "cisco-ios",
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: text (default) or json.",
        ),
    ] = "text",
    output: Annotated[
        str | None,
        typer.Option(
            "--output", "-o",
            help="Write the report to this file path instead of stdout.",
            metavar="FILE",
        ),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colour output (text format only). Implied when --output is set.",
        ),
    ] = False,
) -> None:
    """
    Generate a full report for a configuration file and write it to stdout or a file.

    When ``--output`` is given the report is written to that path and a
    short summary line is printed to stderr.  ``--no-color`` is implied
    when writing to a file.

    Exit codes: 0=clean  1=low/medium  2=high  3=critical  4=error

    Examples:

        netlint report router.cfg

        netlint report router.cfg --format json

        netlint report router.cfg --format json --output report.json

        netlint report router.cfg --format text --output report.txt --no-color
    """
    from netlint.analyzer.analyzer import Analyzer
    from netlint.exceptions import ParseError

    use_json = format.lower() == "json"

    if format.lower() not in _VALID_FORMATS:
        _err = f"Invalid format '{format}'. Valid choices: {', '.join(_VALID_FORMATS)}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("report", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None

    try:
        result = Analyzer().run(config_file, vendor=vendor)
    except FileNotFoundError:
        _err = f"File not found: {config_file}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("report", _err))
        else:
            _err_console.print(f"[red]Error:[/red] {_err}")
        raise typer.Exit(code=4) from None
    except ParseError as exc:
        _err = f"Parse error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("report", _err))
        else:
            _err_console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(code=4) from None
    except Exception as exc:  # noqa: BLE001
        _err = f"Unexpected error: {exc}"
        if use_json:
            from netlint.output.json_formatter import render_error_json
            _err_console.print(render_error_json("report", _err))
        else:
            _err_console.print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=4) from None

    # Writing to a file → always no-color, always UTF-8
    writing_to_file = output is not None
    effective_no_color = no_color or writing_to_file

    if use_json:
        from netlint.output.json_formatter import render_analyze_json
        hostname = _hostname_from_parsed(config_file, vendor)
        rendered = render_analyze_json(result, hostname=hostname)
    else:
        import netlint.output  # noqa: F401
        from netlint.output.terminal import TerminalFormatter
        rendered = TerminalFormatter().render(result, no_color=effective_no_color)

    if writing_to_file:
        out_path = Path(output)  # type: ignore[arg-type]
        out_path.write_text(rendered, encoding="utf-8")
        _err_console.print(
            f"[green]✓[/green]  Report written to [bold]{out_path}[/bold] "
            f"({len(result.findings)} finding(s))"
        )
    else:
        typer.echo(rendered, nl=False)

    raise typer.Exit(code=_exit_code_for_result(result))
