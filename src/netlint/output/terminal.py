"""
Terminal formatter — Rich-powered human-readable report.

Produces output like:

    ╔══════════════════════════════════════════════════════╗
    ║       Network Configuration Analysis — NetLint       ║
    ╚══════════════════════════════════════════════════════╝

    Device  : CORE-RTR-01
    File    : router01.cfg
    Findings: 3   Risk Score: 68/100   Risk Level: HIGH

    ┌──────────────────────────────────────────────────────┐
    │ CRITICAL  NET001  Duplicate IPv4 address             │
    ├──────────────────────────────────────────────────────┤
    │ Line 42                                              │
    │ 10.10.10.1 appears on Gi0/1 and Gi0/2               │
    │                                                      │
    │ Recommendation:                                      │
    │ Assign a unique IPv4 address to every interface.     │
    └──────────────────────────────────────────────────────┘

Works correctly with ``--no-color`` / non-color terminals because it
uses Rich's ``Console(highlight=False, markup=True)`` and writes to a
string buffer.  When color is disabled the Rich ``no_color`` flag strips
ANSI codes and the output degrades gracefully to plain ASCII tables.
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult
from netlint.output.base import BaseFormatter
from netlint.output.registry import FormatterRegistry

# ---------------------------------------------------------------------------
# Severity → Rich style
# ---------------------------------------------------------------------------

_SEV_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEV_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH    ",
    Severity.MEDIUM: "MEDIUM  ",
    Severity.LOW: "LOW     ",
    Severity.INFO: "INFO    ",
}

_CAT_STYLE: dict[RuleCategory, str] = {
    RuleCategory.SECURITY:   "bold magenta",
    RuleCategory.NETWORK:    "bold blue",
    RuleCategory.VLAN:       "bold cyan",
    RuleCategory.ROUTING:    "bold green",
    RuleCategory.INTERFACE:  "bold yellow",
    RuleCategory.ACL:        "bold red",
    RuleCategory.MANAGEMENT: "bold white",
}


def _make_console(no_color: bool) -> Console:
    """Return a Console that writes to a StringIO buffer."""
    buf = StringIO()
    return Console(
        file=buf,
        no_color=no_color,
        highlight=False,
        markup=True,
        width=88,
    )


def _severity_text(sev: Severity) -> Text:
    t = Text(_SEV_LABEL[sev].strip(), style=_SEV_STYLE[sev])
    return t


def _finding_panel(finding: Finding, index: int) -> Panel:
    """Build a Rich Panel for one finding."""
    # Title line: severity badge + rule_id + title
    title_text = Text()
    sev_label = _SEV_LABEL[finding.severity].strip()
    title_text.append(f" {sev_label} ", style=_SEV_STYLE[finding.severity])
    title_text.append("  ")
    title_text.append(finding.rule_id, style="bold")
    title_text.append("  ")
    title_text.append(finding.title)

    # Body
    body = Text()

    if finding.line_number is not None:
        body.append(f"Line {finding.line_number}", style="dim")
        body.append("\n")

    if finding.configuration_line:
        body.append(finding.configuration_line.strip(), style="italic")
        body.append("\n")

    body.append("\n")
    body.append(finding.message)
    body.append("\n\n")
    body.append("Recommendation: ", style="bold")
    body.append(finding.recommendation)

    border_style = _SEV_STYLE[finding.severity]
    return Panel(body, title=title_text, title_align="left", border_style=border_style,
                 box=box.ROUNDED)


@FormatterRegistry.register
class TerminalFormatter(BaseFormatter):
    """Human-readable Rich terminal report."""

    format_id = "text"

    def render(self, result: AnalysisResult, **kwargs: object) -> str:
        """
        Render *result* to a Rich terminal report string.

        Keyword arguments
        -----------------
        no_color : bool
            When ``True`` all ANSI colour codes are stripped (default ``False``).
        """
        no_color: bool = bool(kwargs.get("no_color", False))
        console = _make_console(no_color)
        buf: StringIO = console.file  # type: ignore[assignment]

        self._render_header(console, result)
        self._render_summary(console, result)

        if result.findings:
            console.print()
            for i, finding in enumerate(result.findings, start=1):
                console.print(_finding_panel(finding, i))
        else:
            console.print()
            console.print("[bold green]✓[/bold green]  No findings — configuration looks clean.")

        if result.parser_warnings:
            console.print()
            console.print("[yellow]Parser warnings:[/yellow]")
            for w in result.parser_warnings:
                console.print(f"  [dim]{w}[/dim]")

        return buf.getvalue()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render_header(self, console: Console, result: AnalysisResult) -> None:
        console.rule("[bold]Network Configuration Analysis — NetLint[/bold]")
        console.print()

    def _render_summary(self, console: Console, result: AnalysisResult) -> None:
        from netlint.analyzer.scoring import score_result

        rs = score_result(result)

        # --- top-level summary table ---
        summary = Table(
            box=box.SIMPLE,
            show_header=False,
            pad_edge=False,
            padding=(0, 1),
        )
        summary.add_column(style="dim", no_wrap=True)
        summary.add_column()

        summary.add_row("File", str(result.file_path.name))
        summary.add_row("Vendor", result.vendor)
        summary.add_row(
            "Risk Score",
            Text(f"{rs.score}/100", style=rs.style),
        )
        summary.add_row(
            "Risk Level",
            Text(rs.level, style=rs.style),
        )
        console.print(summary)

        # --- per-severity breakdown ---
        breakdown = Table(
            box=box.SIMPLE,
            show_header=False,
            pad_edge=False,
            padding=(0, 1),
        )
        breakdown.add_column(style="dim", no_wrap=True)
        breakdown.add_column(justify="right", no_wrap=True)

        breakdown.add_row(
            "Critical",
            Text(str(rs.critical_count), style="bold red" if rs.critical_count else "dim"),
        )
        breakdown.add_row(
            "High",
            Text(str(rs.high_count), style="red" if rs.high_count else "dim"),
        )
        breakdown.add_row(
            "Medium",
            Text(str(rs.medium_count), style="yellow" if rs.medium_count else "dim"),
        )
        breakdown.add_row(
            "Low",
            Text(str(rs.low_count), style="cyan" if rs.low_count else "dim"),
        )
        breakdown.add_row(
            "Info",
            Text(str(rs.info_count), style="dim"),
        )
        console.print(breakdown)


# ---------------------------------------------------------------------------
# Plain-text fallback (no Rich dependency in tests that capture raw output)
# ---------------------------------------------------------------------------


def render_plain(result: AnalysisResult) -> str:
    """
    Return a minimal plain-text report with no ANSI codes.

    Used internally when ``--no-color`` is active and by unit tests that
    want predictable output.
    """
    return TerminalFormatter().render(result, no_color=True)
