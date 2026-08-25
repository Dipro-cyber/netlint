"""
DiffFormatter — Rich terminal report for ``netlint diff``.

Output structure
----------------

  ─── Configuration Change Analysis — NetLint ───

  Old  : production.cfg
  New  : proposed.cfg
  Changes: 4 added  2 removed  3 modified

  ── Added ──────────────────────────────────────
  [+] interface GigabitEthernet0/5
  [+] VLAN 50  (name: GUEST)
  [+] static route 10.20.0.0/16 via 10.0.0.2
  [+] ACL OUTSIDE_IN

  ── Removed ────────────────────────────────────
  [-] interface GigabitEthernet0/4

  ── Modified ───────────────────────────────────
  [~] GigabitEthernet0/1  ip_address: 10.0.0.1 → 10.0.0.2
  [~] line vty 0 4  transport_input changed

  ── New Risks ──────────────────────────────────
  ╭─ HIGH  NET002  Overlapping IPv4 subnets ──────╮
  │ ...                                           │
  ╰───────────────────────────────────────────────╯

  ── Resolved (improvements) ────────────────────
  ✓  SEC001  Telnet enabled on VTY lines  (fixed)

  ── Persisting Issues ──────────────────────────
  ⚠  NET001  Duplicate IPv4 address  (unchanged)

  ─── Deployment Recommendation ─────────────────
  ✖  DO NOT DEPLOY
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from netlint.diff.models import (
    ConfigDiff,
)
from netlint.diff.risk import DiffRiskResult
from netlint.models.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Severity colours (re-used from terminal.py pattern)
# ---------------------------------------------------------------------------

_SEV_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

_SEV_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH    ",
    Severity.MEDIUM:   "MEDIUM  ",
    Severity.LOW:      "LOW     ",
    Severity.INFO:     "INFO    ",
}


def _make_console(no_color: bool) -> Console:
    buf = StringIO()
    return Console(file=buf, no_color=no_color, highlight=False,
                   markup=True, width=88)


# ---------------------------------------------------------------------------
# Finding panel (same look as terminal.py)
# ---------------------------------------------------------------------------

def _finding_panel(finding: Finding, label_prefix: str = "") -> Panel:
    title_text = Text()
    if label_prefix:
        title_text.append(f"{label_prefix} ", style="bold")
    title_text.append(
        f" {_SEV_LABEL[finding.severity].strip()} ",
        style=_SEV_STYLE[finding.severity],
    )
    title_text.append("  ")
    title_text.append(finding.rule_id, style="bold")
    title_text.append("  ")
    title_text.append(finding.title)

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

    return Panel(
        body,
        title=title_text,
        title_align="left",
        border_style=_SEV_STYLE[finding.severity],
        box=box.ROUNDED,
    )


# ---------------------------------------------------------------------------
# Change-line helpers
# ---------------------------------------------------------------------------

def _format_value(v: object) -> str:
    """Produce a clean human-readable string for a field delta value."""
    import ipaddress as _ip
    if v is None:
        return "(none)"
    if isinstance(v, _ip.IPv4Address):
        return str(v)
    if isinstance(v, _ip.IPv4Network):
        return str(v)
    if isinstance(v, tuple):
        # e.g. transport_input tuple of TransportProtocol enums
        parts = [getattr(item, "value", str(item)) for item in v]
        return ", ".join(parts) if parts else "(none)"
    if hasattr(v, "value"):        # single enum
        return str(v.value)
    return str(v)


def _added_line(text: str) -> Text:
    t = Text()
    t.append("[+] ", style="bold green")
    t.append(text)
    return t


def _removed_line(text: str) -> Text:
    t = Text()
    t.append("[-] ", style="bold red")
    t.append(text)
    return t


def _modified_line(text: str) -> Text:
    t = Text()
    t.append("[~] ", style="bold yellow")
    t.append(text)
    return t


def _label_for_interface(iface: object) -> str:
    name = getattr(iface, "name", str(iface))
    ip = getattr(iface, "ip_address", None)
    mask = getattr(iface, "subnet_mask", None)
    if ip and mask:
        return f"interface {name}  ({ip}/{getattr(iface, 'prefix_length', mask)})"
    return f"interface {name}"


def _label_for_vlan(vlan: object) -> str:
    vid = getattr(vlan, "vlan_id", "?")
    name = getattr(vlan, "name", None)
    return f"VLAN {vid}" + (f"  (name: {name})" if name else "")


def _label_for_route(route: object) -> str:
    net = getattr(route, "network", "?")
    nh = getattr(route, "next_hop", None)
    iface = getattr(route, "exit_interface", None)
    via = f"via {nh}" if nh else (f"via {iface}" if iface else "")
    return f"static route {net}" + (f"  {via}" if via else "")


def _label_for_acl(acl: object) -> str:
    return f"ACL {getattr(acl, 'name', '?')} ({getattr(acl, 'acl_type', '')})"


# ---------------------------------------------------------------------------
# Main formatter
# ---------------------------------------------------------------------------

class DiffFormatter:
    """
    Renders a :class:`DiffRiskResult` as a Rich terminal report.

    Parameters
    ----------
    no_color:
        Strip all ANSI codes — safe for CI log capture.
    """

    def render(
        self,
        diff_result: DiffRiskResult,
        *,
        no_color: bool = False,
    ) -> str:
        console = _make_console(no_color)
        old_res = diff_result.old_result
        new_res = diff_result.new_result

        self._header(console, old_res, new_res)
        self._change_summary(console, diff_result)
        self._added_section(console, diff_result)
        self._removed_section(console, diff_result)
        self._modified_section(console, diff_result)
        self._new_risks_section(console, diff_result)
        self._resolved_section(console, diff_result)
        self._persisting_section(console, diff_result)
        self._recommendation(console, diff_result)

        buf: StringIO = console.file  # type: ignore[assignment]
        return buf.getvalue()

    # ------------------------------------------------------------------

    def _header(self, console: Console, old_res: object, new_res: object) -> None:
        console.rule("[bold]Configuration Change Analysis — NetLint[/bold]")
        console.print()
        tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0, 1))
        tbl.add_column(style="dim", no_wrap=True)
        tbl.add_column()
        tbl.add_row("Old", str(getattr(old_res, "file_path", "old.cfg")))
        tbl.add_row("New", str(getattr(new_res, "file_path", "new.cfg")))
        console.print(tbl)

    def _change_summary(self, console: Console, r: DiffRiskResult) -> None:
        # Count changes from the two results; pull from stored diff via
        # comparing the two ParsedConfigs inside the results.
        # We surface high-level counts from the DiffRiskResult.
        new_count  = len(r.new_findings)
        res_count  = len(r.resolved_findings)
        pers_count = len(r.persisting_findings)

        tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0, 1))
        tbl.add_column(style="dim", no_wrap=True)
        tbl.add_column()
        tbl.add_row(
            "New risks",
            Text(str(new_count), style="bold red" if new_count else "bold green"),
        )
        tbl.add_row("Resolved", Text(str(res_count), style="bold green"))
        tbl.add_row("Persisting", Text(str(pers_count), style="yellow" if pers_count else "dim"))
        console.print(tbl)

    # ------------------------------------------------------------------
    # Change sections — accept a ConfigDiff directly when available
    # ------------------------------------------------------------------

    def render_with_diff(
        self,
        config_diff: ConfigDiff,
        diff_result: DiffRiskResult,
        *,
        no_color: bool = False,
    ) -> str:
        """
        Full render that also shows the structural diff (added/removed/modified).
        This is the primary entry point used by the CLI.
        """
        console = _make_console(no_color)
        old_res = diff_result.old_result
        new_res = diff_result.new_result

        self._header(console, old_res, new_res)
        self._change_summary_from_diff(console, config_diff, diff_result)
        self._added_from_diff(console, config_diff)
        self._removed_from_diff(console, config_diff)
        self._modified_from_diff(console, config_diff)
        self._new_risks_section(console, diff_result)
        self._resolved_section(console, diff_result)
        self._persisting_section(console, diff_result)
        self._recommendation(console, diff_result)

        buf: StringIO = console.file  # type: ignore[assignment]
        return buf.getvalue()

    def _change_summary_from_diff(
        self,
        console: Console,
        d: ConfigDiff,
        r: DiffRiskResult,
    ) -> None:
        tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0, 1))
        tbl.add_column(style="dim", no_wrap=True)
        tbl.add_column()

        added   = d.added_count
        removed = d.removed_count
        modified = d.modified_count
        new_risks = len(r.new_findings)

        tbl.add_row("Added",    Text(str(added),    style="bold green" if added else "dim"))
        tbl.add_row("Removed",  Text(str(removed),  style="bold red"   if removed else "dim"))
        tbl.add_row("Modified", Text(str(modified), style="yellow"     if modified else "dim"))
        tbl.add_row(
            "New risks",
            Text(str(new_risks), style="bold red" if new_risks else "bold green"),
        )
        console.print(tbl)

    def _added_from_diff(self, console: Console, d: ConfigDiff) -> None:
        items: list[Text] = []

        if d.hostname_change and d.hostname_change.new_hostname != d.hostname_change.old_hostname:
            if d.hostname_change.old_hostname is None:
                items.append(_added_line(f"hostname {d.hostname_change.new_hostname}"))

        for iface in d.interfaces_added:
            items.append(_added_line(_label_for_interface(iface)))
        for vlan in d.vlans_added:
            items.append(_added_line(_label_for_vlan(vlan)))
        for route in d.routes_added:
            items.append(_added_line(_label_for_route(route)))
        for acl in d.acls_added:
            items.append(_added_line(_label_for_acl(acl)))
        if d.http_server_change and d.http_server_change.new_http \
                and not d.http_server_change.old_http:
            items.append(_added_line("ip http server"))
        hsc = d.http_server_change
        if hsc and hsc.new_https and not hsc.old_https:
            items.append(_added_line("ip http secure-server"))

        if not items:
            return
        console.print()
        console.rule("[green]Added[/green]", style="green")
        for item in items:
            console.print(item)

    def _removed_from_diff(self, console: Console, d: ConfigDiff) -> None:
        items: list[Text] = []

        if d.hostname_change and d.hostname_change.new_hostname is None:
            items.append(_removed_line(f"hostname {d.hostname_change.old_hostname}"))

        for iface in d.interfaces_removed:
            items.append(_removed_line(_label_for_interface(iface)))
        for vlan in d.vlans_removed:
            items.append(_removed_line(_label_for_vlan(vlan)))
        for route in d.routes_removed:
            items.append(_removed_line(_label_for_route(route)))
        for acl in d.acls_removed:
            items.append(_removed_line(_label_for_acl(acl)))
        if d.http_server_change and d.http_server_change.old_http \
                and not d.http_server_change.new_http:
            items.append(_removed_line("ip http server"))

        if not items:
            return
        console.print()
        console.rule("[red]Removed[/red]", style="red")
        for item in items:
            console.print(item)

    def _modified_from_diff(self, console: Console, d: ConfigDiff) -> None:
        items: list[Text] = []

        if d.hostname_change and d.hostname_change.old_hostname and d.hostname_change.new_hostname:
            items.append(_modified_line(d.hostname_change.summary))

        for change in d.interfaces_modified:
            for delta in change.deltas:
                old_v = _format_value(delta.old_value)
                new_v = _format_value(delta.new_value)
                items.append(_modified_line(
                    f"{change.name}  {delta.field_name}: {old_v} → {new_v}"
                ))
        for vchange in d.vlans_modified:
            items.append(_modified_line(vchange.summary))
        for rchange in d.routes_modified:
            for delta in rchange.deltas:
                old_v = _format_value(delta.old_value)
                new_v = _format_value(delta.new_value)
                items.append(_modified_line(
                    f"route {rchange.network}  {delta.field_name}: {old_v} → {new_v}"
                ))
        for achange in d.acls_modified:
            items.append(_modified_line(achange.summary))
        for vtchange in d.vty_modified:
            for delta in vtchange.deltas:
                old_v = _format_value(delta.old_value)
                new_v = _format_value(delta.new_value)
                items.append(_modified_line(
                    f"line vty {vtchange.first} {vtchange.last}"
                    f"  {delta.field_name}: {old_v} → {new_v}"
                ))
        if d.http_server_change and (
            d.http_server_change.old_http != d.http_server_change.new_http
            or d.http_server_change.old_https != d.http_server_change.new_https
        ):
            if d.http_server_change.old_http or d.http_server_change.new_http:
                pass  # already handled in added/removed
            if d.http_server_change.old_https != d.http_server_change.new_https:
                items.append(_modified_line(d.http_server_change.summary))

        if not items:
            return
        console.print()
        console.rule("[yellow]Modified[/yellow]", style="yellow")
        for item in items:
            console.print(item)

    # ------------------------------------------------------------------
    # Risk sections
    # ------------------------------------------------------------------

    def _added_section(self, console: Console, r: DiffRiskResult) -> None:
        """Fallback added section used when no ConfigDiff is available."""
        pass  # Only meaningful via render_with_diff

    def _removed_section(self, console: Console, r: DiffRiskResult) -> None:
        pass

    def _modified_section(self, console: Console, r: DiffRiskResult) -> None:
        pass

    def _new_risks_section(self, console: Console, r: DiffRiskResult) -> None:
        if not r.new_findings:
            console.print()
            console.print("[bold green]✓[/bold green]  No new risks introduced.")
            return
        console.print()
        console.rule("[bold red]New Risks[/bold red]", style="red")
        for finding in r.new_findings:
            console.print(_finding_panel(finding, label_prefix="NEW"))

    def _resolved_section(self, console: Console, r: DiffRiskResult) -> None:
        if not r.resolved_findings:
            return
        console.print()
        console.rule("[bold green]Resolved (improvements)[/bold green]", style="green")
        for finding in r.resolved_findings:
            t = Text()
            t.append("✓  ", style="bold green")
            t.append(f"{finding.rule_id}  ", style="bold")
            t.append(finding.title)
            t.append("  ", style="dim")
            t.append("(fixed)", style="bold green")
            console.print(t)

    def _persisting_section(self, console: Console, r: DiffRiskResult) -> None:
        if not r.persisting_findings:
            return
        console.print()
        console.rule("[yellow]Persisting Issues[/yellow]", style="yellow")
        for finding in r.persisting_findings:
            t = Text()
            sev_style = _SEV_STYLE[finding.severity]
            t.append(f"  {_SEV_LABEL[finding.severity].strip()}  ", style=sev_style)
            t.append(f"{finding.rule_id}  ", style="bold")
            t.append(finding.title)
            t.append("  ", style="dim")
            t.append("(unchanged)", style="dim")
            console.print(t)

    def _recommendation(self, console: Console, r: DiffRiskResult) -> None:
        console.print()
        console.rule("[bold]Deployment Recommendation[/bold]")
        console.print()

        style = r.recommendation_style
        icon = "✖" if "DO NOT" in r.deployment_recommendation else (
            "⚠" if "REVIEW" in r.deployment_recommendation else "✓"
        )
        console.print(
            f"  [{style}]{icon}  {r.deployment_recommendation}[/{style}]"
        )
        console.print()
