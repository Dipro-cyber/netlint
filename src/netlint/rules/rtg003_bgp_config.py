"""
RTG-003 — BGP configuration problems.

Checks for BGP processes without neighbours and neighbours missing
a remote-as assignment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import ParsedConfig


@RuleRegistry.register
class BgpConfigRule(Rule):
    """Detect common BGP configuration issues."""

    rule_id = "RTG003"
    title = "BGP configuration problem"
    description = (
        "The BGP configuration has a structural problem such as no "
        "neighbours defined or a neighbour missing 'remote-as'."
    )
    category = RuleCategory.ROUTING
    severity = Severity.HIGH
    recommendation = (
        "Configure at least one BGP neighbour with 'neighbor <addr> "
        "remote-as <asn>'.  Verify the AS number and peering address "
        "with 'show bgp summary'."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None or not parsed.bgp_processes:
            return []

        findings: list[Finding] = []

        for proc in parsed.bgp_processes:
            if not proc.neighbors:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"BGP AS {proc.as_number} has no "
                            f"'neighbor' statements configured."
                        ),
                        line_number=proc.line_number,
                        configuration_line=f"router bgp {proc.as_number}",
                    )
                )
                continue

            for neighbor in proc.neighbors:
                if neighbor.remote_as is not None:
                    continue
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"BGP neighbor {neighbor.address} is missing "
                            f"a 'remote-as' assignment."
                        ),
                        line_number=neighbor.line_number,
                        configuration_line=f"neighbor {neighbor.address}",
                    )
                )

        return findings
