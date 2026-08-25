"""
SEC-003 — VTY lines have no inbound access-class.

Without an access-class restricting which source IPs can reach the
management plane, any host on any reachable network can attempt to
log in to the device.
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
class VtyNoAclRule(Rule):
    """Flag VTY lines that lack an inbound access-class."""

    rule_id = "SEC003"
    title = "VTY lines unrestricted — no inbound access-class"
    description = (
        "One or more VTY lines do not have an 'access-class ... in' "
        "statement.  Without source-IP filtering, any reachable host can "
        "attempt management access to the device."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Create a named ACL that permits only known management host addresses "
        "and apply it to all VTY lines with "
        "'access-class <ACL-NAME> in'."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        findings: list[Finding] = []
        for vty in parsed.vty_lines:
            if vty.access_class_in is None:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"VTY line {vty.first}–{vty.last} has no "
                            f"inbound access-class (unrestricted management access)."
                        ),
                        line_number=vty.line_number,
                        configuration_line=f"line vty {vty.first} {vty.last}",
                    )
                )
        return findings
