"""
IF-001 — Missing interface description.

Interfaces without a ``description`` statement are harder to operate,
troubleshoot, and audit.  Production interfaces should always be labelled.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import ParsedConfig

# Interfaces that are exempt from description requirements.
_SKIP_RE = re.compile(
    r"^(null|tunnel\d+|nve\d+)$",
    re.IGNORECASE,
)


def _needs_description(name: str, iface) -> bool:
    """Return True when this interface should have a description."""
    if _SKIP_RE.match(name):
        return False
    # Any interface with L3 or L2 configuration is significant.
    return (
        iface.ip_address is not None
        or iface.access_vlan is not None
        or iface.trunk_mode
        or re.match(
            r"^(gigabitethernet|fastethernet|tengigabitethernet|"
            r"ethernet|serial|hundredgige|port-channel|vlan|loopback|"
            r"management)",
            name,
            re.IGNORECASE,
        )
    )


@RuleRegistry.register
class MissingDescriptionRule(Rule):
    """Flag configured interfaces that lack a description."""

    rule_id = "IF001"
    title = "Missing interface description"
    description = (
        "An interface has configuration but no 'description' statement. "
        "Undocumented interfaces increase operational risk."
    )
    category = RuleCategory.INTERFACE
    severity = Severity.LOW
    recommendation = (
        "Add a descriptive 'description' line to every interface, "
        "e.g. 'description Uplink to DIST-SW-01'."
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
        for iface in parsed.interfaces:
            if iface.description is not None:
                continue
            if not _needs_description(iface.name, iface):
                continue
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"Interface {iface.name} has no description."
                    ),
                    line_number=iface.line_number,
                    configuration_line=f"interface {iface.name}",
                )
            )
        return findings
