"""
VLAN-001 — Undefined VLAN.

An interface references an access VLAN that does not appear in the
device's VLAN database (i.e. there is no ``vlan <id>`` block in the
configuration).

When a VLAN is not defined, switch hardware silently discards traffic
tagged with that VLAN ID.  Hosts connected to the port will be unable
to communicate even though the port appears operationally up.
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
class UndefinedVlanRule(Rule):
    """Flag access ports whose VLAN is not declared in the VLAN database."""

    rule_id = "VLAN001"
    title = "Undefined VLAN referenced on interface"
    description = (
        "An interface is configured as an access port for a VLAN that has "
        "no corresponding 'vlan <id>' block in the configuration.  Packets "
        "tagged with that VLAN ID will be discarded by the switch."
    )
    category = RuleCategory.VLAN
    severity = Severity.MEDIUM
    recommendation = (
        "Either create the missing VLAN with 'vlan <id>' (and optionally "
        "'name <name>'), or correct the access VLAN assignment on the "
        "interface to reference a VLAN that is already defined."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        # Skip VLAN check entirely if no VLANs are defined at all.
        # On a pure router (no VLAN database) every VLAN would fire, which
        # produces noise rather than actionable findings.
        if not parsed.vlans:
            return []

        defined_vlan_ids: set[int] = {v.vlan_id for v in parsed.vlans}

        findings: list[Finding] = []
        for iface in parsed.interfaces:
            if iface.access_vlan is None:
                continue
            if iface.access_vlan in defined_vlan_ids:
                continue
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"Interface {iface.name} is assigned to access VLAN "
                        f"{iface.access_vlan}, which is not defined in the "
                        f"VLAN database."
                    ),
                    line_number=iface.line_number,
                    configuration_line=(
                        f" switchport access vlan {iface.access_vlan}"
                    ),
                )
            )
        return findings
