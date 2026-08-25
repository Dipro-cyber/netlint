"""
VLAN-003 — Unused VLAN.

A VLAN is defined in the VLAN database but is not referenced by any
access port, trunk allowed list, or VLAN interface (SVI).
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


def _expand_vlan_list(vlan_str: str) -> set[int]:
    """Expand '10,20,30-40' into a set of VLAN IDs."""
    result: set[int] = set()
    for part in vlan_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                result.update(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                result.add(int(part))
            except ValueError:
                continue
    return result


@RuleRegistry.register
class UnusedVlanRule(Rule):
    """Flag VLANs defined but not used on any interface."""

    rule_id = "VLAN003"
    title = "Unused VLAN"
    description = (
        "A VLAN is defined in the VLAN database but is not assigned to "
        "any access port, trunk allowed list, or VLAN interface."
    )
    category = RuleCategory.VLAN
    severity = Severity.LOW
    recommendation = (
        "Remove unused VLANs from the database or assign them to an "
        "interface.  Stale VLANs increase configuration complexity and "
        "audit surface."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None or not parsed.vlans:
            return []

        referenced: set[int] = set()

        for iface in parsed.interfaces:
            if iface.access_vlan is not None:
                referenced.add(iface.access_vlan)
            if iface.trunk_allowed_vlans:
                referenced.update(_expand_vlan_list(iface.trunk_allowed_vlans))
            # VLAN SVI interfaces (e.g. Vlan10 → VLAN 10)
            m = re.match(r"^vlan(\d+)$", iface.name, re.IGNORECASE)
            if m:
                referenced.add(int(m.group(1)))

        findings: list[Finding] = []
        for vlan in parsed.vlans:
            if vlan.vlan_id in referenced:
                continue
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"VLAN {vlan.vlan_id} is defined but not referenced "
                        f"by any interface."
                    ),
                    line_number=vlan.line_number,
                    configuration_line=f"vlan {vlan.vlan_id}",
                )
            )
        return findings
