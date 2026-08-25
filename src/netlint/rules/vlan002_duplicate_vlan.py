"""
VLAN-002 — Duplicate VLAN ID in VLAN database.

Two or more ``vlan <id>`` blocks declare the same VLAN ID, which can
cause unpredictable behaviour when applying configuration.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import ParsedConfig


@RuleRegistry.register
class DuplicateVlanRule(Rule):
    """Detect duplicate VLAN IDs in the global VLAN database."""

    rule_id = "VLAN002"
    title = "Duplicate VLAN ID"
    description = (
        "The VLAN database contains more than one 'vlan <id>' block with "
        "the same VLAN ID."
    )
    category = RuleCategory.VLAN
    severity = Severity.MEDIUM
    recommendation = (
        "Remove the duplicate 'vlan <id>' block and consolidate VLAN "
        "settings into a single stanza."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None or not parsed.vlans:
            return []

        by_id: dict[int, list] = defaultdict(list)
        for vlan in parsed.vlans:
            by_id[vlan.vlan_id].append(vlan)

        findings: list[Finding] = []
        for vlan_id, entries in by_id.items():
            if len(entries) < 2:
                continue
            for vlan in entries:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"VLAN {vlan_id} is declared more than once "
                            f"in the VLAN database."
                        ),
                        line_number=vlan.line_number,
                        configuration_line=f"vlan {vlan_id}",
                    )
                )
        return findings
