"""
VLAN-004 — Invalid VLAN ID.

IEEE 802.1Q VLAN IDs must be in the range 1–4094.  IDs 0 and 4095 are
reserved and must not be used in normal configurations.
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

_VALID_VLAN_RANGE = range(1, 4095)


@RuleRegistry.register
class InvalidVlanIdRule(Rule):
    """Detect VLAN IDs outside the valid 1–4094 range."""

    rule_id = "VLAN004"
    title = "Invalid VLAN ID"
    description = (
        "A VLAN ID is outside the valid IEEE 802.1Q range of 1–4094."
    )
    category = RuleCategory.VLAN
    severity = Severity.HIGH
    recommendation = (
        "Use a VLAN ID between 1 and 4094.  VLAN 0 and 4095 are reserved."
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

        for vlan in parsed.vlans:
            if vlan.vlan_id in _VALID_VLAN_RANGE:
                continue
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"VLAN ID {vlan.vlan_id} is invalid; "
                        f"valid range is 1–4094."
                    ),
                    line_number=vlan.line_number,
                    configuration_line=f"vlan {vlan.vlan_id}",
                )
            )

        for iface in parsed.interfaces:
            if iface.access_vlan is not None and iface.access_vlan not in _VALID_VLAN_RANGE:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"Interface {iface.name} references invalid "
                            f"access VLAN {iface.access_vlan}."
                        ),
                        line_number=iface.line_number,
                        configuration_line=(
                            f" switchport access vlan {iface.access_vlan}"
                        ),
                    )
                )

        return findings
