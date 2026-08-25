"""
NET-001 — Duplicate IPv4 address.

Two or more active interfaces share the same IPv4 address.  This causes
ARP conflicts, unpredictable packet forwarding, and intermittent
connectivity failures that are difficult to diagnose in production.
"""

from __future__ import annotations

import ipaddress
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
class DuplicateIpRule(Rule):
    """Detect interfaces that share an IPv4 address."""

    rule_id = "NET001"
    title = "Duplicate IPv4 address"
    description = (
        "Two or more active interfaces are configured with the same IPv4 "
        "address.  This causes ARP conflicts, unpredictable routing, and "
        "connectivity failures."
    )
    category = RuleCategory.NETWORK
    severity = Severity.CRITICAL
    recommendation = (
        "Assign a unique IPv4 address to every interface.  Audit all "
        "'ip address' statements and remove any duplicates."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        # Group by (ip_address, vrf) — same IP in different VRFs is NOT a duplicate.
        # None vrf = global routing table.
        ip_vrf_to_ifaces: dict[
            tuple[ipaddress.IPv4Address, str | None], list
        ] = defaultdict(list)
        for iface in parsed.interfaces:
            if iface.ip_address is not None and not iface.shutdown:
                key = (iface.ip_address, iface.vrf)
                ip_vrf_to_ifaces[key].append(iface)

        findings: list[Finding] = []
        for (ip_addr, _vrf), ifaces in ip_vrf_to_ifaces.items():
            if len(ifaces) < 2:
                continue
            peer_names = [i.name for i in ifaces]
            for iface in ifaces:
                others = [n for n in peer_names if n != iface.name]
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"IP address {ip_addr} is assigned to "
                            f"{iface.name} and also to: {', '.join(others)}."
                        ),
                        line_number=iface.line_number,
                        configuration_line=(
                            f" ip address {iface.ip_address} {iface.subnet_mask}"
                            if iface.subnet_mask
                            else f"interface {iface.name}"
                        ),
                    )
                )
        return findings
