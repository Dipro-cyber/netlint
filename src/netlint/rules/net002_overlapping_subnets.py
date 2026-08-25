"""
NET-002 — Overlapping IPv4 subnets.

Two or more active interfaces are configured with IPv4 networks that
overlap.  Overlapping subnets cause routing ambiguity: the device cannot
determine which interface a packet should use to reach hosts in the
shared address space, leading to unreachable networks and routing loops.

Detection uses Python's ``ipaddress`` module — no string matching.
Specifically, ``network_a.overlaps(network_b)`` is used, which correctly
handles all cases:

    192.168.1.0/24 overlaps 192.168.1.128/25  ✓
    10.0.0.0/8     overlaps 10.1.0.0/16        ✓
    10.0.0.0/24    does NOT overlap 10.0.1.0/24 ✓
"""

from __future__ import annotations

import ipaddress
from itertools import combinations
from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import Interface, ParsedConfig


@RuleRegistry.register
class OverlappingSubnetsRule(Rule):
    """Detect pairs of active interfaces whose IPv4 networks overlap."""

    rule_id = "NET002"
    title = "Overlapping IPv4 subnets"
    description = (
        "Two or more active interfaces are configured with overlapping IPv4 "
        "networks.  This creates routing ambiguity and can cause packets to "
        "be forwarded incorrectly or dropped."
    )
    category = RuleCategory.NETWORK
    severity = Severity.HIGH
    recommendation = (
        "Redesign the IP addressing plan so that each interface is assigned "
        "a non-overlapping subnet.  Use 'show ip route' to verify routing "
        "table correctness after making changes."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        # Collect active interfaces that have a network.
        # Only compare interfaces within the same VRF (or both in global table).
        routed: list[Interface] = [
            iface
            for iface in parsed.interfaces
            if iface.ip_network is not None and not iface.shutdown
        ]

        # Track pairs already reported to avoid emitting A→B and B→A
        reported: set[frozenset[str]] = set()
        findings: list[Finding] = []

        for iface_a, iface_b in combinations(routed, 2):
            # Skip pairs from different VRFs — overlap between VRFs is expected
            if iface_a.vrf != iface_b.vrf:
                continue

            # Identical networks are caught by NET001; skip here
            if iface_a.ip_network == iface_b.ip_network:
                continue

            net_a: ipaddress.IPv4Network = iface_a.ip_network  # type: ignore[assignment]
            net_b: ipaddress.IPv4Network = iface_b.ip_network  # type: ignore[assignment]

            if not net_a.overlaps(net_b):
                continue

            pair_key = frozenset({iface_a.name, iface_b.name})
            if pair_key in reported:
                continue
            reported.add(pair_key)

            # Emit one finding per interface in the overlapping pair so each
            # finding carries the exact line number of one offending stanza.
            for iface, other, other_net in (
                (iface_a, iface_b, net_b),
                (iface_b, iface_a, net_a),
            ):
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"Interface {iface.name} ({iface.ip_network}) "
                            f"overlaps with {other.name} ({other_net})."
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
