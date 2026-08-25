"""
RTG-001 — Missing default route.

A router with IP routing enabled and L3 interfaces but no default
route cannot reach destinations outside its directly connected networks.
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


@RuleRegistry.register
class MissingDefaultRouteRule(Rule):
    """Flag L3 devices without a default route."""

    rule_id = "RTG001"
    title = "Missing default route"
    description = (
        "The device has IP routing enabled and L3 interfaces but no "
        "default route (0.0.0.0/0) configured."
    )
    category = RuleCategory.ROUTING
    severity = Severity.MEDIUM
    recommendation = (
        "Add a default route, e.g. 'ip route 0.0.0.0 0.0.0.0 <next-hop>'. "
        "If the device is a pure switch with SVIs only, verify that "
        "upstream routing is intentional."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        # Need ip routing and at least one non-loopback L3 interface.
        has_l3 = any(
            iface.ip_address is not None
            and not re.match(r"^loopback", iface.name, re.IGNORECASE)
            for iface in parsed.interfaces
        )
        if not has_l3:
            return []

        # Treat ip routing or OSPF/BGP presence as an L3 device.
        is_router = (
            parsed.ip_routing_enabled
            or bool(parsed.ospf_processes)
            or bool(parsed.bgp_processes)
            or has_l3
        )
        if not is_router:
            return []

        if parsed.default_routes:
            return []

        # Find a representative L3 interface line for the finding.
        ref_iface = next(
            (
                i
                for i in parsed.interfaces
                if i.ip_address is not None
                and not re.match(r"^loopback", i.name, re.IGNORECASE)
            ),
            None,
        )
        line_number = ref_iface.line_number if ref_iface else None

        return [
            self.finding(
                config=config,
                message=(
                    "No default route (0.0.0.0/0) is configured on this "
                    "L3 device."
                ),
                line_number=line_number,
                configuration_line="ip route 0.0.0.0 0.0.0.0 <next-hop>",
            )
        ]
