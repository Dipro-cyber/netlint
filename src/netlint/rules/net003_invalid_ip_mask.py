"""
NET-003 — Invalid IP address or subnet mask.

Flags interface and route statements where the IPv4 address or subnet
mask cannot be parsed or is not a valid Cisco IOS mask.
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

_LINE_RE = re.compile(r"^Line (\d+):")


@RuleRegistry.register
class InvalidIpMaskRule(Rule):
    """Detect invalid IPv4 addresses and unrecognised subnet masks."""

    rule_id = "NET003"
    title = "Invalid IP address or subnet mask"
    description = (
        "An interface or route statement contains an IPv4 address or subnet "
        "mask that is syntactically invalid or not a recognised Cisco mask."
    )
    category = RuleCategory.NETWORK
    severity = Severity.HIGH
    recommendation = (
        "Correct the IP address to a valid dotted-decimal IPv4 value and "
        "use a standard subnet mask (e.g. 255.255.255.0). "
        "Verify with 'show ip interface brief' after applying the fix."
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

        # Interfaces with a mask string that did not map to a prefix length.
        for iface in parsed.interfaces:
            if iface.subnet_mask is not None and iface.prefix_length is None:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"Interface {iface.name} has an unrecognised "
                            f"subnet mask '{iface.subnet_mask}'."
                        ),
                        line_number=iface.line_number,
                        configuration_line=(
                            f" ip address {iface.ip_address} {iface.subnet_mask}"
                            if iface.ip_address
                            else f"interface {iface.name}"
                        ),
                    )
                )

        # Parser warnings for bad IPs, masks, and malformed address lines.
        for warning in parsed.warnings:
            lower = warning.lower()
            if not any(
                kw in lower
                for kw in (
                    "bad ip address",
                    "unrecognised subnet mask",
                    "unknown route mask",
                    "ip address' missing",
                )
            ):
                continue
            line_number: int | None = None
            m = _LINE_RE.match(warning)
            if m:
                line_number = int(m.group(1))
            findings.append(
                self.finding(
                    config=config,
                    message=warning.split(":", 1)[-1].strip(),
                    line_number=line_number,
                    configuration_line=config.lines[line_number - 1].strip()
                    if line_number and 0 < line_number <= len(config.lines)
                    else None,
                )
            )

        return findings
