"""
IF-002 — Administratively shutdown interface with configuration.

An interface that carries IP or switchport configuration but is
administratively shutdown will not forward traffic.
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
class ShutdownInterfaceRule(Rule):
    """Flag configured interfaces that are administratively shutdown."""

    rule_id = "IF002"
    title = "Shutdown interface with active configuration"
    description = (
        "An interface has IP addressing or switchport settings but is "
        "administratively shutdown and will not pass traffic."
    )
    category = RuleCategory.INTERFACE
    severity = Severity.MEDIUM
    recommendation = (
        "If the interface should be active, apply 'no shutdown'. "
        "If it is intentionally disabled, remove unused configuration "
        "to reduce clutter."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        findings: list[Finding] = []
        for iface in parsed.interfaces:
            if not iface.shutdown:
                continue
            has_config = (
                iface.ip_address is not None
                or iface.access_vlan is not None
                or iface.trunk_mode
            )
            if not has_config:
                continue
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"Interface {iface.name} is shutdown but has "
                        f"active configuration."
                    ),
                    line_number=iface.line_number,
                    configuration_line=f"interface {iface.name}",
                )
            )
        return findings
