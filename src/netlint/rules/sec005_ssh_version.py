"""
SEC-005 — Weak or absent SSH configuration.

When VTY lines permit SSH but ``ip ssh version 2`` is not configured,
the device may negotiate SSHv1, which has known cryptographic weaknesses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.parser.cisco_ios.models import TransportProtocol
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import ParsedConfig


@RuleRegistry.register
class WeakSshRule(Rule):
    """Flag SSHv1 or missing SSH version when SSH transport is enabled."""

    rule_id = "SEC005"
    title = "Weak or absent SSH configuration"
    description = (
        "VTY lines allow SSH management but 'ip ssh version 2' is not "
        "configured, or SSH version 1 is explicitly enabled."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Configure 'ip ssh version 2' globally.  Generate RSA keys with "
        "'crypto key generate rsa modulus 2048' if not already present."
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

        ssh_vty_active = any(
            TransportProtocol.SSH in vty.transport_input
            or TransportProtocol.ALL in vty.transport_input
            for vty in parsed.vty_lines
        )
        if not ssh_vty_active:
            return []

        if parsed.ssh_version == 1:
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        "'ip ssh version 1' is configured.  SSHv1 has "
                        "known cryptographic weaknesses."
                    ),
                    line_number=parsed.ssh_version_line,
                    configuration_line="ip ssh version 1",
                )
            )
        elif parsed.ssh_version != 2:
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        "VTY lines allow SSH but 'ip ssh version 2' is "
                        "not configured globally."
                    ),
                    line_number=parsed.vty_lines[0].line_number
                    if parsed.vty_lines
                    else None,
                    configuration_line="ip ssh version 2",
                )
            )

        return findings
