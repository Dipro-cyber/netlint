"""
SEC-001 — Telnet enabled on VTY lines.

Telnet transmits all session data — including usernames, passwords, and
configuration commands — in cleartext.  Any attacker with network access
to a path between the operator and the device can capture credentials
with a passive packet capture.

IOS forms that enable Telnet
-----------------------------
    transport input telnet
    transport input all          (enables both SSH and Telnet)
    transport input telnet ssh   (explicit multi-protocol list)

A VTY line with no ``transport input`` statement defaults to Telnet on
older IOS versions, but that case is intentionally NOT flagged here —
the absence of a transport statement is ambiguous and version-dependent;
it is better reported as a separate hygiene rule.
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
class TelnetEnabledRule(Rule):
    """Flag any VTY line that permits Telnet as a management transport."""

    rule_id = "SEC001"
    title = "Telnet enabled on VTY lines"
    description = (
        "One or more VTY lines permit Telnet as a management transport. "
        "Telnet sends all data — including passwords — in cleartext and is "
        "vulnerable to eavesdropping and man-in-the-middle attacks."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Replace 'transport input telnet' with 'transport input ssh' on all "
        "VTY lines.  Ensure SSHv2 is enabled globally with "
        "'ip ssh version 2' and that RSA keys are generated."
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
        for vty in parsed.vty_lines:
            # TransportProtocol.ALL   → "transport input all"  → Telnet enabled ✗
            # TransportProtocol.TELNET → "transport input telnet" → Telnet enabled ✗
            # TransportProtocol.NONE  → "transport input none" → all disabled   ✓
            telnet_active = (
                TransportProtocol.TELNET in vty.transport_input
                or TransportProtocol.ALL in vty.transport_input
            )
            if not telnet_active:
                continue

            # Determine the exact transport line to cite
            if TransportProtocol.ALL in vty.transport_input:
                transport_str = "transport input all"
            else:
                protos = " ".join(p.value for p in vty.transport_input)
                transport_str = f"transport input {protos}"

            findings.append(
                self.finding(
                    config=config,
                    message=(
                        f"VTY {vty.first}–{vty.last} allows Telnet "
                        f"({transport_str!r})."
                    ),
                    line_number=vty.line_number,
                    configuration_line=transport_str,
                )
            )
        return findings
