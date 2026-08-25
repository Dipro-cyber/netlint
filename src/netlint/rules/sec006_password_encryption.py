"""
SEC-006 — Password encryption not enabled.

When ``service password-encryption`` is disabled, Type 0 (cleartext)
passwords on VTY lines and enable passwords are stored reversibly
or in plaintext in the running configuration.
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


def _is_cleartext_password(password_line: str) -> bool:
    """
    Return True when a VTY password line is Type 0 cleartext.

    Type 7: ``password 7 <hash>``
    Type 5: ``password 5 <hash>`` (enable secret style)
    Cleartext: ``password <plaintext>``
    """
    tokens = password_line.split()
    if len(tokens) < 2:
        return False
    if tokens[1].isdigit():
        return False
    return True


@RuleRegistry.register
class PasswordEncryptionRule(Rule):
    """Flag disabled password encryption and cleartext passwords."""

    rule_id = "SEC006"
    title = "Password encryption disabled"
    description = (
        "'service password-encryption' is not enabled, or cleartext "
        "passwords are present in the configuration."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Enable 'service password-encryption' and replace all cleartext "
        "'password' and 'enable password' statements with "
        "'enable secret' and Type-7 or AAA-based authentication."
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

        if not parsed.service_password_encryption:
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        "'service password-encryption' is not enabled; "
                        "passwords may be stored in cleartext."
                    ),
                    line_number=parsed.service_password_encryption_line,
                    configuration_line="service password-encryption",
                )
            )

        if parsed.enable_password_line is not None and not parsed.enable_secret_configured:
            findings.append(
                self.finding(
                    config=config,
                    message=(
                        "Cleartext 'enable password' is configured instead "
                        "of 'enable secret'."
                    ),
                    line_number=parsed.enable_password_line,
                    configuration_line="enable password",
                    severity=Severity.CRITICAL,
                )
            )

        for vty in parsed.vty_lines:
            if vty.password and _is_cleartext_password(f"password {vty.password}"):
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"VTY {vty.first}–{vty.last} has a cleartext "
                            f"password configured."
                        ),
                        line_number=vty.line_number,
                        configuration_line="password <cleartext>",
                        severity=Severity.CRITICAL,
                    )
                )

        return findings
