"""
SEC-004 — Insecure SNMP configuration.

SNMPv1/v2c community strings are transmitted in cleartext.  Read-write
communities and well-known default strings (``public``, ``private``)
are especially dangerous.
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

_DEFAULT_COMMUNITIES = frozenset({"public", "private", "cisco"})


@RuleRegistry.register
class InsecureSnmpRule(Rule):
    """Flag cleartext SNMP communities and weak community strings."""

    rule_id = "SEC004"
    title = "Insecure SNMP configuration"
    description = (
        "The device uses SNMPv1/v2c community strings, which transmit "
        "management data in cleartext.  Read-write or default community "
        "strings are especially risky."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Remove cleartext SNMP communities.  Use SNMPv3 with "
        "'snmp-server group' and 'snmp-server user' for authenticated, "
        "encrypted management access."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None or not parsed.snmp_communities:
            return []

        findings: list[Finding] = []
        for community, permission, line_number in parsed.snmp_communities:
            perm_lower = permission.lower()
            comm_lower = community.lower()

            if perm_lower == "rw":
                sev = Severity.CRITICAL
                detail = (
                    f"SNMP read-write community '{community}' is configured."
                )
            elif comm_lower in _DEFAULT_COMMUNITIES:
                sev = Severity.HIGH
                detail = (
                    f"SNMP community '{community}' uses a well-known "
                    f"default string."
                )
            else:
                sev = Severity.MEDIUM
                detail = (
                    f"SNMPv1/v2c community '{community}' ({permission}) "
                    f"transmits data in cleartext."
                )

            findings.append(
                self.finding(
                    config=config,
                    message=detail,
                    line_number=line_number,
                    configuration_line=(
                        f"snmp-server community {community} {permission}"
                    ),
                    severity=sev,
                )
            )
        return findings
