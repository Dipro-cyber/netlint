"""
Rule base class — the contract every lint rule must implement.

Rules are pure functions wrapped in a class so they can carry metadata
and be discovered/registered automatically.  A rule module registers
itself by applying ``@RuleRegistry.register`` to its class — the
analyzer never needs a hard-coded list.

Example
-------
::

    from netlint.models.rule import Rule
    from netlint.models.finding import Finding, RuleCategory, Severity
    from netlint.rules.registry import RuleRegistry

    @RuleRegistry.register
    class NoTelnetRule(Rule):
        rule_id    = "SEC001"
        title      = "Telnet enabled on VTY lines"
        description = "Telnet transmits credentials in plaintext."
        category   = RuleCategory.SECURITY
        severity   = Severity.CRITICAL
        recommendation = "Replace 'transport input telnet' with 'transport input ssh'."
        vendors    = ("cisco-ios",)

        def check(self, config, parsed):
            findings = []
            for vty in parsed.vty_lines:
                if TransportProtocol.TELNET in vty.transport_input:
                    findings.append(self.finding(
                        config=config,
                        message=f"VTY {vty.first}-{vty.last} allows Telnet.",
                        line_number=vty.line_number,
                        configuration_line=f"line vty {vty.first} {vty.last}",
                    ))
            return findings
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from netlint.models.finding import Finding, RuleCategory, Severity

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.parser.cisco_ios.models import ParsedConfig


class Rule(ABC):
    """
    Abstract base for all netlint rules.

    Class-level attributes
    ----------------------
    rule_id        Unique identifier, e.g. ``"SEC001"``.
    title          Short name shown in reports.
    description    Full description of what the rule checks.
    category       :class:`~netlint.models.finding.RuleCategory` value.
    severity       Default :class:`~netlint.models.finding.Severity`.
    recommendation Remediation text included in every finding.
    vendors        Tuple of vendor strings this rule applies to.

    Subclasses must set all class attributes **and** implement
    :meth:`check`.
    """

    # --- Required class attributes -----------------------------------------
    rule_id: str
    title: str
    description: str
    category: RuleCategory
    severity: Severity
    recommendation: str
    vendors: tuple[str, ...] = ("cisco-ios",)

    # -----------------------------------------------------------------------

    @abstractmethod
    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        """
        Analyse *config* / *parsed* and return any findings.

        Parameters
        ----------
        config:
            The raw :class:`~netlint.models.config_file.ConfigFile`.
            Provides ``file_path``, ``raw_text``, and ``lines``.
        parsed:
            Vendor-specific structured data produced by the parser,
            e.g. :class:`~netlint.parser.cisco_ios.models.ParsedConfig`.
            May be ``None`` if no parser is registered for the vendor.

        Returns
        -------
        list[Finding]
            Empty list when the config passes the check.
        """
        ...

    # -----------------------------------------------------------------------
    # Helper — build a Finding pre-populated with this rule's metadata
    # -----------------------------------------------------------------------

    def finding(
        self,
        *,
        config: ConfigFile,
        message: str,
        line_number: int | None = None,
        configuration_line: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """
        Convenience factory that creates a :class:`Finding` using this
        rule's metadata.  Callers only need to supply the instance-specific
        *message* and optional line-location fields.
        """
        return Finding(
            rule_id=self.rule_id,
            severity=severity if severity is not None else self.severity,
            category=self.category,
            title=self.title,
            message=message,
            recommendation=self.recommendation,
            file=Path(config.file_path),
            line_number=line_number,
            configuration_line=configuration_line,
        )
