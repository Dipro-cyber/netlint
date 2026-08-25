"""
SEC-002 — HTTP management server enabled.

Cisco IOS supports an embedded HTTP server (``ip http server``) for
web-based device management.  Plain HTTP transmits all management
traffic — including session cookies and credentials — in cleartext.
An attacker with access to the management network can passively capture
credentials or hijack sessions via a man-in-the-middle attack.

Relevant IOS commands
----------------------
    ip http server          — enables plain HTTP on TCP/80 (insecure)
    no ip http server       — disables plain HTTP
    ip http secure-server   — enables HTTPS on TCP/443 (safe)

This rule fires when ``ip http server`` is present in the configuration
and is not immediately followed by ``no ip http server``.
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
class HttpServerEnabledRule(Rule):
    """Flag configurations where the plaintext HTTP management server is active."""

    rule_id = "SEC002"
    title = "HTTP management server enabled"
    description = (
        "The device has 'ip http server' enabled, which exposes the "
        "web-based management interface over unencrypted HTTP (TCP/80). "
        "Credentials and session data are transmitted in cleartext."
    )
    category = RuleCategory.SECURITY
    severity = Severity.HIGH
    recommendation = (
        "Disable the plain HTTP server with 'no ip http server'. "
        "If web-based management is required, enable HTTPS instead with "
        "'ip http secure-server' and restrict access with "
        "'ip http access-class <ACL>'."
    )
    vendors = ("cisco-ios",)

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None:
            return []

        if not parsed.http_server_enabled:
            return []

        return [
            self.finding(
                config=config,
                message=(
                    "Plain HTTP management server is enabled "
                    "('ip http server'). "
                    "Management traffic is transmitted in cleartext."
                ),
                line_number=parsed.http_server_line,
                configuration_line="ip http server",
            )
        ]
