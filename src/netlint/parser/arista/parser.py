"""
Arista EOS configuration parser.

Parses Arista EOS device configurations into the Common IR (ParsedConfig).
"""

from __future__ import annotations

from typing import Any

from netlint.models.config_file import ConfigFile
from netlint.parser.base import BaseParser
from netlint.parser.cisco_ios.parser import CiscoIosParser
from netlint.parser.registry import ParserRegistry


class AristaEosParser(BaseParser):
    """Parser for Arista EOS device configurations."""

    vendor = "arista"

    def parse(self, config: ConfigFile) -> Any:
        """
        Parse Arista EOS configuration into standard ParsedConfig Common IR.
        """
        # Arista EOS uses IOS-style syntax hierarchy for interfaces, VLANs,
        # ACLs, and routing statements. CiscoIosParser parses these commands
        # into the Common IR (ParsedConfig).
        ios_parser = CiscoIosParser()
        parsed = ios_parser.parse(config)

        # Arista EOS specific defaults / adjustments
        # e.g., Arista EOS enables service password-encryption by default or via secret
        for line in config.lines:
            stripped = line.strip().lower()
            if "service password-encryption" in stripped:
                parsed.service_password_encryption = True
            elif "management api http-commands" in stripped:
                parsed.http_server_enabled = True

        return parsed


ParserRegistry.register("arista", AristaEosParser)
ParserRegistry.register("arista-eos", AristaEosParser)
