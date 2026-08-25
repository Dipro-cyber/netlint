"""
Cisco IOS / IOS-XE configuration parser.

Public surface:
    CiscoIosParser  — implements BaseParser, registered as "cisco-ios"
    ParsedConfig    — structured result of a parse run
"""

from netlint.parser.cisco_ios.models import (
    AclEntry,
    AclRule,
    Interface,
    ParsedConfig,
    Route,
    StaticRoute,
    Vlan,
    VtyLine,
)
from netlint.parser.cisco_ios.parser import CiscoIosParser

__all__ = [
    "AclEntry",
    "AclRule",
    "CiscoIosParser",
    "Interface",
    "ParsedConfig",
    "Route",
    "StaticRoute",
    "Vlan",
    "VtyLine",
]
