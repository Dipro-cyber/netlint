"""
Parser subpackage — vendor-specific configuration file parsers.

Each vendor gets its own module. Parsers take raw text and produce
a structured representation the rules can query efficiently.

Currently planned:
- cisco_ios.py  — Cisco IOS / IOS-XE configuration parser
"""

from netlint.parser.base import BaseParser
from netlint.parser.registry import ParserRegistry

__all__ = ["BaseParser", "ParserRegistry"]
