"""
Tests for the parser, rule, and formatter registries.
"""

import pytest

from netlint.parser.registry import ParserRegistry
from netlint.rules.registry import RuleRegistry
from netlint.output.registry import FormatterRegistry


def test_parser_registry_unknown_vendor_raises() -> None:
    """Requesting an unregistered vendor should raise KeyError."""
    with pytest.raises(KeyError, match="no-such-vendor"):
        ParserRegistry.get("no-such-vendor")


def test_parser_registry_supported_vendors_returns_list() -> None:
    """supported_vendors() should return a list (may be empty at init)."""
    vendors = ParserRegistry.supported_vendors()
    assert isinstance(vendors, list)


def test_rule_registry_all_rules_returns_list() -> None:
    """all_rules() should return a list (may be empty at init)."""
    rules = RuleRegistry.all_rules()
    assert isinstance(rules, list)


def test_rule_registry_get_for_vendor_returns_list() -> None:
    """get_for_vendor() should return a list even for unknown vendors."""
    rules = RuleRegistry.get_for_vendor("cisco-ios")
    assert isinstance(rules, list)


def test_formatter_registry_unknown_format_raises() -> None:
    """Requesting an unregistered format should raise KeyError."""
    with pytest.raises(KeyError, match="no-such-format"):
        FormatterRegistry.get("no-such-format")


def test_formatter_registry_supported_formats_returns_list() -> None:
    """supported_formats() should return a list (may be empty at init)."""
    formats = FormatterRegistry.supported_formats()
    assert isinstance(formats, list)
