"""
Custom exceptions for netlint.
"""

from __future__ import annotations


class NetlintError(Exception):
    """Base class for all netlint errors."""


class ParseError(NetlintError):
    """Raised when a configuration file cannot be parsed."""

    def __init__(self, message: str, line_number: int | None = None) -> None:
        self.line_number = line_number
        location = f" (line {line_number})" if line_number is not None else ""
        super().__init__(f"Parse error{location}: {message}")


class UnsupportedVendorError(NetlintError):
    """Raised when no parser or rules are available for a vendor."""

    def __init__(self, vendor: str, supported: list[str]) -> None:
        supported_str = ", ".join(supported) if supported else "(none registered yet)"
        super().__init__(
            f"Unsupported vendor '{vendor}'. Supported vendors: {supported_str}"
        )
