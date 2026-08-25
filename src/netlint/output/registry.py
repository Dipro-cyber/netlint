"""
FormatterRegistry — maps format identifiers to formatter classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netlint.output.base import BaseFormatter


class FormatterRegistry:
    """Central registry for output formatters."""

    _formatters: dict[str, type[BaseFormatter]] = {}

    @classmethod
    def register(cls, formatter_cls: type[BaseFormatter]) -> type[BaseFormatter]:
        """
        Register a formatter class by its ``format_id``.

        Can be used as a class decorator::

            @FormatterRegistry.register
            class JsonFormatter(BaseFormatter):
                format_id = "json"
                ...
        """
        cls._formatters[formatter_cls.format_id] = formatter_cls
        return formatter_cls

    @classmethod
    def get(cls, format_id: str) -> type[BaseFormatter]:
        """
        Return the formatter class for *format_id*.

        Raises :class:`KeyError` when no formatter is registered for that id.
        """
        if format_id not in cls._formatters:
            supported = ", ".join(sorted(cls._formatters)) or "(none registered yet)"
            raise KeyError(
                f"No formatter registered for format '{format_id}'. "
                f"Supported formats: {supported}"
            )
        return cls._formatters[format_id]

    @classmethod
    def supported_formats(cls) -> list[str]:
        """Return a sorted list of all registered format identifiers."""
        return sorted(cls._formatters)
