"""
ParserRegistry — maps vendor identifiers to parser classes.

Parsers self-register by calling :meth:`ParserRegistry.register`.
The analyzer looks up the right parser via :meth:`ParserRegistry.get`.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netlint.parser.base import BaseParser


class ParserRegistry:
    """Central registry for vendor parsers."""

    _parsers: dict[str, type[BaseParser]] = {}
    _discovered: bool = False

    @classmethod
    def register(cls, vendor: str, parser_cls: type[BaseParser]) -> None:
        """Register *parser_cls* for the given *vendor* identifier."""
        cls._parsers[vendor] = parser_cls

    @classmethod
    def get(cls, vendor: str) -> type[BaseParser]:
        """
        Return the parser class for *vendor*.

        Raises :class:`KeyError` when no parser is registered for that vendor.
        """
        if vendor not in cls._parsers:
            supported = ", ".join(sorted(cls._parsers)) or "(none registered yet)"
            raise KeyError(
                f"No parser registered for vendor '{vendor}'. "
                f"Supported vendors: {supported}"
            )
        return cls._parsers[vendor]

    @classmethod
    def supported_vendors(cls) -> list[str]:
        """Return a sorted list of all registered vendor identifiers."""
        return sorted(cls._parsers)

    @classmethod
    def autodiscover(cls) -> None:
        """
        Import every subpackage under ``netlint.parser`` so that
        vendor parsers self-register via ``ParserRegistry.register()``.

        Safe to call multiple times — discovery runs only once per process.
        """
        if cls._discovered:
            return
        cls._discovered = True

        import netlint.parser as parsers_pkg

        for module_info in pkgutil.walk_packages(
            path=parsers_pkg.__path__,
            prefix=parsers_pkg.__name__ + ".",
            onerror=lambda _name: None,
        ):
            if not module_info.ispkg:
                try:
                    importlib.import_module(module_info.name)
                except Exception:  # noqa: BLE001
                    pass
