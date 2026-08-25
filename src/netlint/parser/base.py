"""
BaseParser — abstract interface every vendor parser must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from netlint.models.config_file import ConfigFile


class BaseParser(ABC):
    """
    Abstract base class for all vendor-specific configuration parsers.

    A parser's job is to take a :class:`ConfigFile` (raw text + metadata)
    and produce a vendor-specific structured representation (e.g.
    :class:`~netlint.parser.cisco_ios.models.ParsedConfig`) that rules
    can query efficiently.  Parsers do NOT run rules themselves.
    """

    #: Vendor identifier this parser handles, e.g. "cisco-ios".
    vendor: str

    @abstractmethod
    def parse(self, config: ConfigFile) -> Any:
        """
        Parse *config* and return the vendor-specific structured data.

        The return type is ``Any`` at this level because each vendor
        produces a different concrete parsed-config type.  The Analyzer
        stores whatever is returned as ``config.parsed``.

        Implementations should raise :class:`netlint.exceptions.ParseError`
        on malformed input rather than silently swallowing errors.
        """
        ...
