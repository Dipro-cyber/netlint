"""
BaseFormatter — abstract interface every output formatter must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from netlint.models.result import AnalysisResult


class BaseFormatter(ABC):
    """
    Abstract base class for output formatters.

    A formatter takes an :class:`~netlint.models.result.AnalysisResult`
    and returns a rendered string.  The CLI is responsible for writing
    that string to stdout or a file.

    Subclasses may accept additional keyword arguments in their
    ``render`` implementations (e.g. ``no_color=True``).  The base
    signature accepts ``**kwargs`` so that subclasses remain
    substitutable without violating the Liskov Substitution Principle.
    """

    #: Short identifier used to select this formatter via --format.
    format_id: str

    @abstractmethod
    def render(self, result: AnalysisResult, **kwargs: Any) -> str:
        """
        Render *result* to a string in this formatter's format.

        :param result: The analysis result to format.
        :returns:      The formatted string, ready for print/write.
        """
        ...
