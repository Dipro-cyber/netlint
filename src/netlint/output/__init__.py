"""
Output subpackage — formats and renders AnalysisResult objects.

Formatters:
- terminal.py  — Rich terminal output (default, format_id="text")

All formatters implement BaseFormatter and auto-register with
FormatterRegistry via @FormatterRegistry.register.

Import this package to trigger formatter registration:
    import netlint.output  # noqa: F401
"""

from netlint.output.base import BaseFormatter
from netlint.output.registry import FormatterRegistry

# Trigger formatter registration
import netlint.output.terminal  # noqa: F401

__all__ = ["BaseFormatter", "FormatterRegistry"]
