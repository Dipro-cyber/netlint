"""
Analyzer subpackage — orchestrates parsing and rule execution.

The Analyzer is the main entry point for programmatic use of netlint.
It accepts a path (or ConfigFile), selects the right parser and rules,
runs them, and returns a LintResult.
"""

from netlint.analyzer.analyzer import Analyzer

__all__ = ["Analyzer"]
