"""
netlint domain models.

Public surface
--------------
Finding           — a single problem found by a rule
Severity          — CRITICAL / HIGH / MEDIUM / LOW / INFO
RuleCategory      — SECURITY / NETWORK / VLAN / ROUTING / INTERFACE / ACL / MANAGEMENT
Rule              — abstract base class every lint rule must subclass
AnalysisResult    — aggregated output of one analysis run
ConfigFile        — a loaded configuration file (raw text + metadata)

Backwards-compatible aliases
-----------------------------
LintIssue  → Finding
LintResult → AnalysisResult
"""

from netlint.models.config_file import ConfigFile
from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult
from netlint.models.rule import Rule

# Backwards-compatible aliases so old test code keeps working
LintIssue = Finding
LintResult = AnalysisResult
IssueSeverity = Severity

__all__ = [
    "AnalysisResult",
    "ConfigFile",
    "Finding",
    "IssueSeverity",
    "LintIssue",
    "LintResult",
    "Rule",
    "RuleCategory",
    "Severity",
]
