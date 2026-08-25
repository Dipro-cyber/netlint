"""
Diff subpackage — semantic configuration diffing and new-risk detection.

Public surface
--------------
ConfigDiff      — structured result of comparing two ParsedConfig objects
ConfigDiffer    — computes a ConfigDiff from two ParsedConfig objects
DiffRiskResult  — risk comparison between old and new AnalysisResults
compare_results — produce a DiffRiskResult from two AnalysisResults
"""

from netlint.diff.differ import ConfigDiffer
from netlint.diff.models import (
    AclChange,
    ChangeType,
    ConfigDiff,
    FieldDelta,
    HostnameChange,
    HttpServerChange,
    InterfaceChange,
    RouteChange,
    VlanChange,
    VtyChange,
)
from netlint.diff.risk import DiffRiskResult, compare_results

__all__ = [
    "AclChange",
    "ChangeType",
    "ConfigDiff",
    "ConfigDiffer",
    "DiffRiskResult",
    "FieldDelta",
    "HostnameChange",
    "HttpServerChange",
    "InterfaceChange",
    "RouteChange",
    "VlanChange",
    "VtyChange",
    "compare_results",
]
