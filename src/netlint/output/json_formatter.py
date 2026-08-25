"""
JSON formatter — machine-readable output for CI/CD pipelines.

``netlint analyze router.cfg --format json`` emits a single JSON object
to stdout and nothing else.  All diagnostic messages are written to
stderr so they do not contaminate the JSON stream.

analyze schema
--------------
{
  "netlint_version": "0.1.0",
  "command":         "analyze",
  "file":            "/abs/path/to/router.cfg",
  "hostname":        "CORE-RTR-01",          // from parsed config, null if unknown
  "vendor":          "cisco-ios",
  "risk_score":      68,
  "risk_level":      "HIGH",
  "summary": {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      1,
    "info":     0
  },
  "findings": [
    {
      "rule_id":            "NET001",
      "severity":           "critical",
      "category":           "network",
      "title":              "Duplicate IPv4 address",
      "message":            "IP 10.0.0.1 is assigned to Gi0/0 and also to: Gi0/1.",
      "recommendation":     "Assign a unique IPv4 address to every interface.",
      "line_number":        42,
      "configuration_line": " ip address 10.0.0.1 255.255.255.0"
    }
  ],
  "parser_warnings": []
}

diff schema
-----------
{
  "netlint_version": "0.1.0",
  "command":         "diff",
  "old_file":        "/abs/path/to/production.cfg",
  "new_file":        "/abs/path/to/proposed.cfg",
  "vendor":          "cisco-ios",
  "deployment_recommendation": "DO NOT DEPLOY",
  "summary": {
    "new_risks":        2,
    "resolved":         0,
    "persisting":       1,
    "new_critical":     0,
    "new_high":         2
  },
  "new_findings":       [ ... ],
  "resolved_findings":  [ ... ],
  "persisting_findings":[ ... ]
}

error schema  (written to stderr as JSON when --format json is active)
------------
{
  "netlint_version": "0.1.0",
  "command":  "analyze",
  "error":    "File not found: router.cfg"
}
"""

from __future__ import annotations

import json
from typing import Any

from netlint import __version__
from netlint.models.finding import Finding
from netlint.models.result import AnalysisResult


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialise one Finding to a plain dict."""
    return {
        "rule_id":            f.rule_id,
        "severity":           f.severity.value,
        "category":           f.category.value,
        "title":              f.title,
        "message":            f.message,
        "recommendation":     f.recommendation,
        "line_number":        f.line_number,
        "configuration_line": f.configuration_line,
    }


def _summary_dict(result: AnalysisResult) -> dict[str, int]:
    return {
        "total":    len(result.findings),
        "critical": result.critical_count,
        "high":     result.high_count,
        "medium":   result.medium_count,
        "low":      result.low_count,
        "info":     result.info_count,
    }


def _hostname_from_result(result: AnalysisResult) -> str | None:
    """
    Extract hostname from the ParsedConfig attached to the ConfigFile.

    The Analyzer stores the ParsedConfig on the ConfigFile via
    ``object.__setattr__(config, 'parsed', parsed)``.  The result
    object itself does not carry a reference to the config, so we
    cannot reach it directly.  We store hostname on the result via
    the parser_warnings list — instead we accept an optional
    pre-extracted value.
    """
    return None  # Caller should pass hostname explicitly when available


# ---------------------------------------------------------------------------
# analyze JSON
# ---------------------------------------------------------------------------


def render_analyze_json(
    result: AnalysisResult,
    *,
    hostname: str | None = None,
    indent: int = 2,
) -> str:
    """
    Serialise an :class:`AnalysisResult` to a JSON string.

    Parameters
    ----------
    result:
        The analysis result.
    hostname:
        Device hostname extracted from the parsed config (may be None).
    indent:
        JSON indentation width (default 2).
    """
    from netlint.analyzer.scoring import score_result

    rs = score_result(result)

    doc: dict[str, Any] = {
        "netlint_version":  __version__,
        "command":          "analyze",
        "file":             str(result.file_path),
        "hostname":         hostname,
        "vendor":           result.vendor,
        "risk_score":       rs.score,
        "risk_level":       rs.level,
        "summary":          _summary_dict(result),
        "findings":         [_finding_to_dict(f) for f in result.findings],
        "parser_warnings":  list(result.parser_warnings),
    }
    return json.dumps(doc, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# diff JSON
# ---------------------------------------------------------------------------


def render_diff_json(
    diff_risk: Any,        # DiffRiskResult — imported lazily to avoid circular deps
    *,
    old_hostname: str | None = None,
    new_hostname: str | None = None,
    vendor: str = "cisco-ios",
    indent: int = 2,
) -> str:
    """
    Serialise a :class:`~netlint.diff.risk.DiffRiskResult` to a JSON string.
    """
    doc: dict[str, Any] = {
        "netlint_version":            __version__,
        "command":                    "diff",
        "old_file":                   str(diff_risk.old_result.file_path),
        "new_file":                   str(diff_risk.new_result.file_path),
        "old_hostname":               old_hostname,
        "new_hostname":               new_hostname,
        "vendor":                     vendor,
        "deployment_recommendation":  diff_risk.deployment_recommendation,
        "summary": {
            "new_risks":    len(diff_risk.new_findings),
            "resolved":     len(diff_risk.resolved_findings),
            "persisting":   len(diff_risk.persisting_findings),
            "new_critical": diff_risk.new_critical_count,
            "new_high":     diff_risk.new_high_count,
        },
        "new_findings":        [_finding_to_dict(f) for f in diff_risk.new_findings],
        "resolved_findings":   [_finding_to_dict(f) for f in diff_risk.resolved_findings],
        "persisting_findings": [_finding_to_dict(f) for f in diff_risk.persisting_findings],
    }
    return json.dumps(doc, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# error JSON  (written to stderr)
# ---------------------------------------------------------------------------


def render_error_json(command: str, error: str, indent: int = 2) -> str:
    """Serialise an error response for stderr."""
    doc: dict[str, Any] = {
        "netlint_version": __version__,
        "command":         command,
        "error":           error,
    }
    return json.dumps(doc, indent=indent, ensure_ascii=False)
