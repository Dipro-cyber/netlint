"""
Analyzer — orchestrates parsing and rule execution for a single config file.

Flow
----
1. Load the configuration file into a ConfigFile.
2. Parse it with the registered vendor parser; attach the structured
   ParsedConfig to ``config.parsed``.
3. Auto-discover and load rule modules so all ``@RuleRegistry.register``
   decorators have run.
4. Fetch every rule that applies to the current vendor.
5. Run each rule's ``check(config, parsed)`` and collect Findings.
6. Sort findings: CRITICAL first, then by line number.
7. Return an AnalysisResult.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netlint.exceptions import ParseError
from netlint.models.config_file import ConfigFile
from netlint.models.finding import Finding
from netlint.models.result import AnalysisResult
from netlint.parser.registry import ParserRegistry
from netlint.rules.registry import RuleRegistry


class Analyzer:
    """
    Runs all applicable lint rules against a network device configuration.

    Usage::

        result = Analyzer().run(Path("router.cfg"), vendor="cisco-ios")
        for finding in result.findings:
            print(finding.severity.value.upper(), finding.message)
    """

    def run(self, path: Path | str, vendor: str = "cisco-ios") -> AnalysisResult:
        """
        Load *path*, parse it, run all rules, and return the result.

        :param path:   Path to the configuration file.
        :param vendor: Vendor identifier (default: ``"cisco-ios"``).
        :raises FileNotFoundError: If *path* does not exist.
        :raises ParseError: If the file cannot be parsed.
        """
        config = ConfigFile.from_path(path, vendor=vendor)
        return self._analyze(config)

    def run_batch(self, paths: list[Path | str], vendor: str = "cisco-ios") -> list[AnalysisResult]:
        """
        Run analysis on a list of configuration file paths.
        """
        results: list[AnalysisResult] = []
        for p in paths:
            results.append(self.run(p, vendor=vendor))
        return results

    def run_path(self, path_or_pattern: Path | str, vendor: str = "cisco-ios") -> list[AnalysisResult]:
        """
        Resolve *path_or_pattern* (file, directory, or glob pattern) and analyze
        all matching configuration files.
        """
        from netlint.utils import resolve_config_files
        files = resolve_config_files(path_or_pattern)
        return self.run_batch(files, vendor=vendor)

    def run_config(self, config: ConfigFile) -> AnalysisResult:
        """
        Run analysis on an already-loaded :class:`ConfigFile`.

        Useful when the caller has already constructed the ConfigFile
        (e.g. in tests or when reading from stdin).
        """
        return self._analyze(config)

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _analyze(self, config: ConfigFile) -> AnalysisResult:
        ParserRegistry.autodiscover()
        parsed, parser_warnings = self._parse(config)

        # Attach parsed data to config so rules can access it via
        # config.parsed as a convenience (in addition to the direct arg).
        object.__setattr__(config, "parsed", parsed)

        RuleRegistry.autodiscover()
        findings = self._run_rules(config, parsed)
        findings.sort(key=lambda f: f.sort_key())

        return AnalysisResult(
            file_path=config.file_path,
            findings=tuple(findings),
            vendor=config.vendor,
            parser_warnings=tuple(parser_warnings),
        )

    def _parse(self, config: ConfigFile) -> tuple[Any, list[str]]:
        """
        Invoke the vendor parser and return (parsed_data, warnings).

        Returns ``(None, [])`` when no parser is registered — rules that
        need parsed data should handle ``parsed is None`` gracefully.
        """
        try:
            parser_cls = ParserRegistry.get(config.vendor)
        except KeyError:
            return None, []

        try:
            parser = parser_cls()
            result = parser.parse(config)
            warnings: list[str] = getattr(result, "warnings", [])
            return result, warnings
        except ParseError:
            raise
        except Exception as exc:  # noqa: BLE001
            return None, [f"Parser error: {exc}"]

    def _run_rules(
        self,
        config: ConfigFile,
        parsed: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule_cls in RuleRegistry.get_for_vendor(config.vendor):
            rule = rule_cls()
            try:
                results = rule.check(config, parsed)
                findings.extend(results)
            except Exception as exc:  # noqa: BLE001
                # A buggy rule must never abort the whole analysis.
                import warnings as _w
                _w.warn(
                    f"netlint: rule {rule_cls.__name__} raised an unexpected "
                    f"exception and was skipped: {exc}",
                    stacklevel=2,
                )
        return findings
