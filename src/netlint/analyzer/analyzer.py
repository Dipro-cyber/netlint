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

    def run(self, path: Path | str, vendor: str = "auto") -> AnalysisResult:
        """
        Load *path*, parse it, run all rules, and return the result.

        :param path:   Path to the configuration file.
        :param vendor: Vendor identifier (default: ``"auto"`` for auto-detection).
        :raises FileNotFoundError: If *path* does not exist.
        :raises ParseError: If the file cannot be parsed.
        """
        config = ConfigFile.from_path(path, vendor=vendor)
        return self._analyze(config)

    def run_batch(self, paths: list[Path | str], vendor: str = "auto") -> list[AnalysisResult]:
        """
        Run analysis on a list of configuration file paths.
        """
        results: list[AnalysisResult] = []
        for p in paths:
            results.append(self.run(p, vendor=vendor))
        return results

    def run_path(self, path_or_pattern: Path | str, vendor: str = "auto") -> list[AnalysisResult]:
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
        Handles extension validation and parser warnings for unmapped/structured formats.
        """
        from netlint.registry.extension_registry import ExtensionRegistry
        meta = ExtensionRegistry.lookup(config.file_path)
        warnings: list[str] = []

        # Validate structured files syntax if content exists
        if meta.is_structured and config.raw_text.strip():
            struct_err = self._validate_structured_syntax(config, meta)
            if struct_err:
                # If misleading extension (e.g. Cisco CLI saved as router.json)
                if config.vendor in ParserRegistry.supported_vendors():
                    warnings.append(
                        f"Extension '{meta.extension}' expects structured format '{meta.likely_format}', "
                        f"but content matches '{config.vendor}' CLI syntax. Performing CLI text fallback analysis."
                    )
                else:
                    raise ParseError(struct_err)
            else:
                warnings.append(
                    f"Format '{meta.likely_format}' (extension '{meta.extension}') is recognized, "
                    f"but vendor-specific structured schema mapping to Common IR is not yet implemented for vendor '{config.vendor}'."
                )
        elif meta.likely_vendors and config.vendor not in ParserRegistry.supported_vendors():
            warnings.append(
                f"Vendor '{config.vendor}' (extension '{meta.extension}') is recognized, "
                f"but full parser for '{config.vendor}' is not yet implemented. Performing text fallback analysis."
            )

        try:
            parser_cls = ParserRegistry.get(config.vendor)
        except KeyError:
            if not warnings:
                warnings.append(
                    f"No parser registered for vendor '{config.vendor}' (extension '{meta.extension}'). "
                    f"Performing generic text analysis."
                )
            return None, warnings

        try:
            parser = parser_cls()
            result = parser.parse(config)
            p_warnings: list[str] = getattr(result, "warnings", [])
            warnings.extend(p_warnings)
            return result, warnings
        except ParseError:
            raise
        except Exception as exc:  # noqa: BLE001
            return None, warnings + [f"Parser error: {exc}"]

    def _validate_structured_syntax(self, config: ConfigFile, meta: Any) -> str | None:
        """Validate JSON, YAML, or XML syntax. Returns error message if invalid, None if valid."""
        raw = config.raw_text
        if meta.likely_format == "json":
            import json
            try:
                json.loads(raw)
                return None
            except Exception as exc:
                return f"Invalid JSON syntax in {config.file_path.name}: {exc}"
        elif meta.likely_format == "yaml":
            import re
            for line_no, line in enumerate(raw.splitlines(), 1):
                if re.match(r"^\t+[^\s]", line):
                    return f"Invalid YAML syntax in {config.file_path.name} at line {line_no}: tabs not allowed for indentation"
            return None
        elif meta.likely_format == "xml":
            import xml.etree.ElementTree as ET
            try:
                ET.fromstring(raw)
                return None
            except Exception as exc:
                return f"Invalid XML syntax in {config.file_path.name}: {exc}"
        return None

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
