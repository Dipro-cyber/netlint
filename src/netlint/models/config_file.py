"""
ConfigFile model — represents a loaded network device configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, model_validator


class ConfigFile(BaseModel):
    """
    A loaded, minimally-processed network device configuration file.

    The raw text is always preserved so that parsers and rules can
    work from the original source without information loss.

    ``parsed`` is set by the Analyzer after the vendor parser runs.
    It holds the vendor-specific structured data (e.g. a
    :class:`~netlint.parser.cisco_ios.models.ParsedConfig`).
    Because the model is frozen, the Analyzer uses
    ``object.__setattr__`` to attach it — the same pattern used by
    ``_derive_lines``.
    """

    file_path: Path
    """Absolute path to the file on disk."""

    raw_text: str
    """Raw file contents exactly as read from disk."""

    vendor: str
    """Detected or declared vendor identifier, e.g. 'cisco-ios'."""

    lines: tuple[str, ...]
    """Lines split from raw_text (read-only view)."""

    parsed: Any = None
    """
    Vendor-specific parsed data attached by the Analyzer after parsing.
    Typed as ``Any`` to keep the core model free of vendor dependencies.
    Rules cast this to the concrete type they expect.
    """

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _derive_lines(self) -> ConfigFile:
        """Auto-populate lines from raw_text when lines was left empty."""
        if not self.lines and self.raw_text:
            object.__setattr__(self, "lines", tuple(self.raw_text.splitlines()))
        return self

    @classmethod
    def from_path(cls, path: Path | str, vendor: str = "auto") -> ConfigFile:
        """Load a ConfigFile from a file path with automatic vendor detection."""
        resolved = Path(path).resolve()
        raw_text = resolved.read_text(encoding="utf-8")
        if vendor == "auto" or not vendor:
            from netlint.parser.detector import detect_vendor
            vendor = detect_vendor(raw_text)
        return cls(file_path=resolved, raw_text=raw_text, vendor=vendor, lines=())
