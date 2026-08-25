"""
Centralized Configuration Extension and Format Registry for NetLint.

Maps file extensions to format metadata, parser strategies, and likely vendors
without coupling extension detection to vendor identification.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExtensionMetadata:
    """
    Metadata associated with a configuration file extension.

    Attributes:
        extension: Canonical lowercase extension including leading dot (e.g. ``".yaml"``).
        likely_format: Format family (e.g. ``"cli"``, ``"yaml"``, ``"json"``, ``"xml"``, ``"mikrotik_rsc"``).
        likely_vendors: Tuple of vendor identifiers commonly associated with this extension.
        parser_strategy: Internal strategy name (e.g. ``"text_cli"``, ``"yaml"``, ``"json"``, ``"xml"``, ``"rsc"``).
        is_structured: True if the format uses structured data syntax (JSON/YAML/XML).
        parser_status: Human-readable status of parser implementation.
    """

    extension: str
    likely_format: str
    likely_vendors: tuple[str, ...]
    parser_strategy: str
    is_structured: bool
    parser_status: str


class ExtensionRegistry:
    """Central registry mapping configuration file extensions to ExtensionMetadata."""

    _registry: dict[str, ExtensionMetadata] = {}

    @classmethod
    def register(cls, meta: ExtensionMetadata) -> None:
        """Register or override extension metadata."""
        ext_clean = meta.extension.lower().strip()
        if not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"
        cls._registry[ext_clean] = meta

    @classmethod
    def get(cls, extension_or_path: str | Path) -> ExtensionMetadata | None:
        """
        Look up metadata for a file extension or path.

        Returns None if the extension is not registered.
        """
        if isinstance(extension_or_path, Path):
            ext = extension_or_path.suffix.lower()
        else:
            s = str(extension_or_path).lower().strip()
            if s.startswith("."):
                ext = s
            else:
                ext = Path(s).suffix.lower() if "." in s else f".{s}"

        return cls._registry.get(ext)

    @classmethod
    def lookup(cls, extension_or_path: str | Path) -> ExtensionMetadata:
        """
        Look up metadata for a file extension or path.

        Returns a default fallback ExtensionMetadata for unknown extensions or files without extension.
        """
        found = cls.get(extension_or_path)
        if found is not None:
            return found

        # Fallback for unknown / no extension files
        if isinstance(extension_or_path, Path):
            ext = extension_or_path.suffix.lower()
        else:
            s = str(extension_or_path).lower().strip()
            if s.startswith("."):
                ext = s
            else:
                ext = Path(s).suffix.lower() if "." in s else ""

        return ExtensionMetadata(
            extension=ext,
            likely_format="cli",
            likely_vendors=(),
            parser_strategy="text_cli",
            is_structured=False,
            parser_status="Unknown (Generic text fallback)",
        )

    @classmethod
    def all_supported_extensions(cls) -> tuple[str, ...]:
        """Return a sorted tuple of all registered lowercase file extensions."""
        return tuple(sorted(cls._registry.keys()))

    @classmethod
    def is_recognized(cls, extension_or_path: str | Path) -> bool:
        """Return True if the extension is explicitly registered."""
        return cls.get(extension_or_path) is not None

    @classmethod
    def all_entries(cls) -> tuple[ExtensionMetadata, ...]:
        """Return all registered ExtensionMetadata objects sorted by extension."""
        return tuple(sorted(cls._registry.values(), key=lambda m: m.extension))


# ---------------------------------------------------------------------------
# Default Registry Initialization
# ---------------------------------------------------------------------------

_INITIAL_EXTENSIONS = (
    # Text / CLI Formats
    ExtensionMetadata(".cfg", "cli", ("cisco-ios", "arista", "vyos"), "text_cli", False, "Fully supported (Cisco IOS)"),
    ExtensionMetadata(".conf", "cli", ("juniper", "arista", "frr"), "text_cli", False, "Fully supported (Cisco/Partial Juniper)"),
    ExtensionMetadata(".config", "cli", (), "text_cli", False, "Fully supported (Cisco) / Text fallback"),
    ExtensionMetadata(".txt", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".ios", "cli", ("cisco-ios",), "text_cli", False, "Fully supported"),
    ExtensionMetadata(".set", "cli", ("juniper",), "text_cli", False, "Partial (JunOS set commands)"),
    ExtensionMetadata(".log", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".cli", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".backup", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".bak", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".running", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".startup", "cli", (), "text_cli", False, "Text CLI fallback"),
    ExtensionMetadata(".junos", "cli", ("juniper",), "text_cli", False, "Partial (JunOS parser)"),
    ExtensionMetadata(".nxos", "cli", ("cisco-nxos",), "text_cli", False, "Recognized (Text fallback active)"),
    ExtensionMetadata(".eos", "cli", ("arista-eos",), "text_cli", False, "Partial (Arista parser)"),
    ExtensionMetadata(".vyos", "cli", ("vyos",), "text_cli", False, "Recognized (Text fallback active)"),
    ExtensionMetadata(".rsc", "mikrotik_rsc", ("mikrotik",), "rsc", False, "Recognized (Text fallback active)"),
    # Structured Formats
    ExtensionMetadata(".yaml", "yaml", ("vyos", "ansible"), "yaml", True, "Recognized (Structured syntax check active)"),
    ExtensionMetadata(".yml", "yaml", ("vyos", "ansible"), "yaml", True, "Recognized (Structured syntax check active)"),
    ExtensionMetadata(".json", "json", (), "json", True, "Recognized (Structured syntax check active)"),
    ExtensionMetadata(".xml", "xml", ("juniper",), "xml", True, "Recognized (Structured syntax check active)"),
)

for _meta in _INITIAL_EXTENSIONS:
    ExtensionRegistry.register(_meta)
