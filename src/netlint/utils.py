"""
Utility functions for file discovery and path handling in NetLint.
"""

from __future__ import annotations

import glob
from pathlib import Path

from netlint.registry.extension_registry import ExtensionRegistry


def get_supported_extensions() -> tuple[str, ...]:
    """Return a sorted tuple of all registered lowercase file extensions."""
    return ExtensionRegistry.all_supported_extensions()


# Kept for backward compatibility
SUPPORTED_CONFIG_EXTENSIONS: tuple[str, ...] = ExtensionRegistry.all_supported_extensions()


def is_supported_config_file(path: Path | str) -> bool:
    """
    Return True if *path* has a recognized network configuration file extension.

    Extensions are matched case-insensitively.
    """
    return ExtensionRegistry.is_recognized(path)


def resolve_config_files(
    path_or_pattern: Path | str,
    extensions: tuple[str, ...] | None = None,
) -> list[Path]:
    """
    Resolve *path_or_pattern* to a sorted list of configuration file paths.

    Handling behavior:
    1. If *path_or_pattern* is an existing file, returns ``[Path(path_or_pattern)]``
       (accepts explicit file inputs regardless of extension, including unknown extensions and files without extension).
    2. If *path_or_pattern* is an existing directory, recursively scans for all
       files matching *extensions* (defaults to ExtensionRegistry.all_supported_extensions()).
    3. If *path_or_pattern* contains glob wildcards ('*', '?'), expands the glob
       and filters files by *extensions*.

    :raises FileNotFoundError: If no matching files exist.
    """
    if extensions is None:
        extensions = ExtensionRegistry.all_supported_extensions()

    path_str = str(path_or_pattern)
    p = Path(path_str)

    # 1. Direct existing file (accepts explicit file inputs regardless of extension or no extension)
    if p.is_file():
        return [p.resolve()]

    # 2. Existing directory — discover all matching config files
    if p.is_dir():
        found: list[Path] = []
        ext_set = {e.lower() for e in extensions}
        for item in p.rglob("*"):
            if item.is_file() and item.suffix.lower() in ext_set:
                found.append(item.resolve())
        if not found:
            raise FileNotFoundError(
                f"No configuration files matching registered extensions found in directory '{p}'"
            )
        found.sort()
        return found

    # 3. Glob pattern matching
    matched_strs = glob.glob(path_str, recursive=True)
    if matched_strs:
        found = []
        ext_set = {e.lower() for e in extensions}
        for m in matched_strs:
            mp = Path(m).resolve()
            if mp.is_file():
                if mp.suffix.lower() in ext_set or "*" in mp.suffix:
                    found.append(mp)
        if found:
            seen: set[Path] = set()
            unique: list[Path] = []
            for item in sorted(found):
                if item not in seen:
                    seen.add(item)
                    unique.append(item)
            return unique

    raise FileNotFoundError(f"No configuration files found for '{path_or_pattern}'")
