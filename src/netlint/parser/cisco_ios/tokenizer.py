"""
Cisco IOS config tokenizer.

IOS configs follow a simple two-level structure:

    <global command>          <- depth 0
     <sub-command>            <- depth 1 (one leading space)
     ...
    !                         <- block separator (ignored)

This tokenizer groups the raw lines into :class:`ConfigBlock` objects,
each representing one top-level stanza together with all its child lines.
It also strips comments and blank lines while preserving 1-based line
numbers from the original file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# IOS uses a single space (or multiple) as indentation for sub-commands.
_INDENT_RE = re.compile(r"^[ \t]+")
_COMMENT_RE = re.compile(r"^\s*!")


@dataclass
class ConfigLine:
    """A single stripped configuration line with its original line number."""

    text: str
    """Stripped text of the line (no leading/trailing whitespace)."""

    line_number: int
    """1-based line number in the original file."""

    indent: int
    """Number of leading spaces in the original line (before stripping)."""


@dataclass
class ConfigBlock:
    """
    A top-level IOS stanza together with its indented child lines.

    Example — the ``interface`` stanza below becomes one ConfigBlock::

        interface GigabitEthernet0/0          <- header (depth 0)
         description Uplink to core           <- children (depth 1)
         ip address 10.0.0.1 255.255.255.0
         no shutdown

    ``header`` is the ConfigLine for the top-level command.
    ``children`` are the indented sub-command lines (already stripped).
    """

    header: ConfigLine
    children: list[ConfigLine] = field(default_factory=list)

    @property
    def keyword(self) -> str:
        """First word of the header line, lower-cased."""
        return self.header.text.split()[0].lower() if self.header.text else ""

    @property
    def rest(self) -> str:
        """Everything after the first word of the header line."""
        parts = self.header.text.split(None, 1)
        return parts[1] if len(parts) > 1 else ""


def tokenize(lines: tuple[str, ...]) -> list[ConfigBlock]:
    """
    Convert raw IOS config lines into a flat list of :class:`ConfigBlock` objects.

    :param lines: Lines exactly as produced by ``ConfigFile.lines``.
    :returns:     One ConfigBlock per top-level stanza.
    """
    config_lines = _preprocess(lines)
    return _group_blocks(config_lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _preprocess(lines: tuple[str, ...]) -> list[ConfigLine]:
    """
    Strip comments and blank lines; record indent depth and line numbers.
    """
    result: list[ConfigLine] = []
    for lineno, raw in enumerate(lines, start=1):
        # Skip pure comment lines (start with !) and blank lines
        if _COMMENT_RE.match(raw) or not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        result.append(ConfigLine(text=raw.strip(), line_number=lineno, indent=indent))
    return result


def _group_blocks(config_lines: list[ConfigLine]) -> list[ConfigBlock]:
    """
    Group preprocessed lines into top-level blocks with children.

    Lines at indent == 0 start a new block; lines with indent > 0
    are attached as children of the most recent block.
    """
    blocks: list[ConfigBlock] = []
    current: ConfigBlock | None = None

    for cl in config_lines:
        if cl.indent == 0:
            current = ConfigBlock(header=cl)
            blocks.append(current)
        else:
            if current is None:
                # Indented line before any top-level command — treat as global
                synthetic = ConfigLine(text="", line_number=cl.line_number, indent=0)
                current = ConfigBlock(header=synthetic)
                blocks.append(current)
            current.children.append(cl)

    return blocks
