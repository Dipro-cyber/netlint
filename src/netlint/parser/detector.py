"""
Automatic vendor and file type detector for NetLint.

Inspects raw configuration file content and identifies the network vendor / OS:
- cisco-ios   (Cisco IOS / IOS-XE)
- juniper     (Juniper JunOS - set format or hierarchical brace format)
- arista      (Arista EOS)
- generic     (Generic or unclassified configuration text)
"""

from __future__ import annotations

import re

_JUNIPER_SET_RE = re.compile(r"^\s*set\s+(interfaces|system|routing-options|protocols|vlans|security)\b", re.IGNORECASE)
_JUNIPER_HIER_RE = re.compile(r"^\s*(system|interfaces|protocols|routing-options)\s*\{", re.IGNORECASE)
_ARISTA_EOS_RE = re.compile(
    r"^\s*(transceiver\s+qsfp|management\s+api\s+http-commands|spanning-tree\s+mode\s+|interface\s+Ethernet\d+)",
    re.IGNORECASE,
)
_CISCO_IOS_RE = re.compile(
    r"^\s*(boot-start-marker|interface\s+GigabitEthernet|interface\s+FastEthernet|interface\s+TenGigabitEthernet|crypto\s+key\s+generate|version\s+15\.)",
    re.IGNORECASE,
)


def detect_vendor(raw_text: str) -> str:
    """
    Auto-detect the vendor format of a network configuration file.

    Returns one of:
    - ``"juniper"`` for Juniper JunOS
    - ``"arista"`` for Arista EOS
    - ``"cisco-ios"`` for Cisco IOS / IOS-XE
    - ``"generic"`` for unclassified configuration text
    """
    lines = raw_text.splitlines()

    juniper_score = 0
    arista_score = 0
    cisco_score = 0

    for line in lines[:200]:  # Check first 200 lines
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue

        if _JUNIPER_SET_RE.match(stripped) or _JUNIPER_HIER_RE.match(stripped):
            juniper_score += 3
        elif "apply-groups" in stripped or "host-name" in stripped:
            juniper_score += 2

        if _ARISTA_EOS_RE.match(stripped):
            arista_score += 3
        elif "arista" in stripped.lower() or "ethernet1/" in stripped.lower():
            arista_score += 2

        if _CISCO_IOS_RE.match(stripped):
            cisco_score += 3
        elif "cisco" in stripped.lower() or "building configuration" in stripped.lower() or "line vty" in stripped.lower():
            cisco_score += 1

    if juniper_score > arista_score and juniper_score > cisco_score:
        return "juniper"
    if arista_score > juniper_score and arista_score > cisco_score:
        return "arista"
    if cisco_score > 0:
        return "cisco-ios"

    return "generic"
