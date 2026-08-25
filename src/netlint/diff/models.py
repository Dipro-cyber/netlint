"""
ConfigDiff — structured result of comparing two ParsedConfig objects.

Every change is represented as a typed, immutable value object so the
formatter and tests can inspect each field individually rather than
parsing strings.

Change categories
-----------------
InterfaceChange   — an interface that exists in both configs but differs
VlanChange        — a VLAN definition that changed name or appeared/disappeared
RouteChange       — a static route that appeared, disappeared, or changed
AclChange         — an ACL whose entry list changed
VtyChange         — a VTY block whose transport/access-class changed
HostnameChange    — the device hostname changed
HttpServerChange  — ip http server / ip http secure-server state changed

Added / Removed items are simply lists of the raw parser model objects
(Interface, Vlan, StaticRoute, AclRule) so the formatter can present
them directly.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


# ---------------------------------------------------------------------------
# Change-type enum
# ---------------------------------------------------------------------------


class ChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


# ---------------------------------------------------------------------------
# Per-object change descriptors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldDelta:
    """One field that changed between old and new."""

    field_name: str
    old_value: Any
    new_value: Any

    def __str__(self) -> str:
        return f"{self.field_name}: {self.old_value!r} → {self.new_value!r}"


@dataclass(frozen=True)
class InterfaceChange:
    """An interface that exists in both configs but has differing attributes."""

    name: str
    deltas: tuple[FieldDelta, ...]

    @property
    def summary(self) -> str:
        parts = [d.field_name for d in self.deltas]
        return f"{self.name} ({', '.join(parts)})"


@dataclass(frozen=True)
class VlanChange:
    """A VLAN whose name changed."""

    vlan_id: int
    old_name: str | None
    new_name: str | None

    @property
    def summary(self) -> str:
        return f"VLAN {self.vlan_id} name: {self.old_name!r} → {self.new_name!r}"


@dataclass(frozen=True)
class RouteChange:
    """A static route whose next-hop, exit-interface, or AD changed."""

    network: ipaddress.IPv4Network
    deltas: tuple[FieldDelta, ...]

    @property
    def summary(self) -> str:
        parts = [d.field_name for d in self.deltas]
        return f"route {self.network} ({', '.join(parts)})"


@dataclass(frozen=True)
class AclChange:
    """An ACL whose entry count or entries changed."""

    name: str
    old_entry_count: int
    new_entry_count: int
    entries_added: int
    entries_removed: int

    @property
    def summary(self) -> str:
        parts = []
        if self.entries_added:
            parts.append(f"+{self.entries_added} entries")
        if self.entries_removed:
            parts.append(f"-{self.entries_removed} entries")
        return f"ACL {self.name} ({', '.join(parts)})"


@dataclass(frozen=True)
class VtyChange:
    """A VTY line block whose transport or access-class changed."""

    first: int
    last: int
    deltas: tuple[FieldDelta, ...]

    @property
    def summary(self) -> str:
        parts = [d.field_name for d in self.deltas]
        return f"line vty {self.first} {self.last} ({', '.join(parts)})"


@dataclass(frozen=True)
class HostnameChange:
    old_hostname: str | None
    new_hostname: str | None

    @property
    def summary(self) -> str:
        return f"hostname: {self.old_hostname!r} → {self.new_hostname!r}"


@dataclass(frozen=True)
class HttpServerChange:
    old_http: bool
    new_http: bool
    old_https: bool
    new_https: bool

    @property
    def summary(self) -> str:
        parts = []
        if self.old_http != self.new_http:
            state = "enabled" if self.new_http else "disabled"
            parts.append(f"ip http server {state}")
        if self.old_https != self.new_https:
            state = "enabled" if self.new_https else "disabled"
            parts.append(f"ip http secure-server {state}")
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Top-level ConfigDiff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigDiff:
    """
    The complete semantic diff of two Cisco IOS configuration files.

    All collections are immutable tuples.  Empty tuples mean no changes
    in that category.
    """

    old_path: str
    new_path: str

    # Hostname
    hostname_change: HostnameChange | None = None

    # Interfaces
    interfaces_added: tuple[Any, ...] = field(default_factory=tuple)
    interfaces_removed: tuple[Any, ...] = field(default_factory=tuple)
    interfaces_modified: tuple[InterfaceChange, ...] = field(default_factory=tuple)

    # VLANs
    vlans_added: tuple[Any, ...] = field(default_factory=tuple)
    vlans_removed: tuple[Any, ...] = field(default_factory=tuple)
    vlans_modified: tuple[VlanChange, ...] = field(default_factory=tuple)

    # Static routes
    routes_added: tuple[Any, ...] = field(default_factory=tuple)
    routes_removed: tuple[Any, ...] = field(default_factory=tuple)
    routes_modified: tuple[RouteChange, ...] = field(default_factory=tuple)

    # ACLs
    acls_added: tuple[Any, ...] = field(default_factory=tuple)
    acls_removed: tuple[Any, ...] = field(default_factory=tuple)
    acls_modified: tuple[AclChange, ...] = field(default_factory=tuple)

    # VTY lines
    vty_modified: tuple[VtyChange, ...] = field(default_factory=tuple)

    # HTTP server
    http_server_change: HttpServerChange | None = None

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def has_changes(self) -> bool:
        return any([
            self.hostname_change,
            self.interfaces_added, self.interfaces_removed, self.interfaces_modified,
            self.vlans_added, self.vlans_removed, self.vlans_modified,
            self.routes_added, self.routes_removed, self.routes_modified,
            self.acls_added, self.acls_removed, self.acls_modified,
            self.vty_modified,
            self.http_server_change,
        ])

    @property
    def added_count(self) -> int:
        return (
            len(self.interfaces_added)
            + len(self.vlans_added)
            + len(self.routes_added)
            + len(self.acls_added)
        )

    @property
    def removed_count(self) -> int:
        return (
            len(self.interfaces_removed)
            + len(self.vlans_removed)
            + len(self.routes_removed)
            + len(self.acls_removed)
        )

    @property
    def modified_count(self) -> int:
        return (
            len(self.interfaces_modified)
            + len(self.vlans_modified)
            + len(self.routes_modified)
            + len(self.acls_modified)
            + len(self.vty_modified)
            + (1 if self.hostname_change else 0)
            + (1 if self.http_server_change else 0)
        )
