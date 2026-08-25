"""
ConfigDiffer — semantic comparison of two ParsedConfig objects.

Comparison logic
----------------
Each object type is keyed by a stable identity:

    Interface    → name  (case-insensitive)
    Vlan         → vlan_id
    StaticRoute  → (network, exit_interface)  — same destination, same exit
    AclRule      → name  (case-insensitive)
    VtyLine      → (first, last)

For items present in both configs, field-level deltas are computed and
collected into the appropriate *Change dataclass.  Items present in only
one config are reported as added or removed.

Only semantically meaningful fields are compared:
- Interfaces: ip_address, subnet_mask, prefix_length, description,
              access_vlan, trunk_mode, trunk_encapsulation,
              trunk_allowed_vlans, shutdown
- VLANs:      name
- Routes:     next_hop, exit_interface, admin_distance
- ACLs:       entry count + entry-set symmetric difference
- VTY:        transport_input, access_class_in, login
- Hostname:   string equality
- HTTP:       http_server_enabled, https_server_enabled

Line numbers are intentionally excluded from comparisons — they change
whenever any line is inserted/deleted and would produce spurious diffs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from netlint.diff.models import (
    AclChange,
    ConfigDiff,
    FieldDelta,
    HostnameChange,
    HttpServerChange,
    InterfaceChange,
    RouteChange,
    VlanChange,
    VtyChange,
)

if TYPE_CHECKING:
    from netlint.parser.cisco_ios.models import (
        AclRule,
        Interface,
        ParsedConfig,
        StaticRoute,
        VtyLine,
    )


def _delta(field_name: str, old: Any, new: Any) -> FieldDelta | None:
    """Return a FieldDelta when old != new, else None."""
    if old != new:
        return FieldDelta(field_name=field_name, old_value=old, new_value=new)
    return None


class ConfigDiffer:
    """
    Produces a :class:`ConfigDiff` from two :class:`ParsedConfig` instances.

    Usage::

        old_parsed = parser.parse_text(old_lines)
        new_parsed = parser.parse_text(new_lines)
        diff = ConfigDiffer().diff(old_parsed, new_parsed, old_path, new_path)
    """

    def diff(
        self,
        old: ParsedConfig,
        new: ParsedConfig,
        old_path: str = "old.cfg",
        new_path: str = "new.cfg",
    ) -> ConfigDiff:
        return ConfigDiff(
            old_path=old_path,
            new_path=new_path,
            hostname_change=self._diff_hostname(old, new),
            **self._diff_interfaces(old, new),
            **self._diff_vlans(old, new),
            **self._diff_routes(old, new),
            **self._diff_acls(old, new),
            vty_modified=tuple(self._diff_vty(old, new)),
            http_server_change=self._diff_http(old, new),
        )

    # ------------------------------------------------------------------
    # Hostname
    # ------------------------------------------------------------------

    def _diff_hostname(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> HostnameChange | None:
        if old.hostname != new.hostname:
            return HostnameChange(
                old_hostname=old.hostname, new_hostname=new.hostname
            )
        return None

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def _diff_interfaces(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> dict:
        old_map = {i.name.lower(): i for i in old.interfaces}
        new_map = {i.name.lower(): i for i in new.interfaces}

        old_keys = set(old_map)
        new_keys = set(new_map)

        added = tuple(new_map[k] for k in sorted(new_keys - old_keys))
        removed = tuple(old_map[k] for k in sorted(old_keys - new_keys))
        modified: list[InterfaceChange] = []

        for key in sorted(old_keys & new_keys):
            change = self._compare_interface(old_map[key], new_map[key])
            if change:
                modified.append(change)

        return {
            "interfaces_added": added,
            "interfaces_removed": removed,
            "interfaces_modified": tuple(modified),
        }

    def _compare_interface(
        self, old: Interface, new: Interface
    ) -> InterfaceChange | None:
        deltas: list[FieldDelta] = []

        for field_name in (
            "ip_address", "subnet_mask", "prefix_length",
            "description", "access_vlan", "trunk_mode",
            "trunk_encapsulation", "trunk_allowed_vlans", "shutdown",
        ):
            d = _delta(field_name, getattr(old, field_name), getattr(new, field_name))
            if d:
                deltas.append(d)

        if deltas:
            return InterfaceChange(name=old.name, deltas=tuple(deltas))
        return None

    # ------------------------------------------------------------------
    # VLANs
    # ------------------------------------------------------------------

    def _diff_vlans(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> dict:
        old_map = {v.vlan_id: v for v in old.vlans}
        new_map = {v.vlan_id: v for v in new.vlans}

        old_ids = set(old_map)
        new_ids = set(new_map)

        added = tuple(new_map[i] for i in sorted(new_ids - old_ids))
        removed = tuple(old_map[i] for i in sorted(old_ids - new_ids))
        modified: list[VlanChange] = []

        for vid in sorted(old_ids & new_ids):
            if old_map[vid].name != new_map[vid].name:
                modified.append(VlanChange(
                    vlan_id=vid,
                    old_name=old_map[vid].name,
                    new_name=new_map[vid].name,
                ))

        return {
            "vlans_added": added,
            "vlans_removed": removed,
            "vlans_modified": tuple(modified),
        }

    # ------------------------------------------------------------------
    # Static routes
    # ------------------------------------------------------------------

    def _route_key(self, route: StaticRoute) -> tuple:
        """Stable identity: same destination network + exit interface."""
        return (str(route.network), route.exit_interface or "")

    def _diff_routes(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> dict:
        old_map = {self._route_key(r): r for r in old.static_routes}
        new_map = {self._route_key(r): r for r in new.static_routes}

        old_keys = set(old_map)
        new_keys = set(new_map)

        added = tuple(new_map[k] for k in sorted(new_keys - old_keys))
        removed = tuple(old_map[k] for k in sorted(old_keys - new_keys))
        modified: list[RouteChange] = []

        for key in sorted(old_keys & new_keys):
            change = self._compare_route(old_map[key], new_map[key])
            if change:
                modified.append(change)

        return {
            "routes_added": added,
            "routes_removed": removed,
            "routes_modified": tuple(modified),
        }

    def _compare_route(
        self, old: StaticRoute, new: StaticRoute
    ) -> RouteChange | None:
        deltas: list[FieldDelta] = []
        for field_name in ("next_hop", "exit_interface", "admin_distance"):
            d = _delta(field_name, getattr(old, field_name), getattr(new, field_name))
            if d:
                deltas.append(d)

        if deltas:
            return RouteChange(network=old.network, deltas=tuple(deltas))
        return None

    # ------------------------------------------------------------------
    # ACLs
    # ------------------------------------------------------------------

    def _diff_acls(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> dict:
        old_map = {a.name.lower(): a for a in old.acls}
        new_map = {a.name.lower(): a for a in new.acls}

        old_keys = set(old_map)
        new_keys = set(new_map)

        added = tuple(new_map[k] for k in sorted(new_keys - old_keys))
        removed = tuple(old_map[k] for k in sorted(old_keys - new_keys))
        modified: list[AclChange] = []

        for key in sorted(old_keys & new_keys):
            change = self._compare_acl(old_map[key], new_map[key])
            if change:
                modified.append(change)

        return {
            "acls_added": added,
            "acls_removed": removed,
            "acls_modified": tuple(modified),
        }

    def _compare_acl(
        self, old: AclRule, new: AclRule
    ) -> AclChange | None:
        # Compare entry fingerprints (action+protocol+source+destination+ports)
        def _fingerprint(entry: Any) -> tuple:
            return (
                entry.action,
                entry.protocol,
                entry.source,
                entry.destination,
                entry.source_port,
                entry.destination_port,
            )

        old_fps = {_fingerprint(e) for e in old.entries}
        new_fps = {_fingerprint(e) for e in new.entries}

        added = len(new_fps - old_fps)
        removed = len(old_fps - new_fps)

        if added or removed or (len(old.entries) != len(new.entries)):
            return AclChange(
                name=old.name,
                old_entry_count=len(old.entries),
                new_entry_count=len(new.entries),
                entries_added=added,
                entries_removed=removed,
            )
        return None

    # ------------------------------------------------------------------
    # VTY lines
    # ------------------------------------------------------------------

    def _diff_vty(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> list[VtyChange]:
        old_map = {(v.first, v.last): v for v in old.vty_lines}
        new_map = {(v.first, v.last): v for v in new.vty_lines}

        changes: list[VtyChange] = []
        for key in sorted(set(old_map) & set(new_map)):
            change = self._compare_vty(old_map[key], new_map[key])
            if change:
                changes.append(change)
        return changes

    def _compare_vty(
        self, old: VtyLine, new: VtyLine
    ) -> VtyChange | None:
        deltas: list[FieldDelta] = []
        for field_name in ("transport_input", "access_class_in", "login"):
            d = _delta(field_name, getattr(old, field_name), getattr(new, field_name))
            if d:
                deltas.append(d)

        if deltas:
            return VtyChange(first=old.first, last=old.last, deltas=tuple(deltas))
        return None

    # ------------------------------------------------------------------
    # HTTP server
    # ------------------------------------------------------------------

    def _diff_http(
        self, old: ParsedConfig, new: ParsedConfig
    ) -> HttpServerChange | None:
        if (
            old.http_server_enabled != new.http_server_enabled
            or old.https_server_enabled != new.https_server_enabled
        ):
            return HttpServerChange(
                old_http=old.http_server_enabled,
                new_http=new.http_server_enabled,
                old_https=old.https_server_enabled,
                new_https=new.https_server_enabled,
            )
        return None
