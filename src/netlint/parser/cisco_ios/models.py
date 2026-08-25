"""
Structured data models produced by the Cisco IOS parser.

Every model carries ``line_number`` (1-based) pointing to the first
configuration line that produced it, so later lint rules can cite the
exact source location in their findings.

All models use frozen dataclasses — they are pure value objects.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AclAction(StrEnum):
    PERMIT = "permit"
    DENY = "deny"


class AclProtocol(StrEnum):
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class TransportProtocol(StrEnum):
    SSH = "ssh"
    TELNET = "telnet"
    ALL = "all"    # transport input all  — enables every protocol including Telnet
    NONE = "none"  # transport input none — disables all transports (secure)


class TrunkEncapsulation(StrEnum):
    DOT1Q = "dot1q"
    ISL = "isl"
    NEGOTIATE = "negotiate"


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Interface:
    """
    A single IOS interface stanza.

    ``name`` is the canonical interface name exactly as it appears in
    the config, e.g. ``GigabitEthernet0/0`` or ``Vlan10``.
    """

    name: str
    line_number: int

    description: str | None = None

    ip_address: ipaddress.IPv4Address | None = None
    subnet_mask: str | None = None
    prefix_length: int | None = None
    ip_network: ipaddress.IPv4Network | None = None
    """Derived: the /prefix network this interface belongs to (host bits zeroed)."""

    # Switchport
    access_vlan: int | None = None
    trunk_mode: bool = False
    trunk_encapsulation: TrunkEncapsulation | None = None
    trunk_allowed_vlans: str | None = None
    """Raw allowed-vlan string, e.g. '10,20,30-40'. Parsed by rules as needed."""

    shutdown: bool = False

    # VRF membership — interfaces in different VRFs may share IPs legitimately
    vrf: str | None = None
    """VRF name from 'ip vrf forwarding <name>', or None for global table."""

    # Helper — secondary addresses could be added later
    secondary_ips: tuple[ipaddress.IPv4Address, ...] = field(default_factory=tuple)

    # OSPF interface configuration: "ip ospf <pid> area <area>"
    ospf_process_id: str | None = None
    ospf_area: str | None = None
    ospf_area_line: int | None = None


# ---------------------------------------------------------------------------
# VLAN
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Vlan:
    """A ``vlan <id>`` block from the global config or vlan database."""

    vlan_id: int
    name: str | None = None
    line_number: int = 0


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StaticRoute:
    """
    A single ``ip route`` statement.

    Default routes (0.0.0.0/0) are modelled here too; callers can
    test ``route.network.prefixlen == 0`` to identify them.
    """

    network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address | None
    exit_interface: str | None
    admin_distance: int
    line_number: int

    @property
    def is_default(self) -> bool:
        return self.network.prefixlen == 0


# Alias for readability in rule code
Route = StaticRoute


# ---------------------------------------------------------------------------
# OSPF / BGP
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OspfNetwork:
    """A ``network <addr> <wildcard> area <id>`` statement."""

    network: str
    wildcard: str
    area: str
    line_number: int


@dataclass(frozen=True)
class OspfProcess:
    """A ``router ospf <process-id>`` block."""

    process_id: str
    line_number: int
    router_id: str | None = None
    router_id_line: int | None = None
    networks: tuple[OspfNetwork, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class BgpNeighbor:
    """A ``neighbor <addr> remote-as <asn>`` statement."""

    address: str
    remote_as: int | None
    line_number: int


@dataclass(frozen=True)
class BgpProcess:
    """A ``router bgp <as-number>`` block."""

    as_number: str
    line_number: int
    neighbors: tuple[BgpNeighbor, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# ACLs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AclEntry:
    """
    A single ACE (Access Control Entry) within a named or numbered ACL.

    ``source`` and ``destination`` are stored as strings because IOS
    ACEs support ``any``, ``host X.X.X.X``, and network/wildcard forms.
    We normalise to CIDR strings where possible but preserve the raw
    form for display.
    """

    sequence: int | None
    action: AclAction
    protocol: str  # raw string — may be "ip", "tcp", "udp", "icmp", a number, etc.
    source: str
    destination: str
    source_port: str | None
    destination_port: str | None
    line_number: int

    # Convenience: True when destination is "any" (common in overly-broad rules)
    @property
    def destination_is_any(self) -> bool:
        return self.destination.strip().lower() == "any"

    @property
    def source_is_any(self) -> bool:
        return self.source.strip().lower() == "any"


@dataclass(frozen=True)
class AclRule:
    """
    A complete named or numbered ACL.

    Numbered standard ACLs:  1-99, 1300-1999
    Numbered extended ACLs: 100-199, 2000-2699
    Named ACLs:              ``ip access-list [standard|extended] <name>``
    """

    name: str  # Either a number (as string) or a name
    acl_type: str  # "standard" | "extended" | "numbered-standard" | "numbered-extended"
    entries: tuple[AclEntry, ...]
    line_number: int


# ---------------------------------------------------------------------------
# VTY lines
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VtyLine:
    """
    A ``line vty <first> [last]`` block.

    Captures transport settings and access-class so security rules
    can flag Telnet-enabled management lines.
    """

    first: int
    last: int
    line_number: int

    transport_input: tuple[TransportProtocol, ...] = field(default_factory=tuple)
    transport_output: tuple[TransportProtocol, ...] = field(default_factory=tuple)
    access_class_in: str | None = None
    access_class_out: str | None = None
    login: str | None = None  # "local", "tacacs+", bare "login", or None
    exec_timeout: tuple[int, int] | None = None  # (minutes, seconds)
    password: str | None = None


# ---------------------------------------------------------------------------
# Top-level aggregate
# ---------------------------------------------------------------------------


@dataclass
class ParsedConfig:
    """
    The complete structured output of a Cisco IOS parse run.

    Attached to :class:`~netlint.models.config_file.ConfigFile` as
    ``config.parsed`` after parsing. Rules operate on this object.
    """

    hostname: str | None = None
    hostname_line: int | None = None

    interfaces: list[Interface] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    acls: list[AclRule] = field(default_factory=list)
    vty_lines: list[VtyLine] = field(default_factory=list)

    # Global HTTP / HTTPS management server state
    http_server_enabled: bool = False
    http_server_line: int | None = None
    https_server_enabled: bool = False
    https_server_line: int | None = None

    # NTP servers configured globally
    ntp_servers: list[str] = field(default_factory=list)

    # Logging hosts configured globally
    logging_hosts: list[str] = field(default_factory=list)
    logging_buffered: bool = False

    # SSH configuration
    ssh_version: int | None = None        # 1 or 2 from "ip ssh version <n>"
    ssh_version_line: int | None = None

    # SNMP community strings: list of (community, permission, line_number)
    snmp_communities: list[tuple[str, str, int]] = field(default_factory=list)

    # Password encryption service
    service_password_encryption: bool = False
    service_password_encryption_line: int | None = None

    # Global routing table
    ip_routing_enabled: bool = False

    # Cleartext enable password (distinct from enable secret)
    enable_password_line: int | None = None
    enable_secret_configured: bool = False

    # OSPF / BGP routing processes
    ospf_processes: list[OspfProcess] = field(default_factory=list)
    bgp_processes: list[BgpProcess] = field(default_factory=list)

    # Legacy field — kept for compatibility; prefer ospf_processes
    ospf_interface_areas: dict[str, dict[str, str]] = field(default_factory=dict)

    # Raw warnings collected during parsing (non-fatal)
    warnings: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience helpers used by rules
    # ------------------------------------------------------------------

    @property
    def default_routes(self) -> list[StaticRoute]:
        return [r for r in self.static_routes if r.is_default]

    def get_interface(self, name: str) -> Interface | None:
        """Return the interface with the given name (case-insensitive)."""
        name_lower = name.lower()
        for iface in self.interfaces:
            if iface.name.lower() == name_lower:
                return iface
        return None

    def get_acl(self, name: str) -> AclRule | None:
        """Return the ACL with the given name/number (case-insensitive)."""
        name_lower = name.lower()
        for acl in self.acls:
            if acl.name.lower() == name_lower:
                return acl
        return None
