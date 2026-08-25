"""
Cisco IOS configuration parser.

Walks the token stream produced by the tokenizer and builds a
``ParsedConfig`` from recognized stanzas. Unrecognized top-level
commands are silently skipped; malformed sub-commands produce a
warning stored in ``ParsedConfig.warnings`` rather than crashing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

from netlint.exceptions import ParseError
from netlint.parser.base import BaseParser
from netlint.parser.cisco_ios.models import (
    AclAction,
    AclEntry,
    AclRule,
    BgpNeighbor,
    BgpProcess,
    Interface,
    OspfNetwork,
    OspfProcess,
    ParsedConfig,
    StaticRoute,
    TransportProtocol,
    TrunkEncapsulation,
    Vlan,
    VtyLine,
)
from netlint.parser.cisco_ios.tokenizer import ConfigBlock, ConfigLine, tokenize
from netlint.parser.registry import ParserRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MASK_TO_PREFIX: dict[str, int] = {
    "255.255.255.255": 32, "255.255.255.254": 31, "255.255.255.252": 30,
    "255.255.255.248": 29, "255.255.255.240": 28, "255.255.255.224": 27,
    "255.255.255.192": 26, "255.255.255.128": 25, "255.255.255.0": 24,
    "255.255.254.0": 23,   "255.255.252.0": 22,   "255.255.248.0": 21,
    "255.255.240.0": 20,   "255.255.224.0": 19,   "255.255.192.0": 18,
    "255.255.128.0": 17,   "255.255.0.0": 16,     "255.254.0.0": 15,
    "255.252.0.0": 14,     "255.248.0.0": 13,     "255.240.0.0": 12,
    "255.224.0.0": 11,     "255.192.0.0": 10,     "255.128.0.0": 9,
    "255.0.0.0": 8,        "254.0.0.0": 7,        "252.0.0.0": 6,
    "248.0.0.0": 5,        "240.0.0.0": 4,        "224.0.0.0": 3,
    "192.0.0.0": 2,        "128.0.0.0": 1,        "0.0.0.0": 0,
}


def _mask_to_prefix(mask: str) -> int | None:
    return _MASK_TO_PREFIX.get(mask)


def _wildcard_to_prefix(wildcard: str) -> int | None:
    """Convert an IOS wildcard mask (ACL notation) to a prefix length."""
    try:
        parts = [255 - int(o) for o in wildcard.split(".")]
        if len(parts) != 4:
            return None
        mask = ".".join(str(p) for p in parts)
        return _MASK_TO_PREFIX.get(mask)
    except ValueError:
        return None


def _parse_transport(tokens: list[str]) -> tuple[TransportProtocol, ...]:
    """Parse ``transport input ssh telnet`` etc. into a tuple of protocols."""
    result: list[TransportProtocol] = []
    for tok in tokens:
        t = tok.lower()
        if t == "ssh":
            result.append(TransportProtocol.SSH)
        elif t == "telnet":
            result.append(TransportProtocol.TELNET)
        elif t == "all":
            result.append(TransportProtocol.ALL)
        elif t == "none":
            result.append(TransportProtocol.NONE)
    return tuple(result)


def _normalize_iface_name(name: str) -> str:
    """
    Expand common IOS abbreviations to full interface names.
    e.g. "Gi0/0" -> "GigabitEthernet0/0", "Fa0/1" -> "FastEthernet0/1"
    """
    abbrevs = {
        "gi": "GigabitEthernet",
        "fa": "FastEthernet",
        "te": "TenGigabitEthernet",
        "hu": "HundredGigE",
        "se": "Serial",
        "lo": "Loopback",
        "tu": "Tunnel",
        "vl": "Vlan",
        "po": "Port-channel",
        "mg": "Management",
        "et": "Ethernet",
    }
    for abbrev, full in abbrevs.items():
        if name.lower().startswith(abbrev) and not name.lower().startswith(full.lower()):
            suffix = name[len(abbrev):]
            return full + suffix
    return name


# ---------------------------------------------------------------------------
# Per-stanza sub-parsers (pure functions, no side effects)
# ---------------------------------------------------------------------------


def _parse_interface(block: ConfigBlock, warnings: list[str]) -> Interface:
    """Parse one ``interface`` stanza into an :class:`Interface`."""
    raw_name = block.rest.strip()
    name = _normalize_iface_name(raw_name)

    description: str | None = None
    ip_address: ipaddress.IPv4Address | None = None
    subnet_mask: str | None = None
    prefix_length: int | None = None
    ip_network: ipaddress.IPv4Network | None = None
    access_vlan: int | None = None
    trunk_mode: bool = False
    trunk_encapsulation: TrunkEncapsulation | None = None
    trunk_allowed_vlans: str | None = None
    shutdown: bool = False
    vrf: str | None = None
    ospf_process_id: str | None = None
    ospf_area: str | None = None
    ospf_area_line: int | None = None

    for child in block.children:
        tokens = child.text.split()
        if not tokens:
            continue

        kw = tokens[0].lower()

        # description
        if kw == "description":
            description = child.text.split(None, 1)[1] if len(tokens) > 1 else ""

        # ip vrf forwarding <name>
        elif (
            kw == "ip"
            and len(tokens) >= 3
            and tokens[1].lower() == "vrf"
            and tokens[2].lower() == "forwarding"
        ):
            vrf = tokens[3] if len(tokens) >= 4 else None

        # ip address <addr> <mask> [secondary]
        elif kw == "ip" and len(tokens) >= 2 and tokens[1].lower() == "address":
            if len(tokens) >= 4:
                try:
                    ip_address = ipaddress.IPv4Address(tokens[2])
                    subnet_mask = tokens[3]
                    pl = _mask_to_prefix(subnet_mask)
                    if pl is None:
                        warnings.append(
                            f"Line {child.line_number}: unrecognised subnet mask '{subnet_mask}'"
                        )
                    else:
                        prefix_length = pl
                        ip_network = ipaddress.IPv4Network(
                            f"{tokens[2]}/{pl}", strict=False
                        )
                except (ValueError, ipaddress.AddressValueError) as exc:
                    warnings.append(
                        f"Line {child.line_number}: bad IP address — {exc}"
                    )
            else:
                warnings.append(
                    f"Line {child.line_number}: 'ip address' missing address/mask"
                )

        # shutdown / no shutdown
        elif kw == "shutdown":
            shutdown = True
        elif kw == "no" and len(tokens) >= 2 and tokens[1].lower() == "shutdown":
            shutdown = False

        # encapsulation dot1q <vlan_id> (subinterfaces)
        elif (
            kw == "encapsulation"
            and len(tokens) >= 3
            and tokens[1].lower() == "dot1q"
        ):
            try:
                access_vlan = int(tokens[2])
            except ValueError:
                pass

        # switchport access vlan <id>
        elif (
            kw == "switchport"
            and len(tokens) >= 4
            and tokens[1].lower() == "access"
            and tokens[2].lower() == "vlan"
        ):
            try:
                access_vlan = int(tokens[3])
            except ValueError:
                warnings.append(
                    f"Line {child.line_number}: invalid access VLAN id '{tokens[3]}'"
                )

        # switchport mode trunk
        elif (
            kw == "switchport"
            and len(tokens) >= 3
            and tokens[1].lower() == "mode"
            and tokens[2].lower() == "trunk"
        ):
            trunk_mode = True

        # switchport trunk encapsulation dot1q|isl|negotiate
        elif (
            kw == "switchport"
            and len(tokens) >= 4
            and tokens[1].lower() == "trunk"
            and tokens[2].lower() == "encapsulation"
        ):
            enc = tokens[3].lower()
            if enc == "dot1q":
                trunk_encapsulation = TrunkEncapsulation.DOT1Q
            elif enc == "isl":
                trunk_encapsulation = TrunkEncapsulation.ISL
            elif enc == "negotiate":
                trunk_encapsulation = TrunkEncapsulation.NEGOTIATE
            else:
                warnings.append(
                    f"Line {child.line_number}: unknown trunk encapsulation '{enc}'"
                )

        # switchport trunk allowed vlan <list>
        elif (
            kw == "switchport"
            and len(tokens) >= 5
            and tokens[1].lower() == "trunk"
            and tokens[2].lower() == "allowed"
            and tokens[3].lower() == "vlan"
        ):
            trunk_allowed_vlans = tokens[4]

        # ip ospf <pid> area <area>
        elif (
            kw == "ip"
            and len(tokens) >= 5
            and tokens[1].lower() == "ospf"
            and tokens[3].lower() == "area"
        ):
            ospf_process_id = tokens[2]
            ospf_area = tokens[4]
            ospf_area_line = child.line_number

    return Interface(
        name=name,
        line_number=block.header.line_number,
        description=description,
        ip_address=ip_address,
        subnet_mask=subnet_mask,
        prefix_length=prefix_length,
        ip_network=ip_network,
        access_vlan=access_vlan,
        trunk_mode=trunk_mode,
        trunk_encapsulation=trunk_encapsulation,
        trunk_allowed_vlans=trunk_allowed_vlans,
        shutdown=shutdown,
        vrf=vrf,
        ospf_process_id=ospf_process_id,
        ospf_area=ospf_area,
        ospf_area_line=ospf_area_line,
    )


def _parse_vlan_block(block: ConfigBlock, warnings: list[str]) -> Vlan | None:
    """Parse a ``vlan <id>`` block."""
    try:
        vlan_id = int(block.rest.strip())
    except ValueError:
        warnings.append(
            f"Line {block.header.line_number}: invalid VLAN id '{block.rest.strip()}'"
        )
        return None

    name: str | None = None
    for child in block.children:
        tokens = child.text.split()
        if tokens and tokens[0].lower() == "name" and len(tokens) >= 2:
            name = tokens[1]

    return Vlan(vlan_id=vlan_id, name=name, line_number=block.header.line_number)


def _parse_static_route(
    line: ConfigLine, warnings: list[str]
) -> StaticRoute | None:
    """
    Parse a global ``ip route`` line.

    Forms:
        ip route <network> <mask> <next-hop>
        ip route <network> <mask> <exit-iface>
        ip route <network> <mask> <exit-iface> <next-hop>
        ip route <network> <mask> <next-hop> <admin-distance>
        ip route 0.0.0.0 0.0.0.0 <next-hop>  (default route)
    """
    tokens = line.text.split()
    # tokens[0]="ip", tokens[1]="route", then network mask next-hop...
    # Skip VRF-aware routes: "ip route vrf <name> <net> <mask> <nh>"
    if len(tokens) >= 3 and tokens[2].lower() == "vrf":
        return None  # VRF routing not yet modelled — silently skip

    if len(tokens) < 5:
        warnings.append(
            f"Line {line.line_number}: malformed 'ip route' statement: '{line.text}'"
        )
        return None

    net_str = tokens[2]
    mask_str = tokens[3]
    pl = _mask_to_prefix(mask_str)
    if pl is None:
        warnings.append(
            f"Line {line.line_number}: unknown route mask '{mask_str}'"
        )
        return None

    try:
        network = ipaddress.IPv4Network(f"{net_str}/{pl}", strict=False)
    except ValueError as exc:
        warnings.append(f"Line {line.line_number}: bad route network — {exc}")
        return None

    next_hop: ipaddress.IPv4Address | None = None
    exit_interface: str | None = None
    admin_distance: int = 1

    # tokens[4] is either a next-hop IP or an interface name
    hop_or_iface = tokens[4]
    try:
        next_hop = ipaddress.IPv4Address(hop_or_iface)
    except ValueError:
        exit_interface = hop_or_iface
        # tokens[5] might be next-hop or admin-distance
        if len(tokens) >= 6:
            try:
                next_hop = ipaddress.IPv4Address(tokens[5])
                if len(tokens) >= 7:
                    try:
                        admin_distance = int(tokens[6])
                    except ValueError:
                        pass
            except ValueError:
                try:
                    admin_distance = int(tokens[5])
                except ValueError:
                    pass
    else:
        # tokens[5] might be admin-distance
        if len(tokens) >= 6:
            try:
                admin_distance = int(tokens[5])
            except ValueError:
                pass

    return StaticRoute(
        network=network,
        next_hop=next_hop,
        exit_interface=exit_interface,
        admin_distance=admin_distance,
        line_number=line.line_number,
    )


# ---------------------------------------------------------------------------
# ACL parsing
# ---------------------------------------------------------------------------

_ACE_RE = re.compile(
    r"^(?:(\d+)\s+)?"                        # optional sequence number
    r"(permit|deny)\s+"                       # action
    r"(\S+)\s+"                               # protocol
    r"(.+)$",                                 # rest (source + dest + options)
    re.IGNORECASE,
)


def _parse_ace_rest(rest: str) -> tuple[str, str, str | None, str | None]:
    """
    Split the remainder of an ACE into (source, destination, src_port, dst_port).

    Handles:
        any
        host <ip>
        <ip> <wildcard>
        ... eq <port> / range <lo> <hi>
    """
    tokens = rest.split()
    idx = 0

    def _read_addr() -> tuple[str, int]:
        """Read one address token group; return (addr_string, tokens_consumed)."""
        if idx >= len(tokens):
            return "any", 0
        kw = tokens[idx].lower()
        if kw == "any":
            return "any", 1
        if kw == "host":
            addr = tokens[idx + 1] if idx + 1 < len(tokens) else "?"
            return f"host {addr}", 2
        # ip wildcard
        addr = tokens[idx]
        wildcard = tokens[idx + 1] if idx + 1 < len(tokens) else "0.0.0.0"
        pl = _wildcard_to_prefix(wildcard)
        if pl is not None:
            try:
                net = ipaddress.IPv4Network(f"{addr}/{pl}", strict=False)
                return str(net), 2
            except ValueError:
                pass
        return f"{addr} {wildcard}", 2

    src, consumed = _read_addr()
    idx += consumed

    def _read_port() -> tuple[str | None, int]:
        if idx >= len(tokens):
            return None, 0
        kw = tokens[idx].lower()
        if kw == "eq" and idx + 1 < len(tokens):
            return f"eq {tokens[idx + 1]}", 2
        if kw == "range" and idx + 2 < len(tokens):
            return f"range {tokens[idx + 1]} {tokens[idx + 2]}", 3
        if kw in ("gt", "lt", "neq") and idx + 1 < len(tokens):
            return f"{kw} {tokens[idx + 1]}", 2
        return None, 0

    src_port, consumed = _read_port()
    idx += consumed

    dst, consumed = _read_addr()
    idx += consumed

    dst_port, consumed = _read_port()

    return src, dst, src_port, dst_port


_KNOWN_PROTOCOLS = {
    "ip", "tcp", "udp", "icmp", "icmp6", "ospf", "eigrp", "gre",
    "esp", "ahp", "igmp", "pim", "any",
}

# Standard ACL line: [seq] permit|deny <addr-or-any> [wildcard]
_STD_ACE_RE = re.compile(
    r"^(?:(\d+)\s+)?"               # optional sequence
    r"(permit|deny)\s+"             # action
    r"(.+)$",                       # source (no protocol, no dest)
    re.IGNORECASE,
)


def _looks_like_standard_ace(text: str) -> bool:
    """
    Return True when the line looks like a standard ACL entry
    (action followed by a source address/any, NOT a protocol keyword + src + dst).

    Standard:   permit any
                permit 192.168.1.0 0.0.0.255
    Extended:   permit tcp any any eq 22
                permit ip 10.0.0.0 0.255.255.255 any
    """
    tokens = text.split()
    idx = 0
    # Skip optional sequence number
    if tokens and tokens[0].isdigit():
        idx = 1
    # Must have action
    if idx >= len(tokens) or tokens[idx].lower() not in ("permit", "deny"):
        return False
    idx += 1  # move past action
    if idx >= len(tokens):
        return False
    candidate = tokens[idx].lower()
    # If the candidate is a known protocol AND there are more tokens after it,
    # it's the protocol field of an extended ACE.
    if candidate in _KNOWN_PROTOCOLS and idx + 1 < len(tokens):
        return False
    # If it's a plain integer it's a protocol number (extended)
    if candidate.isdigit():
        return False
    return True


def _parse_ace_line(line: ConfigLine, warnings: list[str]) -> AclEntry | None:
    """Parse a single ACE line into an :class:`AclEntry`."""

    # Standard ACL syntax: [seq] permit|deny <src> [wildcard]
    if _looks_like_standard_ace(line.text):
        m = _STD_ACE_RE.match(line.text)
        if not m:
            return None
        seq_str, action_str, src_rest = m.groups()
        sequence = int(seq_str) if seq_str else None
        try:
            action = AclAction(action_str.lower())
        except ValueError:
            warnings.append(
                f"Line {line.line_number}: unknown ACL action '{action_str}'"
            )
            return None
        src, _, src_port, _ = _parse_ace_rest(src_rest)
        return AclEntry(
            sequence=sequence,
            action=action,
            protocol="ip",
            source=src,
            destination="any",
            source_port=src_port,
            destination_port=None,
            line_number=line.line_number,
        )

    # Extended ACL syntax: [seq] permit|deny <protocol> <src> <dst> [options]
    m = _ACE_RE.match(line.text)
    if not m:
        return None

    seq_str, action_str, protocol, rest = m.groups()
    sequence = int(seq_str) if seq_str else None

    try:
        action = AclAction(action_str.lower())
    except ValueError:
        warnings.append(
            f"Line {line.line_number}: unknown ACL action '{action_str}'"
        )
        return None

    src, dst, src_port, dst_port = _parse_ace_rest(rest)

    return AclEntry(
        sequence=sequence,
        action=action,
        protocol=protocol.lower(),
        source=src,
        destination=dst,
        source_port=src_port,
        destination_port=dst_port,
        line_number=line.line_number,
    )


def _parse_named_acl(block: ConfigBlock, warnings: list[str]) -> AclRule | None:
    """
    Parse a ``ip access-list [standard|extended] <name>`` block.
    """
    # block.header.text == "ip access-list extended OUTSIDE_IN"
    tokens = block.header.text.split()
    # tokens: ["ip", "access-list", "extended"|"standard", "<name>"]
    if len(tokens) < 4:
        warnings.append(
            f"Line {block.header.line_number}: malformed named ACL header: "
            f"'{block.header.text}'"
        )
        return None

    acl_type = tokens[2].lower()
    name = tokens[3]
    entries: list[AclEntry] = []

    for child in block.children:
        entry = _parse_ace_line(child, warnings)
        if entry:
            entries.append(entry)

    return AclRule(
        name=name,
        acl_type=acl_type,
        entries=tuple(entries),
        line_number=block.header.line_number,
    )


def _parse_numbered_acl_line(
    line: ConfigLine,
    acls: dict[str, list[AclEntry]],
    acl_meta: dict[str, tuple[str, int]],
    warnings: list[str],
) -> None:
    """
    Parse a numbered ACL line, e.g.:
        access-list 10 permit 192.168.1.0 0.0.0.255
        access-list 100 deny tcp any any eq 23
    """
    tokens = line.text.split()
    if len(tokens) < 3:
        return

    acl_num_str = tokens[1]
    try:
        acl_num = int(acl_num_str)
    except ValueError:
        warnings.append(
            f"Line {line.line_number}: non-numeric ACL number '{acl_num_str}'"
        )
        return

    if 1 <= acl_num <= 99 or 1300 <= acl_num <= 1999:
        acl_type = "numbered-standard"
    else:
        acl_type = "numbered-extended"

    # Reconstruct an ACE-like line without "access-list <num>"
    ace_text = " ".join(tokens[2:])
    synthetic = ConfigLine(text=ace_text, line_number=line.line_number, indent=0)
    entry = _parse_ace_line(synthetic, warnings)
    if entry:
        if acl_num_str not in acls:
            acls[acl_num_str] = []
            acl_meta[acl_num_str] = (acl_type, line.line_number)
        acls[acl_num_str].append(entry)


def _parse_vty(block: ConfigBlock, warnings: list[str]) -> VtyLine | None:
    """Parse a ``line vty <first> [last]`` block."""
    tokens = block.rest.strip().split()
    if not tokens:
        return None

    # "vty 0 4" or "vty 0"
    try:
        first = int(tokens[0])
        last = int(tokens[1]) if len(tokens) >= 2 else first
    except ValueError:
        warnings.append(
            f"Line {block.header.line_number}: malformed VTY range '{block.rest}'"
        )
        return None

    transport_input: tuple[TransportProtocol, ...] = ()
    transport_output: tuple[TransportProtocol, ...] = ()
    access_class_in: str | None = None
    access_class_out: str | None = None
    login: str | None = None
    exec_timeout: tuple[int, int] | None = None
    password: str | None = None

    for child in block.children:
        tokens_c = child.text.split()
        if not tokens_c:
            continue
        kw = tokens_c[0].lower()

        if kw == "transport" and len(tokens_c) >= 3:
            direction = tokens_c[1].lower()
            protocols = _parse_transport(tokens_c[2:])
            if direction == "input":
                transport_input = protocols
            elif direction == "output":
                transport_output = protocols

        elif kw == "access-class" and len(tokens_c) >= 3:
            acl_name = tokens_c[1]
            direction = tokens_c[2].lower()
            if direction == "in":
                access_class_in = acl_name
            elif direction == "out":
                access_class_out = acl_name

        elif kw == "login":
            login = tokens_c[1].lower() if len(tokens_c) >= 2 else "login"

        elif kw == "exec-timeout" and len(tokens_c) >= 2:
            try:
                mins = int(tokens_c[1])
                secs = int(tokens_c[2]) if len(tokens_c) >= 3 else 0
                exec_timeout = (mins, secs)
            except ValueError:
                warnings.append(
                    f"Line {child.line_number}: bad exec-timeout values"
                )

        elif kw == "password" and len(tokens_c) >= 2:
            password = tokens_c[1]

    return VtyLine(
        first=first,
        last=last,
        line_number=block.header.line_number,
        transport_input=transport_input,
        transport_output=transport_output,
        access_class_in=access_class_in,
        access_class_out=access_class_out,
        login=login,
        exec_timeout=exec_timeout,
        password=password,
    )


def _parse_ospf_block(block: ConfigBlock, warnings: list[str]) -> OspfProcess | None:
    """Parse a ``router ospf <process-id>`` block."""
    process_id = block.rest.strip()
    if not process_id:
        warnings.append(
            f"Line {block.header.line_number}: malformed OSPF process id"
        )
        return None

    router_id: str | None = None
    router_id_line: int | None = None
    networks: list[OspfNetwork] = []

    for child in block.children:
        tokens = child.text.split()
        if not tokens:
            continue
        kw = tokens[0].lower()

        if kw == "router-id" and len(tokens) >= 2:
            router_id = tokens[1]
            router_id_line = child.line_number

        elif kw == "network" and len(tokens) >= 5 and tokens[3].lower() == "area":
            networks.append(
                OspfNetwork(
                    network=tokens[1],
                    wildcard=tokens[2],
                    area=tokens[4],
                    line_number=child.line_number,
                )
            )

    return OspfProcess(
        process_id=process_id,
        line_number=block.header.line_number,
        router_id=router_id,
        router_id_line=router_id_line,
        networks=tuple(networks),
    )


def _parse_bgp_block(block: ConfigBlock, warnings: list[str]) -> BgpProcess | None:
    """Parse a ``router bgp <as-number>`` block."""
    as_number = block.rest.strip()
    if not as_number:
        warnings.append(
            f"Line {block.header.line_number}: malformed BGP AS number"
        )
        return None

    neighbors: list[BgpNeighbor] = []

    for child in block.children:
        tokens = child.text.split()
        if not tokens:
            continue
        kw = tokens[0].lower()

        if kw == "neighbor" and len(tokens) >= 2:
            address = tokens[1]
            remote_as: int | None = None
            if len(tokens) >= 4 and tokens[2].lower() == "remote-as":
                try:
                    remote_as = int(tokens[3])
                except ValueError:
                    warnings.append(
                        f"Line {child.line_number}: invalid BGP remote-as "
                        f"'{tokens[3]}'"
                    )
            neighbors.append(
                BgpNeighbor(
                    address=address,
                    remote_as=remote_as,
                    line_number=child.line_number,
                )
            )

    return BgpProcess(
        as_number=as_number,
        line_number=block.header.line_number,
        neighbors=tuple(neighbors),
    )


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------


class CiscoIosParser(BaseParser):
    """
    Parser for Cisco IOS / IOS-XE configuration files.

    Registered as the ``"cisco-ios"`` vendor parser.

    After :meth:`parse` returns, the result is stored as
    ``config._parsed`` (accessed via :attr:`last_result`).
    Use :meth:`parse_text` directly in tests to skip the ConfigFile layer.
    """

    vendor = "cisco-ios"

    def __init__(self) -> None:
        self._last_result: ParsedConfig | None = None

    @property
    def last_result(self) -> ParsedConfig | None:
        return self._last_result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, config: ConfigFile) -> ParsedConfig:
        """
        Parse *config* and return the structured :class:`ParsedConfig`.

        Raises :class:`~netlint.exceptions.ParseError` only for
        unrecoverable structural problems. Soft errors go into
        ``ParsedConfig.warnings``.
        """
        result = self.parse_text(config.lines)
        self._last_result = result
        return result

    def parse_text(self, lines: tuple[str, ...] | list[str]) -> ParsedConfig:
        """
        Parse raw lines directly (useful in tests without a ConfigFile).
        """
        if isinstance(lines, list):
            lines = tuple(lines)

        if not lines:
            raise ParseError("Configuration is empty")

        blocks = tokenize(lines)
        return self._walk_blocks(blocks)

    # ------------------------------------------------------------------
    # Block walker
    # ------------------------------------------------------------------

    def _walk_blocks(self, blocks: list[ConfigBlock]) -> ParsedConfig:
        result = ParsedConfig()

        # Collect numbered ACL entries across multiple lines before building AclRule objects
        numbered_acl_entries: dict[str, list[AclEntry]] = {}
        numbered_acl_meta: dict[str, tuple[str, int]] = {}  # name -> (type, first_lineno)

        for block in blocks:
            kw = block.keyword

            # hostname
            if kw == "hostname":
                result.hostname = block.rest.strip()
                result.hostname_line = block.header.line_number

            # service password-encryption
            elif kw == "service":
                tokens = block.header.text.split()
                if len(tokens) >= 2 and tokens[1].lower() == "password-encryption":
                    result.service_password_encryption = True
                    result.service_password_encryption_line = block.header.line_number

            # no service password-encryption
            elif kw == "no" and block.header.text.lower().startswith(
                "no service password-encryption"
            ):
                result.service_password_encryption = False
                result.service_password_encryption_line = block.header.line_number

            # ip routing
            elif kw == "ip" and block.header.text.lower() == "ip routing":
                result.ip_routing_enabled = True

            # snmp-server community ...
            elif kw == "snmp-server":
                tokens = block.header.text.split()
                if len(tokens) >= 4 and tokens[1].lower() == "community":
                    community = tokens[2]
                    permission = tokens[3].lower()
                    result.snmp_communities.append(
                        (community, permission, block.header.line_number)
                    )

            # enable password / enable secret
            elif kw == "enable":
                tokens = block.header.text.split()
                if len(tokens) >= 2:
                    sub = tokens[1].lower()
                    if sub == "password":
                        result.enable_password_line = block.header.line_number
                    elif sub == "secret":
                        result.enable_secret_configured = True

            # router ospf / router bgp
            elif kw == "router":
                tokens = block.header.text.split()
                if len(tokens) >= 2:
                    proto = tokens[1].lower()
                    if proto == "ospf":
                        ospf = _parse_ospf_block(block, result.warnings)
                        if ospf:
                            result.ospf_processes.append(ospf)
                    elif proto == "bgp":
                        bgp = _parse_bgp_block(block, result.warnings)
                        if bgp:
                            result.bgp_processes.append(bgp)

            # interface
            elif kw == "interface":
                iface = _parse_interface(block, result.warnings)
                result.interfaces.append(iface)

            # vlan <id>
            elif kw == "vlan":
                # Only treat as a VLAN block when the rest is a plain integer
                # (avoids misinterpreting "vlan database" etc.)
                if block.rest.strip().isdigit():
                    vlan = _parse_vlan_block(block, result.warnings)
                    if vlan:
                        result.vlans.append(vlan)

            # ip route / ip access-list / ip http
            elif kw == "ip":
                tokens = block.header.text.split()
                if len(tokens) >= 2:
                    sub = tokens[1].lower()
                    if sub == "route":
                        route = _parse_static_route(block.header, result.warnings)
                        if route:
                            result.static_routes.append(route)
                    elif sub == "access-list":
                        acl = _parse_named_acl(block, result.warnings)
                        if acl:
                            result.acls.append(acl)
                    elif sub == "http" and len(tokens) >= 3:
                        http_sub = tokens[2].lower()
                        if http_sub == "server":
                            result.http_server_enabled = True
                            result.http_server_line = block.header.line_number
                        elif http_sub == "secure-server":
                            result.https_server_enabled = True
                            result.https_server_line = block.header.line_number
                    elif sub == "ssh" and len(tokens) >= 3 and tokens[2].lower() == "version":
                        try:
                            result.ssh_version = int(tokens[3])
                            result.ssh_version_line = block.header.line_number
                        except (IndexError, ValueError):
                            result.warnings.append(
                                f"Line {block.header.line_number}: "
                                f"invalid SSH version in '{block.header.text}'"
                            )

            # no ip http server / no ip http secure-server
            elif kw == "no":
                tokens = block.header.text.split()
                # tokens: ["no", "ip", "http", "server"|"secure-server"]
                if (
                    len(tokens) >= 4
                    and tokens[1].lower() == "ip"
                    and tokens[2].lower() == "http"
                ):
                    http_sub = tokens[3].lower()
                    if http_sub == "server":
                        result.http_server_enabled = False
                        result.http_server_line = block.header.line_number
                    elif http_sub == "secure-server":
                        result.https_server_enabled = False
                        result.https_server_line = block.header.line_number

            # access-list <num> permit|deny ...  (numbered ACL)
            elif kw == "access-list":
                _parse_numbered_acl_line(
                    block.header,
                    numbered_acl_entries,
                    numbered_acl_meta,
                    result.warnings,
                )

            # line vty / line con / line aux
            elif kw == "line":
                tokens = block.header.text.split()
                if len(tokens) >= 2 and tokens[1].lower() == "vty":
                    # Re-frame block so _parse_vty sees "vty 0 4" as .rest
                    vty_block = ConfigBlock(
                        header=ConfigLine(
                            text=" ".join(tokens[1:]),
                            line_number=block.header.line_number,
                            indent=0,
                        ),
                        children=block.children,
                    )
                    vty = _parse_vty(vty_block, result.warnings)
                    if vty:
                        result.vty_lines.append(vty)

        # Finalise numbered ACLs
        for name, entries in numbered_acl_entries.items():
            acl_type, first_lineno = numbered_acl_meta[name]
            result.acls.append(
                AclRule(
                    name=name,
                    acl_type=acl_type,
                    entries=tuple(entries),
                    line_number=first_lineno,
                )
            )

        return result


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------

ParserRegistry.register(CiscoIosParser.vendor, CiscoIosParser)
