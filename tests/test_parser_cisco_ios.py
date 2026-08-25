"""
Tests for the Cisco IOS configuration parser.

Covers:
- Hostname parsing
- Interface parsing (IP, mask, prefix, description, shutdown, secondary)
- Switchport (access VLAN, trunk mode, encapsulation, allowed VLANs)
- VLAN block parsing
- Static and default route parsing
- Named ACL and numbered ACL parsing
- VTY line parsing (transport, access-class, login, exec-timeout)
- Parser resilience against malformed input
- Line number preservation
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from netlint.parser.cisco_ios.models import (
    AclAction,
    TransportProtocol,
    TrunkEncapsulation,
)
from netlint.parser.cisco_ios.parser import CiscoIosParser
from netlint.parser.registry import ParserRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def parse_file(name: str):
    parser = CiscoIosParser()
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return parser.parse_text(lines)


def parse_text(text: str):
    parser = CiscoIosParser()
    return parser.parse_text(text.strip().splitlines())


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_cisco_ios_registered():
    """CiscoIosParser must be registered as 'cisco-ios'."""
    cls = ParserRegistry.get("cisco-ios")
    assert cls is CiscoIosParser


# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------


def test_hostname_clean():
    cfg = parse_file("clean.cfg")
    assert cfg.hostname == "CORE-SW-01"


def test_hostname_line_number():
    cfg = parse_file("clean.cfg")
    assert cfg.hostname_line is not None
    assert cfg.hostname_line > 0


def test_hostname_simple():
    cfg = parse_text("hostname R1")
    assert cfg.hostname == "R1"


# ---------------------------------------------------------------------------
# Interface — basic fields
# ---------------------------------------------------------------------------


def test_interface_count_clean():
    cfg = parse_file("clean.cfg")
    names = [i.name for i in cfg.interfaces]
    assert "Loopback0" in names
    assert "GigabitEthernet0/0" in names
    assert "GigabitEthernet0/1" in names
    assert "Vlan10" in names


def test_interface_ip_address():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.ip_address == ipaddress.IPv4Address("203.0.113.2")
    assert iface.subnet_mask == "255.255.255.252"
    assert iface.prefix_length == 30


def test_interface_ip_network_derived():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.ip_network == ipaddress.IPv4Network("203.0.113.0/30")


def test_interface_loopback_slash32():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("Loopback0")
    assert iface is not None
    assert iface.prefix_length == 32
    assert iface.ip_network == ipaddress.IPv4Network("10.255.0.1/32")


def test_interface_description():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.description == "Uplink to ISP"


def test_interface_no_shutdown_default():
    """Interfaces with 'no shutdown' should have shutdown=False."""
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.shutdown is False


def test_interface_shutdown_state():
    cfg = parse_text("""
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 shutdown
""")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.shutdown is True


def test_interface_line_number_preserved():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.line_number > 0


# ---------------------------------------------------------------------------
# Interface — abbreviation expansion
# ---------------------------------------------------------------------------


def test_interface_abbreviation_gi():
    cfg = parse_text("""
interface Gi0/0
 ip address 10.0.0.1 255.255.255.0
""")
    assert cfg.get_interface("GigabitEthernet0/0") is not None


def test_interface_abbreviation_lo():
    cfg = parse_text("""
interface Lo0
 ip address 10.255.0.1 255.255.255.255
""")
    assert cfg.get_interface("Loopback0") is not None


# ---------------------------------------------------------------------------
# Switchport
# ---------------------------------------------------------------------------


def test_switchport_access_vlan():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/2")
    assert iface is not None
    assert iface.access_vlan == 30


def test_switchport_trunk_mode():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/3")
    assert iface is not None
    assert iface.trunk_mode is True


def test_switchport_trunk_encapsulation():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/3")
    assert iface is not None
    assert iface.trunk_encapsulation == TrunkEncapsulation.DOT1Q


def test_switchport_trunk_allowed_vlans():
    cfg = parse_file("clean.cfg")
    iface = cfg.get_interface("GigabitEthernet0/3")
    assert iface is not None
    assert iface.trunk_allowed_vlans == "10,20,30"


# ---------------------------------------------------------------------------
# VLAN blocks
# ---------------------------------------------------------------------------


def test_vlan_count():
    cfg = parse_file("clean.cfg")
    assert len(cfg.vlans) == 3


def test_vlan_ids():
    cfg = parse_file("clean.cfg")
    ids = {v.vlan_id for v in cfg.vlans}
    assert ids == {10, 20, 30}


def test_vlan_names():
    cfg = parse_file("clean.cfg")
    by_id = {v.vlan_id: v for v in cfg.vlans}
    assert by_id[10].name == "MANAGEMENT"
    assert by_id[20].name == "SERVERS"
    assert by_id[30].name == "USERS"


def test_vlan_line_number():
    cfg = parse_file("clean.cfg")
    for vlan in cfg.vlans:
        assert vlan.line_number > 0


def test_vlan_fixture():
    cfg = parse_file("vlans.cfg")
    ids = {v.vlan_id for v in cfg.vlans}
    assert 10 in ids
    assert 20 in ids
    assert 99 not in ids  # VLAN 99 used but not declared


# ---------------------------------------------------------------------------
# Static routes
# ---------------------------------------------------------------------------


def test_default_route_clean():
    cfg = parse_file("clean.cfg")
    assert len(cfg.default_routes) == 1
    dr = cfg.default_routes[0]
    assert dr.network == ipaddress.IPv4Network("0.0.0.0/0")
    assert dr.next_hop == ipaddress.IPv4Address("203.0.113.1")


def test_specific_route_clean():
    cfg = parse_file("clean.cfg")
    specific = [r for r in cfg.static_routes if not r.is_default]
    assert len(specific) == 1
    assert specific[0].network == ipaddress.IPv4Network("10.30.0.0/16")


def test_multiple_default_routes():
    cfg = parse_file("routing.cfg")
    defaults = cfg.default_routes
    assert len(defaults) == 2


def test_floating_static_admin_distance():
    cfg = parse_file("routing.cfg")
    defaults = cfg.default_routes
    distances = {r.admin_distance for r in defaults}
    assert 1 in distances
    assert 200 in distances


def test_route_via_exit_interface():
    cfg = parse_file("routing.cfg")
    iface_routes = [r for r in cfg.static_routes if r.exit_interface is not None]
    assert any(r.exit_interface == "GigabitEthernet0/2" for r in iface_routes)


def test_route_line_numbers():
    cfg = parse_file("routing.cfg")
    for route in cfg.static_routes:
        assert route.line_number > 0


# ---------------------------------------------------------------------------
# Named ACLs
# ---------------------------------------------------------------------------


def test_named_acl_exists():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None


def test_named_acl_type():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None
    assert acl.acl_type == "extended"


def test_named_acl_entry_count():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None
    assert len(acl.entries) == 2


def test_named_acl_first_entry():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None
    first = acl.entries[0]
    assert first.action == AclAction.PERMIT
    assert first.protocol == "tcp"
    assert first.sequence == 10
    assert first.destination_port == "eq 22"


def test_named_acl_deny_any_any():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None
    last = acl.entries[-1]
    assert last.action == AclAction.DENY
    assert last.source_is_any
    assert last.destination_is_any


def test_named_acl_line_number():
    cfg = parse_file("clean.cfg")
    acl = cfg.get_acl("MGMT_ACCESS")
    assert acl is not None
    assert acl.line_number > 0
    for entry in acl.entries:
        assert entry.line_number > 0


# ---------------------------------------------------------------------------
# Numbered ACLs
# ---------------------------------------------------------------------------


def test_numbered_acl_parsed():
    cfg = parse_text("""
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 deny any
""")
    acl = cfg.get_acl("10")
    assert acl is not None
    assert acl.acl_type == "numbered-standard"
    assert len(acl.entries) == 2


def test_numbered_extended_acl():
    cfg = parse_text("""
access-list 100 permit tcp 10.0.0.0 0.0.0.255 any eq 80
access-list 100 deny ip any any
""")
    acl = cfg.get_acl("100")
    assert acl is not None
    assert acl.acl_type == "numbered-extended"
    assert acl.entries[0].protocol == "tcp"
    assert acl.entries[0].destination_port == "eq 80"


# ---------------------------------------------------------------------------
# VTY lines
# ---------------------------------------------------------------------------


def test_vty_exists():
    cfg = parse_file("clean.cfg")
    assert len(cfg.vty_lines) == 1


def test_vty_range():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.first == 0
    assert vty.last == 4


def test_vty_transport_ssh_only():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.transport_input == (TransportProtocol.SSH,)


def test_vty_transport_ssh_and_telnet():
    cfg = parse_file("duplicate-ip.cfg")
    vty = cfg.vty_lines[0]
    assert TransportProtocol.SSH in vty.transport_input
    assert TransportProtocol.TELNET in vty.transport_input


def test_vty_access_class():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.access_class_in == "MGMT_ACCESS"


def test_vty_login():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.login == "local"


def test_vty_exec_timeout():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.exec_timeout == (10, 0)


def test_vty_line_number():
    cfg = parse_file("clean.cfg")
    vty = cfg.vty_lines[0]
    assert vty.line_number > 0


# ---------------------------------------------------------------------------
# Duplicate IPs fixture
# ---------------------------------------------------------------------------


def test_duplicate_ip_interfaces_parsed():
    cfg = parse_file("duplicate-ip.cfg")
    ips = [i.ip_address for i in cfg.interfaces if i.ip_address is not None]
    # 10.0.0.1 appears twice
    assert ips.count(ipaddress.IPv4Address("10.0.0.1")) == 2
    # 192.168.1.1 appears twice
    assert ips.count(ipaddress.IPv4Address("192.168.1.1")) == 2


# ---------------------------------------------------------------------------
# Malformed config — parser must NOT crash
# ---------------------------------------------------------------------------


def test_malformed_no_crash():
    """Parser must return a ParsedConfig (not raise) for malformed input."""
    cfg = parse_file("malformed.cfg")
    assert cfg is not None


def test_malformed_warnings_recorded():
    """Malformed lines should produce warnings, not exceptions."""
    cfg = parse_file("malformed.cfg")
    assert len(cfg.warnings) > 0


def test_malformed_valid_parts_still_parsed():
    """Valid constructs in an otherwise malformed file must still be parsed."""
    cfg = parse_file("malformed.cfg")
    assert cfg.hostname == "MALFORMED-ROUTER"
    # The valid VTY block at the end should still be parsed
    assert len(cfg.vty_lines) >= 1


def test_malformed_incomplete_ip_address():
    """'ip address 10.0.0.1' (missing mask) should warn, not crash."""
    cfg = parse_text("""
hostname TEST
interface GigabitEthernet0/0
 ip address 10.0.0.1
""")
    assert len(cfg.warnings) > 0
    iface = cfg.get_interface("GigabitEthernet0/0")
    assert iface is not None
    assert iface.ip_address is None  # should not be set on malformed input


def test_empty_config_raises():
    """An empty config should raise ParseError."""
    from netlint.exceptions import ParseError

    parser = CiscoIosParser()
    with pytest.raises(ParseError):
        parser.parse_text([])


# ---------------------------------------------------------------------------
# ParsedConfig helpers
# ---------------------------------------------------------------------------


def test_get_interface_case_insensitive():
    cfg = parse_file("clean.cfg")
    assert cfg.get_interface("gigabitethernet0/0") is not None
    assert cfg.get_interface("GIGABITETHERNET0/0") is not None


def test_get_acl_case_insensitive():
    cfg = parse_file("clean.cfg")
    assert cfg.get_acl("mgmt_access") is not None
    assert cfg.get_acl("MGMT_ACCESS") is not None


def test_default_routes_property():
    cfg = parse_file("routing.cfg")
    for r in cfg.default_routes:
        assert r.is_default is True
