"""
Edge-case regression tests for the netlint parser and rules.

These tests use the nasty fixture configs to verify:
- No crashes on any real-world config pattern
- No false positives on VRF same-IP
- VRF ip route lines silently skipped (no warning noise)
- Subinterfaces parsed without errors
- Secondary IP addresses don't cause duplicate-IP findings
- ACL remark lines don't crash the parser
- Multiple VTY sections correctly parsed
- Unknown IOS commands silently skipped
- Incomplete configs produce warnings, not crashes
- Empty interface/ACL/VTY blocks don't crash
- Large configs parse fast (< 500ms)
- Precise subnet overlap math: /29 contains /30 → overlap; adjacent /30s → no overlap
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from netlint.analyzer.analyzer import Analyzer
from netlint.models.finding import Severity
from netlint.parser.cisco_ios.parser import CiscoIosParser
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_registry():
    RuleRegistry._reset()
    yield
    RuleRegistry._reset()


def parse(name: str):
    return CiscoIosParser().parse_text(
        (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    )


def analyze(name: str):
    return Analyzer().run(FIXTURES / name)


# ---------------------------------------------------------------------------
# No crashes — every fixture must complete without exception
# ---------------------------------------------------------------------------


class TestNoCrashes:
    @pytest.mark.parametrize("fixture", [
        "edge_vrf.cfg",
        "edge_subinterfaces.cfg",
        "edge_secondary_ip.cfg",
        "edge_acl.cfg",
        "edge_vty_multi.cfg",
        "edge_weird_names.cfg",
        "edge_unknown_commands.cfg",
        "edge_incomplete.cfg",
        "edge_overlapping_slash30.cfg",
        "large.cfg",
    ])
    def test_parse_does_not_crash(self, fixture):
        parsed = parse(fixture)
        assert parsed is not None

    @pytest.mark.parametrize("fixture", [
        "edge_vrf.cfg",
        "edge_subinterfaces.cfg",
        "edge_secondary_ip.cfg",
        "edge_acl.cfg",
        "edge_vty_multi.cfg",
        "edge_weird_names.cfg",
        "edge_unknown_commands.cfg",
        "edge_incomplete.cfg",
        "edge_overlapping_slash30.cfg",
        "large.cfg",
    ])
    def test_analyze_does_not_crash(self, fixture):
        result = analyze(fixture)
        assert result is not None


# ---------------------------------------------------------------------------
# VRF — same IP in different VRFs must NOT trigger NET001
# ---------------------------------------------------------------------------


class TestVRF:
    def test_vrf_same_ip_no_net001(self):
        """192.168.1.1 on Gi0/1 (CUST-A) and Gi0/2 (CUST-B) — different VRFs."""
        result = analyze("edge_vrf.cfg")
        net001 = [f for f in result.findings if f.rule_id == "NET001"]
        assert net001 == [], (
            f"NET001 should not fire for same IP in different VRFs, "
            f"but got: {[f.message for f in net001]}"
        )

    def test_vrf_route_no_warning(self):
        """'ip route vrf CUST-A ...' must be silently skipped, not warned."""
        parsed = parse("edge_vrf.cfg")
        vrf_warnings = [w for w in parsed.warnings if "vrf" in w.lower()]
        assert vrf_warnings == [], (
            f"ip route vrf should be silently skipped, got: {vrf_warnings}"
        )

    def test_vrf_iface_vrf_field_set(self):
        """Interfaces with 'ip vrf forwarding' must have vrf field set."""
        parsed = parse("edge_vrf.cfg")
        gi1 = parsed.get_interface("GigabitEthernet0/1")
        gi2 = parsed.get_interface("GigabitEthernet0/2")
        assert gi1 is not None
        assert gi2 is not None
        assert gi1.vrf == "CUST-A"
        assert gi2.vrf == "CUST-B"

    def test_global_iface_has_no_vrf(self):
        parsed = parse("edge_vrf.cfg")
        gi0 = parsed.get_interface("GigabitEthernet0/0")
        assert gi0 is not None
        assert gi0.vrf is None


# ---------------------------------------------------------------------------
# Subinterfaces — dot in name, parent has no IP
# ---------------------------------------------------------------------------


class TestSubinterfaces:
    def test_subinterfaces_parsed(self):
        parsed = parse("edge_subinterfaces.cfg")
        names = [i.name for i in parsed.interfaces]
        assert "GigabitEthernet0/0.10" in names
        assert "GigabitEthernet0/0.20" in names
        assert "GigabitEthernet0/0.30" in names

    def test_parent_interface_no_ip(self):
        parsed = parse("edge_subinterfaces.cfg")
        parent = parsed.get_interface("GigabitEthernet0/0")
        assert parent is not None
        assert parent.ip_address is None

    def test_subinterfaces_have_correct_ips(self):
        import ipaddress
        parsed = parse("edge_subinterfaces.cfg")
        sub10 = parsed.get_interface("GigabitEthernet0/0.10")
        assert sub10 is not None
        assert sub10.ip_address == ipaddress.IPv4Address("10.10.10.1")

    def test_no_false_positive_findings(self):
        result = analyze("edge_subinterfaces.cfg")
        assert result.findings == ()


# ---------------------------------------------------------------------------
# Secondary IPs — must not cause duplicate-IP findings
# ---------------------------------------------------------------------------


class TestSecondaryIP:
    def test_secondary_ip_no_net001(self):
        """Primary + secondary on same interface must not trigger NET001."""
        result = analyze("edge_secondary_ip.cfg")
        net001 = [f for f in result.findings if f.rule_id == "NET001"]
        assert net001 == []

    def test_secondary_ip_no_net002(self):
        """10.0.0.0/24 and 10.0.1.0/24 are adjacent, not overlapping."""
        result = analyze("edge_secondary_ip.cfg")
        net002 = [f for f in result.findings if f.rule_id == "NET002"]
        assert net002 == []

    def test_secondary_parsed(self):
        """Secondary IP keyword must not crash parser."""
        parsed = parse("edge_secondary_ip.cfg")
        gi0 = parsed.get_interface("GigabitEthernet0/0")
        assert gi0 is not None
        assert gi0.ip_address is not None  # primary IP parsed


# ---------------------------------------------------------------------------
# ACL edge cases
# ---------------------------------------------------------------------------


class TestACLEdgeCases:
    def test_acl_remark_does_not_crash(self):
        """Remark lines inside ACL blocks must be silently skipped."""
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("WITH_REMARKS")
        assert acl is not None

    def test_acl_remark_not_counted_as_entry(self):
        """Remark lines must not be counted as ACE entries."""
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("WITH_REMARKS")
        assert acl is not None
        # Only the 2 permit/deny entries, not the 2 remarks
        assert len(acl.entries) == 2

    def test_named_standard_acl_parsed(self):
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("MGMT_HOSTS")
        assert acl is not None
        assert acl.acl_type == "standard"

    def test_named_extended_acl_with_range(self):
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("INBOUND_POLICY")
        assert acl is not None
        range_entry = next(
            (e for e in acl.entries if e.destination_port and "range" in e.destination_port),
            None
        )
        assert range_entry is not None

    def test_empty_acl_parsed(self):
        """An ACL with no entries must parse without crashing."""
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("EMPTY_ACL")
        assert acl is not None
        assert len(acl.entries) == 0

    def test_numbered_standard_acl(self):
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("10")
        assert acl is not None
        assert acl.acl_type == "numbered-standard"

    def test_numbered_extended_acl(self):
        parsed = parse("edge_acl.cfg")
        acl = parsed.get_acl("100")
        assert acl is not None
        assert acl.acl_type == "numbered-extended"

    def test_no_findings_on_acl_fixture(self):
        result = analyze("edge_acl.cfg")
        # ACL fixture has proper SSH-only VTY with access-class
        unexpected = [f for f in result.findings if f.rule_id in ("NET001", "NET002", "VLAN001")]
        assert unexpected == []


# ---------------------------------------------------------------------------
# Multiple VTY sections
# ---------------------------------------------------------------------------


class TestMultipleVTY:
    def test_two_vty_blocks_parsed(self):
        parsed = parse("edge_vty_multi.cfg")
        assert len(parsed.vty_lines) == 2

    def test_vty_0_4_correct(self):
        parsed = parse("edge_vty_multi.cfg")
        vty_0_4 = next((v for v in parsed.vty_lines if v.first == 0), None)
        assert vty_0_4 is not None
        assert vty_0_4.last == 4
        assert vty_0_4.access_class_in == "MGMT_ACL"

    def test_vty_5_15_correct(self):
        parsed = parse("edge_vty_multi.cfg")
        vty_5_15 = next((v for v in parsed.vty_lines if v.first == 5), None)
        assert vty_5_15 is not None
        assert vty_5_15.last == 15

    def test_no_false_sec001(self):
        """SSH-only VTY must not trigger SEC001."""
        result = analyze("edge_vty_multi.cfg")
        sec001 = [f for f in result.findings if f.rule_id == "SEC001"]
        assert sec001 == []

    def test_no_false_sec003(self):
        """Both VTY blocks have access-class — SEC003 must not fire."""
        result = analyze("edge_vty_multi.cfg")
        sec003 = [f for f in result.findings if f.rule_id == "SEC003"]
        assert sec003 == []

    def test_con_and_aux_not_parsed_as_vty(self):
        """line con 0 and line aux 0 must not appear in vty_lines."""
        parsed = parse("edge_vty_multi.cfg")
        for vty in parsed.vty_lines:
            assert vty.first >= 0 and vty.last <= 15


# ---------------------------------------------------------------------------
# Weird interface names
# ---------------------------------------------------------------------------


class TestWeirdInterfaceNames:
    def test_port_channel_parsed(self):
        parsed = parse("edge_weird_names.cfg")
        assert parsed.get_interface("Port-channel1") is not None

    def test_tunnel_parsed(self):
        parsed = parse("edge_weird_names.cfg")
        assert parsed.get_interface("Tunnel0") is not None

    def test_serial_parsed(self):
        parsed = parse("edge_weird_names.cfg")
        assert parsed.get_interface("Serial1/0") is not None

    def test_null_interface_parsed(self):
        parsed = parse("edge_weird_names.cfg")
        assert parsed.get_interface("Null0") is not None

    def test_multiple_loopbacks_parsed(self):
        parsed = parse("edge_weird_names.cfg")
        assert parsed.get_interface("Loopback0") is not None
        assert parsed.get_interface("Loopback100") is not None

    def test_no_crashes(self):
        result = analyze("edge_weird_names.cfg")
        assert result is not None


# ---------------------------------------------------------------------------
# Unknown IOS commands
# ---------------------------------------------------------------------------


class TestUnknownCommands:
    def test_aaa_does_not_crash(self):
        parsed = parse("edge_unknown_commands.cfg")
        assert parsed is not None

    def test_ospf_does_not_crash(self):
        parsed = parse("edge_unknown_commands.cfg")
        assert parsed.hostname == "UNKNOWN-CMD-ROUTER"

    def test_no_http_server(self):
        """'no ip http server' must set http_server_enabled=False."""
        parsed = parse("edge_unknown_commands.cfg")
        assert parsed.http_server_enabled is False

    def test_no_warnings_for_unknown_cmds(self):
        """Unknown top-level commands must not produce parser warnings."""
        parsed = parse("edge_unknown_commands.cfg")
        # The only acceptable warnings are for genuinely malformed lines,
        # not for valid IOS commands that netlint doesn't model
        assert len(parsed.warnings) == 0

    def test_ssh_vty_no_sec001(self):
        result = analyze("edge_unknown_commands.cfg")
        assert all(f.rule_id != "SEC001" for f in result.findings)

    def test_clean_analysis(self):
        result = analyze("edge_unknown_commands.cfg")
        assert result.findings == ()


# ---------------------------------------------------------------------------
# Incomplete / malformed config
# ---------------------------------------------------------------------------


class TestIncompleteConfig:
    def test_empty_interface_block_no_crash(self):
        parsed = parse("edge_incomplete.cfg")
        # Gi0/0 has no sub-commands — must parse as interface with defaults
        gi0 = parsed.get_interface("GigabitEthernet0/0")
        assert gi0 is not None
        assert gi0.ip_address is None

    def test_malformed_route_produces_warning(self):
        parsed = parse("edge_incomplete.cfg")
        route_warnings = [w for w in parsed.warnings if "ip route" in w]
        assert len(route_warnings) >= 1

    def test_empty_acl_no_crash(self):
        parsed = parse("edge_incomplete.cfg")
        acl = parsed.get_acl("EMPTY_ACL")
        assert acl is not None
        assert len(acl.entries) == 0

    def test_empty_vty_block_no_crash(self):
        parsed = parse("edge_incomplete.cfg")
        assert len(parsed.vty_lines) == 1
        vty = parsed.vty_lines[0]
        assert vty.transport_input == ()

    def test_vlan_without_name_parsed(self):
        parsed = parse("edge_incomplete.cfg")
        vids = {v.vlan_id for v in parsed.vlans}
        assert 10 in vids  # vlan 10 has no name
        assert 20 in vids  # vlan 20 has name DEFINED


# ---------------------------------------------------------------------------
# Precise subnet overlap calculations
# ---------------------------------------------------------------------------


class TestPreciseOverlap:
    def test_slash29_contains_slash30_fires(self):
        """/29 (0-7) and /30 (0-3) overlap — NET002 must fire."""
        result = analyze("edge_overlapping_slash30.cfg")
        net002 = [f for f in result.findings if f.rule_id == "NET002"]
        involved = {f.message for f in net002}
        # Gi0/0 (/29) and Gi0/1 (/30) must be in findings
        assert any("GigabitEthernet0/0" in m and "GigabitEthernet0/1" in m for m in involved)

    def test_adjacent_slash30_does_not_fire(self):
        """10.0.0.0/30 and 10.0.0.4/30 are adjacent, not overlapping."""
        result = analyze("edge_overlapping_slash30.cfg")
        net002 = [f for f in result.findings if f.rule_id == "NET002"]
        # Gi0/1 (/30 = 0-3) and Gi0/2 (/30 = 4-7) must NOT appear together
        for f in net002:
            assert not (
                "GigabitEthernet0/1" in f.message and "GigabitEthernet0/2" in f.message
            ), f"Adjacent /30s incorrectly flagged as overlapping: {f.message}"

    def test_slash32_inside_slash24_fires(self):
        """Loopback1 /32 (10.1.1.1) is inside Gi0/3 /24 (10.1.1.0/24)."""
        result = analyze("edge_overlapping_slash30.cfg")
        net002 = [f for f in result.findings if f.rule_id == "NET002"]
        assert any(
            "Loopback1" in f.message or "GigabitEthernet0/3" in f.message
            for f in net002
        )

    def test_overlap_findings_are_high_severity(self):
        result = analyze("edge_overlapping_slash30.cfg")
        for f in result.findings:
            if f.rule_id == "NET002":
                assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Large config performance
# ---------------------------------------------------------------------------


class TestLargeConfig:
    def test_large_config_parses_fast(self):
        """1274-line config with 200 VLANs and 200 interfaces must parse in < 500ms."""
        t0 = time.perf_counter()
        parsed = parse("large.cfg")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"Parse took {elapsed_ms:.0f}ms (limit 500ms)"
        assert len(parsed.interfaces) > 200
        assert len(parsed.vlans) == 200

    def test_large_config_analysis_fast(self):
        """Full analysis of large config must complete in < 2000ms."""
        t0 = time.perf_counter()
        result = analyze("large.cfg")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 2000, f"Analysis took {elapsed_ms:.0f}ms (limit 2000ms)"
        assert result is not None

    def test_large_config_no_crash(self):
        result = analyze("large.cfg")
        assert result.findings == ()
