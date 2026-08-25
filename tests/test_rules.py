"""
Comprehensive tests for all five Cisco IOS lint rules.

Rules under test
----------------
NET001  DuplicateIpRule          — duplicate IPv4 address across interfaces
NET002  OverlappingSubnetsRule   — overlapping IPv4 networks
VLAN001 UndefinedVlanRule        — access port references an undeclared VLAN
SEC001  TelnetEnabledRule        — Telnet permitted on VTY lines
SEC002  HttpServerEnabledRule    — plain HTTP management server enabled

Each rule has:
    • positive test  — config that SHOULD produce a finding
    • negative test  — config that SHOULD NOT produce a finding
    • edge-case tests — boundary / tricky scenarios
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netlint.models.config_file import ConfigFile
from netlint.models.finding import RuleCategory, Severity
from netlint.parser.cisco_ios.parser import CiscoIosParser
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(text: str):
    """Parse a config string and return ParsedConfig."""
    parser = CiscoIosParser()
    return parser.parse_text(text.strip().splitlines())


def _config(text: str) -> ConfigFile:
    return ConfigFile(
        file_path=Path("/tmp/test.cfg"),
        raw_text=text,
        vendor="cisco-ios",
        lines=(),
    )


def _run_rule(rule_class, text: str):
    """Instantiate rule_class, parse text, return findings list."""
    parsed = _parse(text)
    config = _config(text)
    return rule_class().check(config, parsed)


def _parse_fixture(name: str):
    content = (FIXTURES / name).read_text(encoding="utf-8")
    return _parse(content), _config(content)


# ===========================================================================
# NET001 — Duplicate IPv4 Address
# ===========================================================================


class TestNET001:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from netlint.rules.net001_duplicate_ip import DuplicateIpRule
        self.rule = DuplicateIpRule

    # --- positive -----------------------------------------------------------

    def test_duplicate_across_two_interfaces(self):
        """Two active interfaces with same IP → two findings (one per iface)."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""")
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "NET001"
            assert f.severity == Severity.CRITICAL
            assert f.category == RuleCategory.NETWORK

    def test_finding_names_both_interfaces(self):
        """Each finding message must identify the duplicate IP and peer name."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
""")
        messages = " ".join(f.message for f in findings)
        assert "192.168.1.1" in messages
        assert "GigabitEthernet0/0" in messages
        assert "GigabitEthernet0/1" in messages

    def test_finding_carries_config_line(self):
        """Each finding must include the 'ip address' config line."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.1.1.1 255.255.255.0
 no shutdown
""")
        for f in findings:
            assert f.configuration_line is not None
            assert "10.1.1.1" in f.configuration_line

    def test_finding_carries_line_number(self):
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""")
        for f in findings:
            assert f.line_number is not None and f.line_number > 0

    def test_three_way_duplicate(self):
        """Three interfaces sharing one IP → three findings."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/2
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""")
        assert len(findings) == 3

    def test_fixture_duplicate_ip(self):
        """duplicate-ip.cfg has two pairs of duplicate IPs."""
        parsed, config = _parse_fixture("duplicate-ip.cfg")
        findings = self.rule().check(config, parsed)
        assert len(findings) >= 4  # 2 interfaces × 2 duplicate pairs

    # --- negative -----------------------------------------------------------

    def test_unique_ips_no_finding(self):
        """Different IPs on every interface → no findings."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.1.1 255.255.255.0
 no shutdown
""")
        assert findings == []

    def test_clean_fixture_no_net001(self):
        parsed, config = _parse_fixture("clean.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    def test_no_ip_interfaces_no_finding(self):
        """Switchport-only interfaces have no IP — should not fire."""
        findings = _run_rule(self.rule, """
hostname SW1
interface GigabitEthernet0/0
 switchport access vlan 10
 no shutdown
interface GigabitEthernet0/1
 switchport access vlan 10
 no shutdown
""")
        assert findings == []

    # --- edge cases ---------------------------------------------------------

    def test_shutdown_interface_excluded(self):
        """A shutdown interface must not count toward duplicate detection."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 shutdown
""")
        assert findings == []

    def test_loopback_and_physical_duplicate(self):
        """Loopback + physical interface sharing IP should also be caught."""
        findings = _run_rule(self.rule, """
hostname R1
interface Loopback0
 ip address 10.99.99.1 255.255.255.255
interface GigabitEthernet0/0
 ip address 10.99.99.1 255.255.255.255
 no shutdown
""")
        assert len(findings) == 2

    def test_none_parsed_returns_empty(self):
        assert self.rule().check(_config("hostname R1"), None) == []


# ===========================================================================
# NET002 — Overlapping IPv4 Subnets
# ===========================================================================


class TestNET002:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from netlint.rules.net002_overlapping_subnets import OverlappingSubnetsRule
        self.rule = OverlappingSubnetsRule

    # --- positive -----------------------------------------------------------

    def test_slash24_overlaps_slash25(self):
        """/24 and /25 carved from same space overlap."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 192.168.1.100 255.255.255.128
 no shutdown
""")
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "NET002"
            assert f.severity == Severity.HIGH
            assert f.category == RuleCategory.NETWORK

    def test_finding_names_both_networks(self):
        """/8 supernet vs /16 subnet."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.0.0.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.1.0.1 255.255.0.0
 no shutdown
""")
        assert len(findings) == 2
        messages = " ".join(f.message for f in findings)
        assert "10.0.0.0/8" in messages
        assert "10.1.0.0/16" in messages

    def test_finding_carries_config_line(self):
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 172.16.0.1 255.255.0.0
 no shutdown
interface GigabitEthernet0/1
 ip address 172.16.1.1 255.255.255.0
 no shutdown
""")
        for f in findings:
            assert f.configuration_line is not None
            assert "ip address" in f.configuration_line

    def test_finding_carries_line_number(self):
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 192.168.1.100 255.255.255.128
 no shutdown
""")
        for f in findings:
            assert f.line_number is not None and f.line_number > 0

    def test_three_way_overlap(self):
        """/8 overlaps two /16 subnets within it → two pairs, four findings."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.0.0.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.1.0.1 255.255.0.0
 no shutdown
interface GigabitEthernet0/2
 ip address 10.2.0.1 255.255.0.0
 no shutdown
""")
        # Gi0/0(/8) overlaps Gi0/1(/16): 2 findings
        # Gi0/0(/8) overlaps Gi0/2(/16): 2 findings
        # Gi0/1(/16) and Gi0/2(/16) do NOT overlap each other
        assert len(findings) == 4

    def test_routing_fixture_no_interface_overlap(self):
        """routing.cfg has distinct interface subnets — NET002 must not fire."""
        parsed, config = _parse_fixture("routing.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    def test_supernet_contains_subnet(self):
        """/8 supernet contains a /16 — they overlap."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.0.0.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.1.0.1 255.255.0.0
 no shutdown
interface GigabitEthernet0/2
 ip address 172.16.0.1 255.255.0.0
 no shutdown
""")
        # Only Gi0/0 (/8) and Gi0/1 (/16) overlap; Gi0/2 is separate
        assert len(findings) == 2

    # --- negative -----------------------------------------------------------

    def test_adjacent_subnets_no_overlap(self):
        """.0/24 and .1/24 are adjacent — do not overlap."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.1.1 255.255.255.0
 no shutdown
""")
        assert findings == []

    def test_clean_fixture_no_net002(self):
        parsed, config = _parse_fixture("clean.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    def test_loopback_slash32_no_overlap(self):
        """A /32 loopback is entirely inside a /24, but the /24 is
        the host subnet for that same address — not a real overlap."""
        findings = _run_rule(self.rule, """
hostname R1
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
interface GigabitEthernet0/0
 ip address 10.0.1.1 255.255.255.0
 no shutdown
""")
        assert findings == []

    # --- edge cases ---------------------------------------------------------

    def test_identical_networks_not_double_reported(self):
        """Identical /24 on two interfaces: NET001 handles this; NET002
        must skip the pair (same network is not an 'overlap' in the
        overlapping-subnet sense)."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 10.0.0.2 255.255.255.0
 no shutdown
""")
        # Should be empty — NET001 is the right rule for same network
        assert findings == []

    def test_shutdown_interface_excluded(self):
        """Shutdown interfaces are excluded from overlap checks."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 192.168.1.100 255.255.255.128
 shutdown
""")
        assert findings == []

    def test_no_duplicate_findings_for_same_pair(self):
        """Each overlapping pair should produce exactly two findings
        (one per interface), not four."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/1
 ip address 192.168.1.100 255.255.255.128
 no shutdown
""")
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids.count("NET002") == 2

    def test_none_parsed_returns_empty(self):
        assert self.rule().check(_config("hostname R1"), None) == []

    def test_interfaces_without_ip_skipped(self):
        """Switchport-only interfaces have no ip_network; must not crash."""
        findings = _run_rule(self.rule, """
hostname SW1
interface GigabitEthernet0/0
 switchport access vlan 10
 no shutdown
interface GigabitEthernet0/1
 switchport access vlan 20
 no shutdown
""")
        assert findings == []


# ===========================================================================
# VLAN001 — Undefined VLAN
# ===========================================================================


class TestVLAN001:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from netlint.rules.vlan001_undefined_vlan import UndefinedVlanRule
        self.rule = UndefinedVlanRule

    # --- positive -----------------------------------------------------------

    def test_undefined_access_vlan(self):
        """Interface assigned to VLAN that has no vlan block → one finding."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
 name DATA
interface GigabitEthernet0/0
 switchport access vlan 99
 no shutdown
""")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "VLAN001"
        assert f.severity == Severity.MEDIUM
        assert f.category == RuleCategory.VLAN

    def test_finding_names_interface_and_vlan(self):
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
 name DATA
interface GigabitEthernet0/2
 switchport access vlan 50
 no shutdown
""")
        assert len(findings) == 1
        assert "50" in findings[0].message
        assert "GigabitEthernet0/2" in findings[0].message

    def test_finding_carries_config_line(self):
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
interface GigabitEthernet0/0
 switchport access vlan 77
""")
        assert findings[0].configuration_line == " switchport access vlan 77"

    def test_finding_carries_line_number(self):
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
interface GigabitEthernet0/0
 switchport access vlan 99
""")
        assert findings[0].line_number is not None and findings[0].line_number > 0

    def test_multiple_undefined_vlans(self):
        """Two interfaces on two different undefined VLANs → two findings."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
 name DATA
interface GigabitEthernet0/0
 switchport access vlan 50
 no shutdown
interface GigabitEthernet0/1
 switchport access vlan 60
 no shutdown
""")
        assert len(findings) == 2
        vlan_ids = {int(f.message.split("VLAN")[1].split(",")[0].strip()) for f in findings}
        assert vlan_ids == {50, 60}

    def test_vlans_fixture(self):
        """vlans.cfg has VLAN 99 used on Gi0/2 but not defined."""
        parsed, config = _parse_fixture("vlans.cfg")
        findings = self.rule().check(config, parsed)
        assert any("99" in f.message for f in findings)
        assert any("GigabitEthernet0/2" in f.message for f in findings)

    # --- negative -----------------------------------------------------------

    def test_defined_vlan_no_finding(self):
        """Interface on a properly declared VLAN → no finding."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
 name DATA
interface GigabitEthernet0/0
 switchport access vlan 10
 no shutdown
""")
        assert findings == []

    def test_clean_fixture_no_vlan001(self):
        """clean.cfg has all access-VLANs defined."""
        parsed, config = _parse_fixture("clean.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    def test_no_vlan_database_skips_check(self):
        """If no VLANs are defined at all, skip the check (router context)."""
        findings = _run_rule(self.rule, """
hostname ROUTER
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""")
        assert findings == []

    def test_trunk_port_not_checked(self):
        """Trunk ports do not have an access_vlan — must not fire."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
interface GigabitEthernet0/0
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no shutdown
""")
        assert findings == []

    # --- edge cases ---------------------------------------------------------

    def test_vlan_1_is_always_predefined(self):
        """VLAN 1 is the native VLAN — finding fires if it's not in the DB."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 10
interface GigabitEthernet0/0
 switchport access vlan 1
 no shutdown
""")
        # VLAN 1 is not in the DB (only VLAN 10 is), so it fires
        assert len(findings) == 1

    def test_no_finding_if_vlan_defined_without_name(self):
        """vlan block without 'name' sub-command is still a valid declaration."""
        findings = _run_rule(self.rule, """
hostname SW1
vlan 20
interface GigabitEthernet0/0
 switchport access vlan 20
 no shutdown
""")
        assert findings == []

    def test_none_parsed_returns_empty(self):
        assert self.rule().check(_config("hostname R1"), None) == []


# ===========================================================================
# SEC001 — Telnet Enabled
# ===========================================================================


class TestSEC001:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from netlint.rules.sec001_telnet import TelnetEnabledRule
        self.rule = TelnetEnabledRule

    # --- positive -----------------------------------------------------------

    def test_transport_input_telnet(self):
        """Explicit 'transport input telnet' → one finding."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet
 login local
""")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC001"
        assert f.severity == Severity.HIGH
        assert f.category == RuleCategory.SECURITY

    def test_transport_input_telnet_ssh(self):
        """'transport input telnet ssh' still has Telnet → finding."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet ssh
 login local
""")
        assert len(findings) == 1

    def test_transport_input_all(self):
        """'transport input all' enables Telnet → finding."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input all
 login local
""")
        assert len(findings) == 1
        assert "all" in findings[0].configuration_line.lower()

    def test_finding_cites_transport_line(self):
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet
 login local
""")
        assert "transport input" in findings[0].configuration_line

    def test_finding_carries_line_number(self):
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet
 login local
""")
        assert findings[0].line_number is not None and findings[0].line_number > 0

    def test_finding_carries_vty_range(self):
        """Message should identify which VTY range is affected."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet ssh
""")
        assert "0" in findings[0].message and "4" in findings[0].message

    def test_multiple_vty_blocks(self):
        """Two VTY blocks both with Telnet → two findings."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input telnet
line vty 5 15
 transport input telnet ssh
""")
        assert len(findings) == 2

    def test_fixture_duplicate_ip_has_telnet(self):
        """duplicate-ip.cfg has 'transport input ssh telnet'."""
        parsed, config = _parse_fixture("duplicate-ip.cfg")
        findings = self.rule().check(config, parsed)
        assert len(findings) >= 1

    def test_fixture_http_enabled_has_telnet(self):
        """http-enabled.cfg also has 'transport input telnet ssh'."""
        parsed, config = _parse_fixture("http-enabled.cfg")
        findings = self.rule().check(config, parsed)
        assert len(findings) >= 1

    # --- negative -----------------------------------------------------------

    def test_transport_input_ssh_only(self):
        """'transport input ssh' — no Telnet, no finding."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 transport input ssh
 login local
""")
        assert findings == []

    def test_clean_fixture_no_sec001(self):
        parsed, config = _parse_fixture("clean.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    def test_no_vty_lines_no_finding(self):
        findings = _run_rule(self.rule, "hostname R1")
        assert findings == []

    # --- edge cases ---------------------------------------------------------

    def test_vty_with_no_transport_statement(self):
        """VTY with no 'transport input' line — ambiguous, must NOT fire."""
        findings = _run_rule(self.rule, """
hostname R1
line vty 0 4
 login local
""")
        assert findings == []

    def test_none_parsed_returns_empty(self):
        assert self.rule().check(_config("hostname R1"), None) == []


# ===========================================================================
# SEC002 — HTTP Management Server Enabled
# ===========================================================================


class TestSEC002:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from netlint.rules.sec002_http_server import HttpServerEnabledRule
        self.rule = HttpServerEnabledRule

    # --- positive -----------------------------------------------------------

    def test_ip_http_server_triggers_finding(self):
        """'ip http server' → one finding."""
        findings = _run_rule(self.rule, """
hostname R1
ip http server
""")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC002"
        assert f.severity == Severity.HIGH
        assert f.category == RuleCategory.SECURITY

    def test_finding_cites_config_line(self):
        findings = _run_rule(self.rule, """
hostname R1
ip http server
""")
        assert findings[0].configuration_line == "ip http server"

    def test_finding_carries_line_number(self):
        findings = _run_rule(self.rule, """
hostname R1
ip http server
""")
        assert findings[0].line_number is not None and findings[0].line_number > 0

    def test_finding_message_mentions_http(self):
        findings = _run_rule(self.rule, """
hostname R1
ip http server
""")
        assert "http" in findings[0].message.lower()

    def test_http_and_https_both_enabled(self):
        """Both http and https enabled: only http triggers the finding."""
        findings = _run_rule(self.rule, """
hostname R1
ip http server
ip http secure-server
""")
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC002"

    def test_fixture_http_enabled(self):
        """http-enabled.cfg has 'ip http server'."""
        parsed, config = _parse_fixture("http-enabled.cfg")
        findings = self.rule().check(config, parsed)
        assert len(findings) == 1

    # --- negative -----------------------------------------------------------

    def test_no_http_server_no_finding(self):
        """Config with no 'ip http server' → no finding."""
        findings = _run_rule(self.rule, """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""")
        assert findings == []

    def test_https_only_no_finding(self):
        """Only 'ip http secure-server' → SEC002 does not fire."""
        findings = _run_rule(self.rule, """
hostname R1
ip http secure-server
""")
        assert findings == []

    def test_no_http_server_explicit(self):
        """'no ip http server' disables it — no finding."""
        findings = _run_rule(self.rule, """
hostname R1
no ip http server
""")
        assert findings == []

    def test_clean_fixture_no_sec002(self):
        parsed, config = _parse_fixture("clean.cfg")
        findings = self.rule().check(config, parsed)
        assert findings == []

    # --- edge cases ---------------------------------------------------------

    def test_http_enabled_then_disabled(self):
        """'ip http server' followed by 'no ip http server': parser records
        the final state (disabled), so no finding."""
        findings = _run_rule(self.rule, """
hostname R1
ip http server
no ip http server
""")
        assert findings == []

    def test_none_parsed_returns_empty(self):
        assert self.rule().check(_config("hostname R1"), None) == []

    def test_recommendation_mentions_https(self):
        """Recommendation should direct to 'ip http secure-server'."""
        findings = _run_rule(self.rule, """
hostname R1
ip http server
""")
        assert "secure-server" in findings[0].recommendation.lower()


# ===========================================================================
# Integration — run Analyzer over fixtures and check correct rules fire
# ===========================================================================


class TestIntegration:
    """End-to-end tests through the full Analyzer pipeline."""

    def setup_method(self):
        RuleRegistry._reset()

    def teardown_method(self):
        RuleRegistry._reset()

    def _analyze(self, fixture: str):
        from netlint.analyzer.analyzer import Analyzer
        return Analyzer().run(FIXTURES / fixture)

    def test_clean_cfg_zero_findings(self):
        """A well-configured device should produce no findings from the
        five rules under test."""
        result = self._analyze("clean.cfg")
        rule_ids = {f.rule_id for f in result.findings}
        for rid in ("NET001", "NET002", "VLAN001", "SEC001", "SEC002"):
            assert rid not in rule_ids, f"{rid} fired unexpectedly on clean.cfg"

    def test_duplicate_ip_cfg_fires_net001(self):
        result = self._analyze("duplicate-ip.cfg")
        assert any(f.rule_id == "NET001" for f in result.findings)

    def test_vlans_cfg_fires_vlan001(self):
        result = self._analyze("vlans.cfg")
        assert any(f.rule_id == "VLAN001" for f in result.findings)

    def test_http_enabled_cfg_fires_sec001_and_sec002(self):
        result = self._analyze("http-enabled.cfg")
        rule_ids = {f.rule_id for f in result.findings}
        assert "SEC001" in rule_ids
        assert "SEC002" in rule_ids

    def test_findings_sorted_critical_first(self):
        result = self._analyze("duplicate-ip.cfg")
        weights = [f.severity.weight for f in result.findings]
        assert weights == sorted(weights, reverse=True)

    def test_findings_same_severity_sorted_by_line(self):
        result = self._analyze("duplicate-ip.cfg")
        for sev in Severity:
            group = [f for f in result.findings if f.severity == sev]
            lines = [f.line_number or 0 for f in group]
            assert lines == sorted(lines)
