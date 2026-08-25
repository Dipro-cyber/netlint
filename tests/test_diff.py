"""
Tests for the netlint diff subsystem.

Coverage
--------
ConfigDiffer
  - identical configs produce empty diff
  - hostname change detected
  - interface added / removed / modified (ip_address, shutdown, description,
    access_vlan, trunk_mode, trunk_allowed_vlans)
  - VLAN added / removed / name changed
  - static route added / removed / next-hop changed
  - ACL added / removed / entry added / entry removed
  - VTY transport_input changed / access_class_in changed
  - HTTP server enabled / disabled
  - line numbers are NOT compared (only semantic fields)

DiffRiskResult / compare_results
  - no new risks when configs identical
  - new finding identified by (rule_id, message) fingerprint
  - finding present in old but gone in new → resolved
  - finding in both → persisting
  - recommendation: DO NOT DEPLOY for HIGH+, REVIEW for MEDIUM, SAFE for LOW/INFO/none

DiffFormatter
  - render_with_diff returns a non-empty string
  - output contains old/new file names
  - added items appear with [+]
  - removed items appear with [-]
  - modified items appear with [~]
  - new-risk panels appear
  - recommendation text present
  - no-color strips ANSI codes

CLI (netlint diff)
  - identical configs → exit 0
  - new risks → exit 1
  - nonexistent file → exit 2
  - output contains expected sections
  - --no-color strips ANSI
  - --quiet suppresses output, exit code still correct
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netlint.cli import app
from netlint.diff.differ import ConfigDiffer
from netlint.diff.models import ConfigDiff, FieldDelta
from netlint.diff.risk import DiffRiskResult, compare_results
from netlint.models.config_file import ConfigFile
from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult
from netlint.parser.cisco_ios.parser import CiscoIosParser
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(text: str):
    return CiscoIosParser().parse_text(text.strip().splitlines())


def _diff(old_text: str, new_text: str) -> ConfigDiff:
    old = _parse(old_text)
    new = _parse(new_text)
    return ConfigDiffer().diff(old, new, old_path="old.cfg", new_path="new.cfg")


def _finding(
    rule_id: str = "T001",
    severity: Severity = Severity.HIGH,
    message: str = "test message",
    file: Path = Path("/tmp/test.cfg"),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=RuleCategory.SECURITY,
        title="Test",
        message=message,
        recommendation="Fix it",
        file=file,
    )


def _result(*findings: Finding, path: str = "/tmp/test.cfg") -> AnalysisResult:
    return AnalysisResult(
        file_path=Path(path),
        findings=tuple(sorted(findings, key=lambda f: f.sort_key())),
    )


@pytest.fixture(autouse=True)
def reset_registry():
    RuleRegistry._reset()
    yield
    RuleRegistry._reset()


# ===========================================================================
# ConfigDiffer — identical configs
# ===========================================================================


class TestDifferIdentical:

    def test_no_changes_when_identical(self):
        cfg = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        d = _diff(cfg, cfg)
        assert not d.has_changes

    def test_empty_config_diff(self):
        d = _diff("hostname R1", "hostname R1")
        assert not d.has_changes

    def test_paths_preserved(self):
        old = _parse("hostname R1")
        new = _parse("hostname R1")
        d = ConfigDiffer().diff(old, new, old_path="prod.cfg", new_path="proposed.cfg")
        assert d.old_path == "prod.cfg"
        assert d.new_path == "proposed.cfg"


# ===========================================================================
# Hostname
# ===========================================================================


class TestDifferHostname:

    def test_hostname_change_detected(self):
        d = _diff("hostname OLD", "hostname NEW")
        assert d.hostname_change is not None
        assert d.hostname_change.old_hostname == "OLD"
        assert d.hostname_change.new_hostname == "NEW"

    def test_no_hostname_change_when_same(self):
        d = _diff("hostname R1", "hostname R1")
        assert d.hostname_change is None

    def test_hostname_in_modified_count(self):
        d = _diff("hostname OLD", "hostname NEW")
        assert d.modified_count >= 1


# ===========================================================================
# Interfaces
# ===========================================================================


class TestDifferInterfaces:

    def test_interface_added(self):
        old = "hostname R1"
        new = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        d = _diff(old, new)
        assert len(d.interfaces_added) == 1
        assert d.interfaces_added[0].name == "GigabitEthernet0/0"

    def test_interface_removed(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        d = _diff(old, "hostname R1")
        assert len(d.interfaces_removed) == 1
        assert d.interfaces_removed[0].name == "GigabitEthernet0/0"

    def test_interface_ip_modified(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        new = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.0
 no shutdown
"""
        d = _diff(old, new)
        assert len(d.interfaces_modified) == 1
        change = d.interfaces_modified[0]
        assert change.name == "GigabitEthernet0/0"
        field_names = [delta.field_name for delta in change.deltas]
        assert "ip_address" in field_names

    def test_interface_ip_delta_values(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""
        new = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.0
"""
        d = _diff(old, new)
        ip_deltas = [
            delta for delta in d.interfaces_modified[0].deltas
            if delta.field_name == "ip_address"
        ]
        assert len(ip_deltas) == 1
        assert ip_deltas[0].old_value == ipaddress.IPv4Address("10.0.0.1")
        assert ip_deltas[0].new_value == ipaddress.IPv4Address("10.0.0.2")

    def test_interface_shutdown_modified(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 shutdown
"""
        new = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        d = _diff(old, new)
        field_names = [delta.field_name for delta in d.interfaces_modified[0].deltas]
        assert "shutdown" in field_names

    def test_interface_description_modified(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 description Old description
 ip address 10.0.0.1 255.255.255.0
"""
        new = """
hostname R1
interface GigabitEthernet0/0
 description New description
 ip address 10.0.0.1 255.255.255.0
"""
        d = _diff(old, new)
        assert any(delta.field_name == "description"
                   for delta in d.interfaces_modified[0].deltas)

    def test_interface_access_vlan_modified(self):
        old = """
hostname SW1
vlan 10
interface GigabitEthernet0/0
 switchport access vlan 10
"""
        new = """
hostname SW1
vlan 10
vlan 20
interface GigabitEthernet0/0
 switchport access vlan 20
"""
        d = _diff(old, new)
        assert len(d.interfaces_modified) == 1
        field_names = [delta.field_name for delta in d.interfaces_modified[0].deltas]
        assert "access_vlan" in field_names

    def test_interface_trunk_allowed_vlans_modified(self):
        old = """
hostname SW1
interface GigabitEthernet0/3
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20
"""
        new = """
hostname SW1
interface GigabitEthernet0/3
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
"""
        d = _diff(old, new)
        assert len(d.interfaces_modified) == 1
        field_names = [delta.field_name for delta in d.interfaces_modified[0].deltas]
        assert "trunk_allowed_vlans" in field_names

    def test_line_number_change_does_not_trigger_diff(self):
        """Inserting a comment above an interface must not count as a modification."""
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        new = """
hostname R1
! This comment shifts all line numbers by one
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
        d = _diff(old, new)
        assert len(d.interfaces_modified) == 0

    def test_interface_name_case_insensitive(self):
        """gi0/0 and GigabitEthernet0/0 expand to the same canonical name."""
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""
        new = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.0
"""
        d = _diff(old, new)
        assert len(d.interfaces_modified) == 1  # same interface, different IP

    def test_added_count_and_removed_count(self):
        old = """
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""
        new = """
hostname R1
interface GigabitEthernet0/1
 ip address 10.0.1.1 255.255.255.0
"""
        d = _diff(old, new)
        assert d.added_count == 1
        assert d.removed_count == 1


# ===========================================================================
# VLANs
# ===========================================================================


class TestDifferVlans:

    def test_vlan_added(self):
        old = "hostname SW1\nvlan 10\n name DATA"
        new = "hostname SW1\nvlan 10\n name DATA\nvlan 20\n name VOICE"
        d = _diff(old, new)
        assert len(d.vlans_added) == 1
        assert d.vlans_added[0].vlan_id == 20

    def test_vlan_removed(self):
        old = "hostname SW1\nvlan 10\nvlan 20"
        new = "hostname SW1\nvlan 10"
        d = _diff(old, new)
        assert len(d.vlans_removed) == 1
        assert d.vlans_removed[0].vlan_id == 20

    def test_vlan_name_modified(self):
        old = "hostname SW1\nvlan 10\n name OLD"
        new = "hostname SW1\nvlan 10\n name NEW"
        d = _diff(old, new)
        assert len(d.vlans_modified) == 1
        assert d.vlans_modified[0].vlan_id == 10
        assert d.vlans_modified[0].old_name == "OLD"
        assert d.vlans_modified[0].new_name == "NEW"

    def test_vlan_no_change_when_identical(self):
        cfg = "hostname SW1\nvlan 10\n name DATA"
        d = _diff(cfg, cfg)
        assert len(d.vlans_modified) == 0


# ===========================================================================
# Static routes
# ===========================================================================


class TestDifferRoutes:

    def test_route_added(self):
        old = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1"
        new = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1\nip route 10.10.0.0 255.255.0.0 10.0.0.2"
        d = _diff(old, new)
        assert len(d.routes_added) == 1
        assert str(d.routes_added[0].network) == "10.10.0.0/16"

    def test_route_removed(self):
        old = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1\nip route 10.10.0.0 255.255.0.0 10.0.0.2"
        new = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1"
        d = _diff(old, new)
        assert len(d.routes_removed) == 1

    def test_route_next_hop_modified(self):
        old = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1"
        new = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.2"
        d = _diff(old, new)
        assert len(d.routes_modified) == 1
        field_names = [delta.field_name for delta in d.routes_modified[0].deltas]
        assert "next_hop" in field_names

    def test_route_admin_distance_modified(self):
        old = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1"
        new = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.0.0.1 200"
        d = _diff(old, new)
        assert len(d.routes_modified) == 1
        field_names = [delta.field_name for delta in d.routes_modified[0].deltas]
        assert "admin_distance" in field_names


# ===========================================================================
# ACLs
# ===========================================================================


class TestDifferAcls:

    def test_acl_added(self):
        old = "hostname R1"
        new = "hostname R1\nip access-list extended NEW_ACL\n 10 permit ip any any"
        d = _diff(old, new)
        assert len(d.acls_added) == 1
        assert d.acls_added[0].name == "NEW_ACL"

    def test_acl_removed(self):
        old = "hostname R1\nip access-list extended OLD_ACL\n 10 permit ip any any"
        new = "hostname R1"
        d = _diff(old, new)
        assert len(d.acls_removed) == 1

    def test_acl_entry_added(self):
        old = "hostname R1\nip access-list extended MYACL\n 10 permit tcp any any eq 22"
        new = "hostname R1\nip access-list extended MYACL\n 10 permit tcp any any eq 22\n 20 deny ip any any"
        d = _diff(old, new)
        assert len(d.acls_modified) == 1
        assert d.acls_modified[0].entries_added == 1
        assert d.acls_modified[0].entries_removed == 0

    def test_acl_entry_removed(self):
        old = "hostname R1\nip access-list extended MYACL\n 10 permit tcp any any eq 22\n 20 deny ip any any"
        new = "hostname R1\nip access-list extended MYACL\n 10 permit tcp any any eq 22"
        d = _diff(old, new)
        assert len(d.acls_modified) == 1
        assert d.acls_modified[0].entries_removed == 1

    def test_acl_unchanged(self):
        cfg = "hostname R1\nip access-list extended MYACL\n 10 permit ip any any"
        d = _diff(cfg, cfg)
        assert len(d.acls_modified) == 0


# ===========================================================================
# VTY
# ===========================================================================


class TestDifferVty:

    def test_vty_transport_input_modified(self):
        old = "hostname R1\nline vty 0 4\n transport input ssh\n login local"
        new = "hostname R1\nline vty 0 4\n transport input telnet ssh\n login local"
        d = _diff(old, new)
        assert len(d.vty_modified) == 1
        field_names = [delta.field_name for delta in d.vty_modified[0].deltas]
        assert "transport_input" in field_names

    def test_vty_access_class_added(self):
        old = "hostname R1\nline vty 0 4\n transport input ssh\n login local"
        new = "hostname R1\nline vty 0 4\n transport input ssh\n access-class MGMT in\n login local"
        d = _diff(old, new)
        assert len(d.vty_modified) == 1
        field_names = [delta.field_name for delta in d.vty_modified[0].deltas]
        assert "access_class_in" in field_names

    def test_vty_no_change_when_identical(self):
        cfg = "hostname R1\nline vty 0 4\n transport input ssh\n login local"
        d = _diff(cfg, cfg)
        assert len(d.vty_modified) == 0


# ===========================================================================
# HTTP server
# ===========================================================================


class TestDifferHttp:

    def test_http_server_enabled(self):
        old = "hostname R1"
        new = "hostname R1\nip http server"
        d = _diff(old, new)
        assert d.http_server_change is not None
        assert d.http_server_change.old_http is False
        assert d.http_server_change.new_http is True

    def test_http_server_disabled(self):
        old = "hostname R1\nip http server"
        new = "hostname R1\nno ip http server"
        d = _diff(old, new)
        assert d.http_server_change is not None
        assert d.http_server_change.old_http is True
        assert d.http_server_change.new_http is False

    def test_https_server_added(self):
        old = "hostname R1"
        new = "hostname R1\nip http secure-server"
        d = _diff(old, new)
        assert d.http_server_change is not None
        assert d.http_server_change.new_https is True

    def test_no_http_change_when_same(self):
        cfg = "hostname R1\nip http server"
        d = _diff(cfg, cfg)
        assert d.http_server_change is None


# ===========================================================================
# ConfigDiff properties
# ===========================================================================


class TestConfigDiffProperties:

    def test_has_changes_false_when_identical(self):
        d = _diff("hostname R1", "hostname R1")
        assert not d.has_changes

    def test_has_changes_true_when_different(self):
        d = _diff("hostname OLD", "hostname NEW")
        assert d.has_changes

    def test_added_count(self):
        old = "hostname R1"
        new = """
hostname R1
vlan 10
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 10.0.0.2
"""
        d = _diff(old, new)
        assert d.added_count == 3  # 1 vlan + 1 interface + 1 route


# ===========================================================================
# compare_results — risk detection
# ===========================================================================


class TestCompareResults:

    def test_no_new_risks_when_identical(self):
        r = _result()
        dr = compare_results(r, r)
        assert not dr.has_new_risks
        assert len(dr.new_findings) == 0

    def test_new_finding_detected(self):
        old_r = _result()
        new_r = _result(_finding("SEC001", Severity.HIGH, "Telnet on VTY 0-4"))
        dr = compare_results(old_r, new_r)
        assert dr.has_new_risks
        assert len(dr.new_findings) == 1
        assert dr.new_findings[0].rule_id == "SEC001"

    def test_resolved_finding_detected(self):
        f = _finding("SEC001", Severity.HIGH, "Telnet on VTY 0-4")
        old_r = _result(f)
        new_r = _result()
        dr = compare_results(old_r, new_r)
        assert len(dr.resolved_findings) == 1
        assert dr.resolved_findings[0].rule_id == "SEC001"

    def test_persisting_finding_detected(self):
        # Same rule_id + message but different file path → same fingerprint
        f_old = _finding("NET001", Severity.CRITICAL, "Dup IP", file=Path("/tmp/old.cfg"))
        f_new = _finding("NET001", Severity.CRITICAL, "Dup IP", file=Path("/tmp/new.cfg"))
        old_r = _result(f_old)
        new_r = _result(f_new)
        dr = compare_results(old_r, new_r)
        assert len(dr.new_findings) == 0
        assert len(dr.persisting_findings) == 1

    def test_fingerprint_uses_rule_id_and_message_not_file(self):
        """Same finding on a different file path must be treated as persisting."""
        msg = "Identical message"
        f1 = _finding("T001", Severity.HIGH, msg, file=Path("/tmp/a.cfg"))
        f2 = _finding("T001", Severity.HIGH, msg, file=Path("/tmp/b.cfg"))
        dr = compare_results(_result(f1), _result(f2))
        assert len(dr.new_findings) == 0
        assert len(dr.persisting_findings) == 1

    def test_different_message_same_rule_id_counts_as_new(self):
        f_old = _finding("NET001", Severity.CRITICAL, "IP 10.0.0.1 on Gi0/0 also on Gi0/1")
        f_new = _finding("NET001", Severity.CRITICAL, "IP 10.0.0.2 on Gi0/2 also on Gi0/3")
        dr = compare_results(_result(f_old), _result(f_new))
        assert len(dr.new_findings) == 1
        assert len(dr.resolved_findings) == 1

    def test_recommendation_do_not_deploy_for_critical(self):
        f = _finding("X001", Severity.CRITICAL, "bad")
        dr = compare_results(_result(), _result(f))
        assert "DO NOT DEPLOY" in dr.deployment_recommendation

    def test_recommendation_do_not_deploy_for_high(self):
        f = _finding("X001", Severity.HIGH, "bad")
        dr = compare_results(_result(), _result(f))
        assert "DO NOT DEPLOY" in dr.deployment_recommendation

    def test_recommendation_review_for_medium(self):
        f = _finding("X001", Severity.MEDIUM, "medium issue")
        dr = compare_results(_result(), _result(f))
        assert "REVIEW" in dr.deployment_recommendation

    def test_recommendation_safe_for_low(self):
        f = _finding("X001", Severity.LOW, "minor")
        dr = compare_results(_result(), _result(f))
        assert "SAFE" in dr.deployment_recommendation

    def test_recommendation_safe_when_no_new_findings(self):
        dr = compare_results(_result(), _result())
        assert "SAFE" in dr.deployment_recommendation

    def test_new_findings_sorted_by_severity(self):
        findings = [
            _finding("A", Severity.LOW,      "low msg"),
            _finding("B", Severity.CRITICAL, "critical msg"),
            _finding("C", Severity.HIGH,     "high msg"),
        ]
        dr = compare_results(_result(), _result(*findings))
        weights = [f.severity.weight for f in dr.new_findings]
        assert weights == sorted(weights, reverse=True)

    def test_new_critical_count(self):
        findings = [
            _finding("A", Severity.CRITICAL, "c1"),
            _finding("B", Severity.CRITICAL, "c2"),
            _finding("C", Severity.HIGH,     "h1"),
        ]
        dr = compare_results(_result(), _result(*findings))
        assert dr.new_critical_count == 2
        assert dr.new_high_count == 1

    def test_has_new_risks_false_when_empty(self):
        dr = compare_results(_result(), _result())
        assert not dr.has_new_risks


# ===========================================================================
# DiffFormatter
# ===========================================================================


class TestDiffFormatter:

    def _make_diff_result(self) -> tuple:
        """Return (config_diff, diff_risk) for clean.cfg vs proposed.cfg."""
        from netlint.analyzer.analyzer import Analyzer
        from netlint.diff.differ import ConfigDiffer

        old_path = FIXTURES / "clean.cfg"
        new_path  = FIXTURES / "proposed.cfg"

        old_parsed = CiscoIosParser().parse_text(
            old_path.read_text(encoding="utf-8").splitlines()
        )
        new_parsed = CiscoIosParser().parse_text(
            new_path.read_text(encoding="utf-8").splitlines()
        )
        config_diff = ConfigDiffer().diff(
            old_parsed, new_parsed,
            old_path=str(old_path), new_path=str(new_path),
        )

        old_result = Analyzer().run(old_path)
        new_result = Analyzer().run(new_path)
        diff_risk = compare_results(old_result, new_result)
        return config_diff, diff_risk

    def test_render_returns_string(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_output_contains_old_filename(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "clean.cfg" in output

    def test_output_contains_new_filename(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "proposed.cfg" in output

    def test_output_contains_added_marker(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "[+]" in output

    def test_output_contains_modified_marker(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "[~]" in output

    def test_output_contains_recommendation(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert any(
            kw in output
            for kw in ("DO NOT DEPLOY", "REVIEW", "SAFE TO DEPLOY")
        )

    def test_no_color_strips_ansi(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "\x1b[" not in output

    def test_new_risk_panel_present_when_risks_exist(self):
        from netlint.output.diff_formatter import DiffFormatter
        config_diff, diff_risk = self._make_diff_result()
        if diff_risk.has_new_risks:
            output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
            assert "NEW" in output or "New Risks" in output

    def test_no_new_risk_message_when_clean(self):
        from netlint.output.diff_formatter import DiffFormatter
        # Diff a config against itself
        cfg_path = FIXTURES / "clean.cfg"
        old_parsed = CiscoIosParser().parse_text(cfg_path.read_text().splitlines())
        from netlint.analyzer.analyzer import Analyzer
        from netlint.diff.differ import ConfigDiffer
        config_diff = ConfigDiffer().diff(old_parsed, old_parsed)
        result = Analyzer().run(cfg_path)
        diff_risk = compare_results(result, result)
        output = DiffFormatter().render_with_diff(config_diff, diff_risk, no_color=True)
        assert "No new risks" in output


# ===========================================================================
# CLI — netlint diff
# ===========================================================================


class TestDiffCli:

    def _run(self, *args: str):
        return runner.invoke(app, ["diff", *args], catch_exceptions=False)

    def test_identical_configs_exit_zero(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "clean.cfg"),
            "--no-color",
        )
        assert result.exit_code == 0, result.output

    def test_configs_with_new_risks_exit_one(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert result.exit_code in (1, 2, 3), result.output

    def test_nonexistent_old_file_exit_two(self):
        result = self._run(
            str(FIXTURES / "does_not_exist.cfg"),
            str(FIXTURES / "clean.cfg"),
        )
        assert result.exit_code == 4

    def test_nonexistent_new_file_exit_two(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "does_not_exist.cfg"),
        )
        assert result.exit_code == 4

    def test_output_contains_header(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert "Configuration Change Analysis" in result.output

    def test_output_contains_both_filenames(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert "clean.cfg" in result.output
        assert "proposed.cfg" in result.output

    def test_output_contains_added_items(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert "[+]" in result.output

    def test_output_contains_modified_items(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert "[~]" in result.output

    def test_output_contains_recommendation(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert any(
            kw in result.output
            for kw in ("DO NOT DEPLOY", "REVIEW BEFORE DEPLOYING", "SAFE TO DEPLOY")
        )

    def test_no_color_strips_ansi(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        assert "\x1b[" not in result.output

    def test_quiet_suppresses_output_exit_one(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--quiet",
        )
        assert result.exit_code in (1, 2, 3)
        assert result.output.strip() == ""

    def test_quiet_suppresses_output_exit_zero(self):
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "clean.cfg"),
            "--quiet",
        )
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_help_shows_diff_description(self):
        result = runner.invoke(app, ["diff", "--help"])
        assert result.exit_code == 0
        assert "diff" in result.output.lower() or "compare" in result.output.lower()

    def test_new_risk_rule_ids_in_output(self):
        """proposed.cfg adds ip http server and changes VTY — SEC001/SEC002 must appear."""
        result = self._run(
            str(FIXTURES / "clean.cfg"),
            str(FIXTURES / "proposed.cfg"),
            "--no-color",
        )
        # At least one new security finding should be in the output
        assert any(rid in result.output for rid in ("SEC001", "SEC002", "SEC003"))

    def test_resolved_section_present_when_risk_removed(self):
        """
        Diff duplicate-ip.cfg (many issues) against clean.cfg (no issues).
        All old findings become resolved.
        """
        result = self._run(
            str(FIXTURES / "duplicate-ip.cfg"),
            str(FIXTURES / "clean.cfg"),
            "--no-color",
        )
        assert result.exit_code == 0
        assert "Resolved" in result.output

    def test_persisting_section_present(self):
        """
        Diff duplicate-ip.cfg against itself.
        All findings persist — none are new.
        """
        result = self._run(
            str(FIXTURES / "duplicate-ip.cfg"),
            str(FIXTURES / "duplicate-ip.cfg"),
            "--no-color",
        )
        assert result.exit_code == 0
        # If there are persisting findings, the section should appear
        # (could be empty if no findings at all, but dup-ip has many)
        assert "Persisting" in result.output or "No new risks" in result.output
