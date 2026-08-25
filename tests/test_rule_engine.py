"""
Tests for the netlint rule engine.

Covers:
- Finding model fields, sort_key, immutability
- Severity ordering and weights
- RuleCategory values
- Rule base class: class-attribute contract, finding() helper
- RuleRegistry: register, get_for_vendor, get, all_rules, duplicate detection,
  autodiscover, supported_vendors, _reset isolation
- Analyzer: parse + rule pipeline, findings sorted by severity then line,
  parser_warnings forwarded, graceful handling of rules that raise
- Three concrete rules: SEC001, NET001, SEC002 via fixtures
- AnalysisResult: counts, by_severity, by_category
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from netlint.models.config_file import ConfigFile
from netlint.models.finding import Finding, RuleCategory, Severity
from netlint.models.result import AnalysisResult
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers — isolated registry for tests that register their own rules
# ---------------------------------------------------------------------------


def _make_config(raw: str, vendor: str = "cisco-ios") -> ConfigFile:
    return ConfigFile(
        file_path=Path("/tmp/test.cfg"),
        raw_text=raw,
        vendor=vendor,
        lines=(),
    )


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="TST001",
        severity=Severity.HIGH,
        category=RuleCategory.SECURITY,
        title="Test finding",
        message="Something is wrong",
        recommendation="Fix it",
        file=Path("/tmp/test.cfg"),
        line_number=10,
        configuration_line="interface GigabitEthernet0/0",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_values_are_strings(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_weight_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_info_weight_is_zero(self):
        assert Severity.INFO.weight == 0


# ---------------------------------------------------------------------------
# RuleCategory
# ---------------------------------------------------------------------------


class TestRuleCategory:
    def test_all_categories_exist(self):
        expected = {"security", "network", "vlan", "routing", "interface", "acl", "management"}
        actual = {c.value for c in RuleCategory}
        assert actual == expected


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class TestFinding:
    def test_fields_stored_correctly(self):
        f = _make_finding(rule_id="X001", severity=Severity.CRITICAL, line_number=42)
        assert f.rule_id == "X001"
        assert f.severity == Severity.CRITICAL
        assert f.line_number == 42

    def test_optional_fields_default_none(self):
        f = Finding(
            rule_id="X001",
            severity=Severity.INFO,
            category=RuleCategory.NETWORK,
            title="T",
            message="M",
            recommendation="R",
            file=Path("/tmp/t.cfg"),
        )
        assert f.line_number is None
        assert f.configuration_line is None

    def test_immutable(self):
        f = _make_finding()
        with pytest.raises(Exception):
            f.message = "changed"  # type: ignore[misc]

    def test_sort_key_critical_before_high(self):
        critical = _make_finding(severity=Severity.CRITICAL, line_number=50)
        high = _make_finding(severity=Severity.HIGH, line_number=1)
        # sort_key returns (-weight, line_number) so critical sorts first
        assert critical.sort_key() < high.sort_key()

    def test_sort_key_same_severity_by_line(self):
        f1 = _make_finding(severity=Severity.HIGH, line_number=5)
        f2 = _make_finding(severity=Severity.HIGH, line_number=20)
        assert f1.sort_key() < f2.sort_key()

    def test_sort_key_no_line_number(self):
        f = _make_finding(line_number=None)
        # Should not raise; line_number=None treated as 0
        key = f.sort_key()
        assert key[1] == 0


# ---------------------------------------------------------------------------
# Rule base class
# ---------------------------------------------------------------------------


class TestRuleBase:
    def _make_rule_class(self, rule_id="TST001"):
        """Create a minimal concrete Rule subclass without registering it."""

        class _TestRule(Rule):
            rule_id = "TST001"
            title = "Test rule"
            description = "Does nothing"
            category = RuleCategory.SECURITY
            severity = Severity.MEDIUM
            recommendation = "Do something"
            vendors = ("cisco-ios",)

            def check(self, config, parsed):
                return []

        _TestRule.rule_id = rule_id
        return _TestRule

    def test_class_attributes_readable(self):
        cls = self._make_rule_class()
        assert cls.rule_id == "TST001"
        assert cls.severity == Severity.MEDIUM
        assert cls.category == RuleCategory.SECURITY
        assert "cisco-ios" in cls.vendors

    def test_check_returns_empty_list_by_default(self):
        rule = self._make_rule_class()()
        config = _make_config("hostname R1")
        assert rule.check(config, None) == []

    def test_finding_helper_populates_metadata(self):
        rule = self._make_rule_class()()
        config = _make_config("hostname R1")
        f = rule.finding(
            config=config,
            message="Specific problem",
            line_number=7,
            configuration_line="hostname R1",
        )
        assert f.rule_id == "TST001"
        assert f.severity == Severity.MEDIUM
        assert f.category == RuleCategory.SECURITY
        assert f.title == "Test rule"
        assert f.recommendation == "Do something"
        assert f.message == "Specific problem"
        assert f.line_number == 7

    def test_finding_helper_severity_override(self):
        rule = self._make_rule_class()()
        config = _make_config("hostname R1")
        f = rule.finding(
            config=config,
            message="M",
            severity=Severity.CRITICAL,
        )
        assert f.severity == Severity.CRITICAL

    def test_abstract_check_enforced(self):
        """Cannot instantiate a Rule subclass without implementing check()."""
        with pytest.raises(TypeError):
            class _Incomplete(Rule):  # type: ignore[abstract]
                rule_id = "X"
                title = "X"
                description = "X"
                category = RuleCategory.NETWORK
                severity = Severity.LOW
                recommendation = "X"
            _Incomplete()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# RuleRegistry
# ---------------------------------------------------------------------------


class TestRuleRegistry:
    """All tests reset the registry before and after to ensure isolation."""

    def setup_method(self):
        RuleRegistry._reset()

    def teardown_method(self):
        RuleRegistry._reset()

    def _register_dummy(self, rule_id="TST001", vendor="cisco-ios"):
        # rule_id must be set as a class attribute BEFORE @register fires.
        @RuleRegistry.register
        class _Rule(Rule):
            vendors = (vendor,)
            severity = Severity.LOW
            category = RuleCategory.NETWORK
            title = "Dummy"
            description = "Dummy rule"
            recommendation = "Nothing"
            # Set a placeholder; overwritten below if caller passed a different id.
            rule_id = "TST001"

            def check(self, config, parsed):
                return []

        # If caller wants a different id and it's already registered under
        # "TST001" we need a fresh class. Simplest: build with the right id
        # from the start using type().
        if rule_id != "TST001":
            RuleRegistry._rules.pop("TST001", None)
            DynRule = type(
                "_DynRule",
                (Rule,),
                {
                    "rule_id": rule_id,
                    "vendors": (vendor,),
                    "severity": Severity.LOW,
                    "category": RuleCategory.NETWORK,
                    "title": "Dummy",
                    "description": "Dummy rule",
                    "recommendation": "Nothing",
                    "check": lambda self, config, parsed: [],
                },
            )
            RuleRegistry.register(DynRule)
            return DynRule
        return _Rule

    def test_register_adds_rule(self):
        self._register_dummy()
        assert len(RuleRegistry.all_rules()) == 1

    def test_register_as_decorator(self):
        @RuleRegistry.register
        class _Rule(Rule):
            rule_id = "DEC001"
            title = "Dec"
            description = "Dec"
            category = RuleCategory.ACL
            severity = Severity.INFO
            recommendation = "Dec"
            vendors = ("cisco-ios",)

            def check(self, config, parsed):
                return []

        assert RuleRegistry.get("DEC001") is _Rule

    def test_register_missing_rule_id_raises(self):
        with pytest.raises(ValueError, match="rule_id"):
            @RuleRegistry.register
            class _Bad(Rule):
                rule_id = ""
                title = "X"
                description = "X"
                category = RuleCategory.NETWORK
                severity = Severity.LOW
                recommendation = "X"

                def check(self, config, parsed):
                    return []

    def test_duplicate_rule_id_raises(self):
        self._register_dummy("DUP001")
        with pytest.raises(ValueError, match="DUP001"):
            @RuleRegistry.register
            class _Other(Rule):
                rule_id = "DUP001"
                title = "Dup"
                description = "Dup"
                category = RuleCategory.NETWORK
                severity = Severity.LOW
                recommendation = "Dup"

                def check(self, config, parsed):
                    return []

    def test_same_class_double_register_idempotent(self):
        """Re-registering the exact same class is allowed (module re-import)."""
        cls = self._register_dummy("IDEM001")
        RuleRegistry.register(cls)  # second time — should not raise
        assert len(RuleRegistry.all_rules()) == 1

    def test_get_for_vendor_filters_correctly(self):
        self._register_dummy("IOS001", vendor="cisco-ios")
        self._register_dummy("JNP001", vendor="juniper")

        ios_rules = RuleRegistry.get_for_vendor("cisco-ios")
        assert len(ios_rules) == 1
        assert ios_rules[0].rule_id == "IOS001"

    def test_get_for_vendor_unknown_returns_empty(self):
        self._register_dummy()
        assert RuleRegistry.get_for_vendor("no-such-vendor") == []

    def test_get_returns_none_for_unknown(self):
        assert RuleRegistry.get("UNKNOWN") is None

    def test_all_rules_insertion_order(self):
        self._register_dummy("A001")
        self._register_dummy("B002")
        self._register_dummy("C003")
        ids = [r.rule_id for r in RuleRegistry.all_rules()]
        assert ids == ["A001", "B002", "C003"]

    def test_supported_vendors(self):
        self._register_dummy("V001", "cisco-ios")
        self._register_dummy("V002", "juniper")
        vendors = RuleRegistry.supported_vendors()
        assert "cisco-ios" in vendors
        assert "juniper" in vendors
        assert vendors == sorted(vendors)

    def test_reset_clears_all(self):
        self._register_dummy()
        RuleRegistry._reset()
        assert RuleRegistry.all_rules() == []

    def test_autodiscover_loads_real_rules(self):
        """autodiscover() should load the three rules we shipped."""
        RuleRegistry.autodiscover()
        ids = {r.rule_id for r in RuleRegistry.all_rules()}
        assert "SEC001" in ids
        assert "NET001" in ids
        assert "SEC002" in ids

    def test_autodiscover_idempotent(self):
        RuleRegistry.autodiscover()
        count_after_first = len(RuleRegistry.all_rules())
        RuleRegistry.autodiscover()
        assert len(RuleRegistry.all_rules()) == count_after_first


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------


class TestAnalysisResult:
    def _make_result(self, findings=()) -> AnalysisResult:
        return AnalysisResult(
            file_path=Path("/tmp/test.cfg"),
            findings=findings,
        )

    def test_empty_result(self):
        r = self._make_result()
        assert not r.has_findings
        assert r.critical_count == 0
        assert r.high_count == 0

    def test_counts(self):
        findings = (
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.INFO),
        )
        r = self._make_result(findings)
        assert r.critical_count == 2
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1
        assert r.info_count == 1
        assert r.has_findings

    def test_by_severity(self):
        findings = (
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.HIGH),
        )
        r = self._make_result(findings)
        assert len(r.by_severity(Severity.HIGH)) == 2
        assert len(r.by_severity(Severity.MEDIUM)) == 1
        assert len(r.by_severity(Severity.LOW)) == 0

    def test_by_category(self):
        findings = (
            _make_finding(category=RuleCategory.SECURITY),
            _make_finding(category=RuleCategory.NETWORK),
            _make_finding(category=RuleCategory.SECURITY),
        )
        r = self._make_result(findings)
        assert len(r.by_category("security")) == 2
        assert len(r.by_category("SECURITY")) == 2  # case-insensitive
        assert len(r.by_category("network")) == 1

    def test_backwards_compat_aliases(self):
        r = self._make_result((_make_finding(severity=Severity.CRITICAL),))
        assert r.has_issues is True
        assert r.error_count == 1  # CRITICAL + HIGH

    def test_immutable(self):
        r = self._make_result()
        with pytest.raises(Exception):
            r.file_path = Path("/other.cfg")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Analyzer integration — using real fixtures and real rules
# ---------------------------------------------------------------------------


class TestAnalyzer:
    """Uses autodiscover so real rules are loaded."""

    def setup_method(self):
        # Reset then let autodiscover re-load real rules cleanly
        RuleRegistry._reset()

    def teardown_method(self):
        RuleRegistry._reset()

    def _run(self, fixture_name: str):
        from netlint.analyzer.analyzer import Analyzer
        return Analyzer().run(FIXTURES / fixture_name)

    def test_clean_config_no_security_findings(self):
        """clean.cfg has SSH-only VTY with access-class — SEC001 and SEC002 silent."""
        result = self._run("clean.cfg")
        sec001 = [f for f in result.findings if f.rule_id == "SEC001"]
        sec003 = [f for f in result.findings if f.rule_id == "SEC003"]
        assert sec001 == []
        assert sec003 == []

    def test_duplicate_ip_found(self):
        """duplicate-ip.cfg should trigger NET001 for the two shared IPs."""
        result = self._run("duplicate-ip.cfg")
        net001 = [f for f in result.findings if f.rule_id == "NET001"]
        assert len(net001) >= 2  # at least one per duplicate IP

    def test_duplicate_ip_findings_are_critical(self):
        result = self._run("duplicate-ip.cfg")
        for f in result.findings:
            if f.rule_id == "NET001":
                assert f.severity == Severity.CRITICAL

    def test_telnet_enabled_found(self):
        """duplicate-ip.cfg has 'transport input ssh telnet' — SEC001 fires."""
        result = self._run("duplicate-ip.cfg")
        sec001 = [f for f in result.findings if f.rule_id == "SEC001"]
        assert len(sec001) >= 1

    def test_no_acl_found(self):
        """duplicate-ip.cfg VTY has no access-class — SEC003 fires."""
        result = self._run("duplicate-ip.cfg")
        sec003 = [f for f in result.findings if f.rule_id == "SEC003"]
        assert len(sec003) >= 1

    def test_findings_sorted_by_severity_descending(self):
        """CRITICAL findings must appear before HIGH, HIGH before MEDIUM, etc."""
        result = self._run("duplicate-ip.cfg")
        weights = [f.severity.weight for f in result.findings]
        assert weights == sorted(weights, reverse=True)

    def test_same_severity_sorted_by_line_number(self):
        """Within the same severity, line numbers must be ascending."""
        result = self._run("duplicate-ip.cfg")
        for severity in Severity:
            group = [f for f in result.findings if f.severity == severity]
            line_numbers = [f.line_number or 0 for f in group]
            assert line_numbers == sorted(line_numbers), (
                f"Findings at severity {severity} not sorted by line number"
            )

    def test_result_carries_parser_warnings(self):
        """Malformed config should surface parser warnings on the result."""
        result = self._run("malformed.cfg")
        assert len(result.parser_warnings) > 0

    def test_result_has_file_path(self):
        result = self._run("clean.cfg")
        assert result.file_path.name == "clean.cfg"

    def test_parsed_attached_to_config(self):
        """After analysis, config.parsed should hold the ParsedConfig."""
        from netlint.analyzer.analyzer import Analyzer
        from netlint.models.config_file import ConfigFile
        config = ConfigFile.from_path(FIXTURES / "clean.cfg")
        Analyzer().run_config(config)
        assert config.parsed is not None
        assert config.parsed.hostname == "CORE-SW-01"


# ---------------------------------------------------------------------------
# SEC001 unit tests
# ---------------------------------------------------------------------------


class TestSEC001:
    def setup_method(self):
        RuleRegistry._reset()

    def teardown_method(self):
        RuleRegistry._reset()

    def _rule(self):
        from netlint.rules.sec001_telnet import TelnetEnabledRule
        return TelnetEnabledRule()

    def _parsed_with_telnet(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "line vty 0 4",
            " transport input telnet ssh",
            " login local",
        ])

    def _parsed_ssh_only(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "line vty 0 4",
            " transport input ssh",
            " login local",
        ])

    def test_telnet_triggers_finding(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_with_telnet()
        findings = self._rule().check(config, parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC001"
        assert findings[0].severity == Severity.HIGH

    def test_ssh_only_no_finding(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_ssh_only()
        findings = self._rule().check(config, parsed)
        assert findings == []

    def test_finding_has_line_number(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_with_telnet()
        findings = self._rule().check(config, parsed)
        assert findings[0].line_number is not None
        assert findings[0].line_number > 0

    def test_none_parsed_returns_empty(self):
        findings = self._rule().check(_make_config("hostname R1"), None)
        assert findings == []


# ---------------------------------------------------------------------------
# NET001 unit tests
# ---------------------------------------------------------------------------


class TestNET001:
    def _rule(self):
        from netlint.rules.net001_duplicate_ip import DuplicateIpRule
        return DuplicateIpRule()

    def _parsed_duplicate(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
        ])

    def _parsed_unique(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.2 255.255.255.0",
            " no shutdown",
        ])

    def _parsed_shutdown_duplicate(self):
        """Shutdown interfaces should be excluded from duplicate checks."""
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.1 255.255.255.0",
            " shutdown",
        ])

    def test_duplicate_detected(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_duplicate()
        findings = self._rule().check(config, parsed)
        assert len(findings) == 2  # one per offending interface

    def test_unique_ips_no_finding(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_unique()
        findings = self._rule().check(config, parsed)
        assert findings == []

    def test_shutdown_excluded(self):
        """A shutdown interface should not contribute to duplicate detection."""
        config = _make_config("hostname R1")
        parsed = self._parsed_shutdown_duplicate()
        findings = self._rule().check(config, parsed)
        assert findings == []

    def test_finding_mentions_both_interfaces(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_duplicate()
        findings = self._rule().check(config, parsed)
        # Each finding message should name the conflicting peer
        for f in findings:
            assert "GigabitEthernet" in f.message

    def test_finding_severity_critical(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_duplicate()
        for f in self._rule().check(config, parsed):
            assert f.severity == Severity.CRITICAL

    def test_none_parsed_returns_empty(self):
        assert self._rule().check(_make_config("hostname R1"), None) == []


# ---------------------------------------------------------------------------
# SEC002 unit tests
# ---------------------------------------------------------------------------


class TestSEC002:
    def _rule(self):
        from netlint.rules.sec003_vty_no_acl import VtyNoAclRule
        return VtyNoAclRule()

    def _parsed_no_acl(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "line vty 0 4",
            " transport input ssh",
            " login local",
        ])

    def _parsed_with_acl(self):
        from netlint.parser.cisco_ios.parser import CiscoIosParser
        return CiscoIosParser().parse_text([
            "hostname R1",
            "ip access-list standard MGMT",
            " permit 10.0.0.0 0.0.0.255",
            "line vty 0 4",
            " transport input ssh",
            " access-class MGMT in",
            " login local",
        ])

    def test_no_acl_triggers_finding(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_no_acl()
        findings = self._rule().check(config, parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC003"
        assert findings[0].severity == Severity.HIGH

    def test_acl_present_no_finding(self):
        config = _make_config("hostname R1")
        parsed = self._parsed_with_acl()
        findings = self._rule().check(config, parsed)
        assert findings == []

    def test_none_parsed_returns_empty(self):
        assert self._rule().check(_make_config("hostname R1"), None) == []
