"""
Tests for NetLint Multi-Vendor Architecture & Automatic Vendor Detection.

Architecture Pipeline:
                    NetLint
                       │
                Detect file type
                       │
          ┌────────────┼────────────┐
          ↓            ↓            ↓
       Cisco IOS    Juniper       Arista
          │           │             │
          ↓           ↓             ↓
       Parser       Parser        Parser
          │           │             │
          └───────────┼─────────────┘
                      ↓
               Common IR / Model
                      ↓
                Linting Rules
                      ↓
                   Report
"""

import tempfile
from pathlib import Path

from netlint.analyzer.analyzer import Analyzer
from netlint.parser.detector import detect_vendor
from netlint.parser.registry import ParserRegistry

CISCO_CONFIG = """! Cisco IOS Config
hostname CORE-CISCO-01
service password-encryption
ip ssh version 2
interface GigabitEthernet0/0
 description WAN Interface
 ip address 203.0.113.1 255.255.255.252
 no shutdown
ip route 0.0.0.0 0.0.0.0 203.0.113.2
line vty 0 4
 transport input ssh
 login local
end
"""

JUNIPER_CONFIG = """# Juniper JunOS Config
set system host-name CORE-JUNIPER-01
set system services ssh
set interfaces ge-0/0/0 description "WAN Interface"
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.1/30
set routing-options static route 0.0.0.0/0 next-hop 203.0.113.2
set vlans MANAGEMENT vlan-id 10
"""

ARISTA_CONFIG = """! Arista EOS Config
hostname CORE-ARISTA-01
transceiver qsfp default-mode 4x10G
service password-encryption
spanning-tree mode mstp
interface Ethernet1
 description WAN Interface
 ip address 203.0.113.1/30
 no shutdown
ip route 0.0.0.0/0 203.0.113.2
line vty 0 4
 transport input ssh
 login local
end
"""


def test_detect_vendor():
    assert detect_vendor(CISCO_CONFIG) == "cisco-ios"
    assert detect_vendor(JUNIPER_CONFIG) == "juniper"
    assert detect_vendor(ARISTA_CONFIG) == "arista"


def test_parser_registry_multivendor():
    ParserRegistry.autodiscover()
    supported = ParserRegistry.supported_vendors()
    assert "cisco-ios" in supported
    assert "juniper" in supported
    assert "arista" in supported


def test_cisco_ios_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "cisco.cfg"
        file_path.write_text(CISCO_CONFIG, encoding="utf-8")

        result = Analyzer().run(file_path, vendor="auto")
        assert result.vendor == "cisco-ios"
        assert result.file_path == file_path.resolve()


def test_juniper_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "juniper.conf"
        file_path.write_text(JUNIPER_CONFIG, encoding="utf-8")

        result = Analyzer().run(file_path, vendor="auto")
        assert result.vendor == "juniper"
        assert result.file_path == file_path.resolve()


def test_arista_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "arista.cfg"
        file_path.write_text(ARISTA_CONFIG, encoding="utf-8")

        result = Analyzer().run(file_path, vendor="auto")
        assert result.vendor == "arista"
        assert result.file_path == file_path.resolve()
