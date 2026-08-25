"""
Comprehensive test suite for NetLint Extension Registry & Input Handling.

Tests:
1. Every newly supported extension (.yaml, .yml, .json, .xml, .cli, .backup, .bak, .running, .startup, .rsc, .junos, .nxos, .eos, .vyos)
2. Uppercase extensions (.CFG, .YML, .JSON)
3. Unknown extensions (.xyz, .foo)
4. Files with no extension (e.g., core-router-1)
5. Misleading extensions (e.g., Cisco config saved as router.json or switch.junos)
6. Empty files
7. Malformed structured files (bad JSON, bad XML, bad YAML)
8. Existing .cfg files
"""

import tempfile
from pathlib import Path

import pytest
from netlint.analyzer.analyzer import Analyzer
from netlint.exceptions import ParseError
from netlint.registry.extension_registry import ExtensionRegistry
from netlint.utils import resolve_config_files

CISCO_SAMPLE = """! Cisco IOS sample config
hostname TEST-CORE-01
service password-encryption
ip ssh version 2
interface GigabitEthernet0/0
 description Core Link
 ip address 10.0.0.1 255.255.255.0
 no shutdown
ip route 0.0.0.0 0.0.0.0 10.0.0.254
ip access-list extended VTY_ACC
 10 permit tcp 10.0.0.0 0.0.0.255 any eq 22
 20 deny ip any any
line vty 0 4
 access-class VTY_ACC in
 transport input ssh
 login local
end
"""

NEW_EXTENSIONS = [
    ".yaml", ".yml", ".json", ".xml", ".cli", ".backup", ".bak",
    ".running", ".startup", ".rsc", ".junos", ".nxos", ".eos", ".vyos"
]


def test_registry_contains_all_extensions():
    all_exts = ExtensionRegistry.all_supported_extensions()
    for ext in NEW_EXTENSIONS:
        assert ext in all_exts
        meta = ExtensionRegistry.get(ext)
        assert meta is not None
        assert meta.extension == ext


@pytest.mark.parametrize("ext", NEW_EXTENSIONS)
def test_newly_supported_extensions_analysis(ext: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / f"device_config{ext}"
        if ext in (".json", ".yaml", ".yml", ".xml"):
            # Provide simple valid structured syntax for structured files
            if ext in (".json",):
                config_path.write_text('{"hostname": "DEV-01"}', encoding="utf-8")
            elif ext in (".yaml", ".yml"):
                config_path.write_text("hostname: DEV-01\ninterfaces:\n  - name: eth0", encoding="utf-8")
            elif ext in (".xml",):
                config_path.write_text("<config><hostname>DEV-01</hostname></config>", encoding="utf-8")
        else:
            config_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        result = Analyzer().run(config_path, vendor="auto")
        assert result.file_path == config_path.resolve()


@pytest.mark.parametrize("ext", [".CFG", ".YML", ".JSON", ".CONF", ".EOS"])
def test_uppercase_extensions(ext: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / f"DEVICE_CONFIG{ext}"
        if ext.lower() == ".json":
            config_path.write_text('{"device": "test"}', encoding="utf-8")
        elif ext.lower() == ".yml":
            config_path.write_text("device: test", encoding="utf-8")
        else:
            config_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        result = Analyzer().run(config_path)
        assert result.file_path == config_path.resolve()


@pytest.mark.parametrize("ext", [".xyz", ".foo", ".unrecognized"])
def test_unknown_extensions(ext: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / f"my_device{ext}"
        config_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        # Direct file input must still be accepted and analyzed
        files = resolve_config_files(config_path)
        assert len(files) == 1
        assert files[0] == config_path.resolve()

        result = Analyzer().run(config_path)
        assert result.file_path == config_path.resolve()
        assert result.vendor == "cisco-ios"  # Auto-detected from content


def test_files_with_no_extension():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "core-router-1"
        config_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        files = resolve_config_files(config_path)
        assert len(files) == 1

        result = Analyzer().run(config_path)
        assert result.file_path == config_path.resolve()
        assert result.vendor == "cisco-ios"


def test_misleading_extensions():
    # Cisco IOS config saved as router.json or switch.junos
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "router.json"
        json_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        # Content auto-detector identifies Cisco IOS syntax from body
        result = Analyzer().run(json_path, vendor="auto")
        assert result.vendor == "cisco-ios"


def test_empty_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_path = Path(tmpdir) / "empty_device.cfg"
        empty_path.write_text("", encoding="utf-8")

        result = Analyzer().run(empty_path)
        assert result.file_path == empty_path.resolve()
        assert len(result.findings) == 0


def test_malformed_json_structured_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_json = Path(tmpdir) / "invalid.json"
        bad_json.write_text('{"hostname": "DEV-01", invalid_json}', encoding="utf-8")

        with pytest.raises(ParseError) as exc_info:
            Analyzer().run(bad_json)
        assert "Invalid JSON syntax" in str(exc_info.value)


def test_malformed_xml_structured_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_xml = Path(tmpdir) / "invalid.xml"
        bad_xml.write_text("<config><hostname>DEV-01</config>", encoding="utf-8")

        with pytest.raises(ParseError) as exc_info:
            Analyzer().run(bad_xml)
        assert "Invalid XML syntax" in str(exc_info.value)


def test_malformed_yaml_structured_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_yaml = Path(tmpdir) / "invalid.yaml"
        bad_yaml.write_text("hostname: DEV-01\n\tbad_tab_indentation: true", encoding="utf-8")

        with pytest.raises(ParseError) as exc_info:
            Analyzer().run(bad_yaml)
        assert "Invalid YAML syntax" in str(exc_info.value)


def test_existing_cfg_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "standard_router.cfg"
        cfg_path.write_text(CISCO_SAMPLE, encoding="utf-8")

        result = Analyzer().run(cfg_path)
        assert result.file_path == cfg_path.resolve()
        assert result.vendor == "cisco-ios"
        assert len(result.findings) == 0
