"""
Tests for multi-extension file support and directory file discovery.

Supported extensions: .cfg, .conf, .config, .txt, .ios, .set, .log
Custom extensions: supported when explicitly provided.
"""

import tempfile
from pathlib import Path

import pytest
from netlint.analyzer.analyzer import Analyzer
from netlint.models.config_file import ConfigFile
from netlint.utils import (
    SUPPORTED_CONFIG_EXTENSIONS,
    is_supported_config_file,
    resolve_config_files,
)

SAMPLE_CONFIG = """! Cisco IOS test config
hostname TEST-ROUTER
service password-encryption
ip ssh version 2
interface GigabitEthernet0/0
 description Test Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
ip route 0.0.0.0 0.0.0.0 192.168.1.254
ip access-list extended MGMT_ACL
 10 permit tcp 192.168.1.0 0.0.0.255 any eq 22
 20 deny ip any any
line vty 0 4
 access-class MGMT_ACL in
 transport input ssh
 login local
end
"""


def test_supported_extensions_tuple():
    expected = (".cfg", ".conf", ".config", ".txt", ".ios", ".set", ".log")
    for ext in expected:
        assert ext in SUPPORTED_CONFIG_EXTENSIONS
        assert is_supported_config_file(f"router{ext}")
        assert is_supported_config_file(f"ROUTER{ext.upper()}")


@pytest.mark.parametrize("ext", [".cfg", ".conf", ".config", ".txt", ".ios", ".set", ".log", ".backup"])
def test_analyzer_runs_on_various_extensions(ext: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / f"device_config{ext}"
        config_path.write_text(SAMPLE_CONFIG, encoding="utf-8")

        # Test ConfigFile.from_path
        cf = ConfigFile.from_path(config_path)
        assert cf.file_path == config_path.resolve()

        # Test Analyzer.run
        result = Analyzer().run(config_path)
        assert result.file_path == config_path.resolve()
        assert result.findings == ()  # Clean config


def test_directory_discovery_all_extensions():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        extensions = [".cfg", ".conf", ".config", ".txt", ".ios", ".set", ".log"]
        created_files = []

        for i, ext in enumerate(extensions):
            file_p = tmp_path / f"device_{i}{ext}"
            file_p.write_text(SAMPLE_CONFIG, encoding="utf-8")
            created_files.append(file_p.resolve())

        # Non-config file that should be ignored during directory scan
        (tmp_path / "script.py").write_text("print('hello')", encoding="utf-8")
        (tmp_path / "image.png").write_text("fake binary data", encoding="utf-8")

        resolved = resolve_config_files(tmp_path)
        assert len(resolved) == len(extensions)
        assert sorted(resolved) == sorted(created_files)


def test_analyzer_run_path_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "r1.conf").write_text(SAMPLE_CONFIG, encoding="utf-8")
        (tmp_path / "sw1.ios").write_text(SAMPLE_CONFIG, encoding="utf-8")

        results = Analyzer().run_path(tmp_path)
        assert len(results) == 2
        for res in results:
            assert res.findings == ()
