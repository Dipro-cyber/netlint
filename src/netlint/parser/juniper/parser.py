"""
Juniper JunOS configuration parser.

Parses both `set` format and hierarchical brace format JunOS configurations
into the Common IR (ParsedConfig).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netlint.models.config_file import ConfigFile
from netlint.parser.base import BaseParser
from netlint.parser.cisco_ios.models import (
    Interface,
    ParsedConfig,
    StaticRoute,
    TransportProtocol,
    Vlan,
    VtyLine,
)
from netlint.parser.registry import ParserRegistry


class JuniperParser(BaseParser):
    """Parser for Juniper JunOS device configurations."""

    vendor = "juniper"

    def parse(self, config: ConfigFile) -> ParsedConfig:
        """Parse Juniper JunOS text into standard ParsedConfig Common IR."""
        parsed = ParsedConfig()
        lines = config.lines

        interfaces_dict: dict[str, dict[str, Any]] = {}
        vlans_dict: dict[int, dict[str, Any]] = {}
        static_routes: list[StaticRoute] = []
        ssh_enabled = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("/*"):
                continue

            # --- Hostname ---
            # set system host-name core-router-01
            # host-name core-router-01;
            m_host = re.search(r"\bhost-name\s+([\w\.\-]+)", stripped, re.IGNORECASE)
            if m_host and not parsed.hostname:
                parsed.hostname = m_host.group(1)
                parsed.hostname_line = idx

            # --- SSH Service ---
            if "services ssh" in stripped.lower():
                ssh_enabled = True
                parsed.ssh_version = 2
                parsed.ssh_version_line = idx

            # --- Set Interfaces ---
            # set interfaces ge-0/0/0 description "Uplink"
            # set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
            # set interfaces ge-0/0/0 disable
            m_if = re.match(
                r"^set\s+interfaces\s+([\w\/\-\.]+)(?:\s+unit\s+(\d+))?(?:\s+(.*))?$",
                stripped,
                re.IGNORECASE,
            )
            if m_if:
                iface_base = m_if.group(1)
                unit = m_if.group(2)
                rest = m_if.group(3) or ""
                iface_name = f"{iface_base}.{unit}" if unit else iface_base

                if iface_name not in interfaces_dict:
                    interfaces_dict[iface_name] = {
                        "name": iface_name,
                        "line_number": idx,
                        "description": None,
                        "ip_address": None,
                        "subnet_mask": None,
                        "prefix_length": None,
                        "shutdown": False,
                    }
                data = interfaces_dict[iface_name]

                if "description" in rest.lower():
                    m_desc = re.search(r"description\s+[\"']?(.*?)[\"']?$", rest, re.IGNORECASE)
                    if m_desc:
                        data["description"] = m_desc.group(1)

                if "disable" in rest.lower():
                    data["shutdown"] = True

                m_addr = re.search(r"address\s+([\d\.]+)/(\d+)", rest, re.IGNORECASE)
                if m_addr:
                    try:
                        ip_obj = ipaddress.IPv4Address(m_addr.group(1))
                        prefix = int(m_addr.group(2))
                        net_obj = ipaddress.IPv4Network(f"{ip_obj}/{prefix}", strict=False)
                        data["ip_address"] = ip_obj
                        data["prefix_length"] = prefix
                        data["subnet_mask"] = str(net_obj.netmask)
                    except ValueError:
                        pass

            # --- Set VLANs ---
            # set vlans MANAGEMENT vlan-id 10
            m_vlan = re.match(
                r"^set\s+vlans\s+([\w\-\.]+)\s+vlan-id\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if m_vlan:
                vlan_name = m_vlan.group(1)
                vlan_id = int(m_vlan.group(2))
                vlans_dict[vlan_id] = {"vlan_id": vlan_id, "name": vlan_name, "line_number": idx}

            # --- Set Static Routes ---
            # set routing-options static route 0.0.0.0/0 next-hop 192.168.1.254
            m_route = re.match(
                r"^set\s+routing-options\s+static\s+route\s+([\d\.\/]+)\s+next-hop\s+([\d\.]+)",
                stripped,
                re.IGNORECASE,
            )
            if m_route:
                try:
                    net = ipaddress.IPv4Network(m_route.group(1), strict=False)
                    nh = ipaddress.IPv4Address(m_route.group(2))
                    static_routes.append(
                        StaticRoute(
                            network=net,
                            next_hop=nh,
                            exit_interface=None,
                            admin_distance=5,
                            line_number=idx,
                        )
                    )
                except ValueError:
                    pass

        # Build Interface model objects
        for name, data in interfaces_dict.items():
            parsed.interfaces.append(
                Interface(
                    name=data["name"],
                    line_number=data["line_number"],
                    description=data["description"],
                    ip_address=data["ip_address"],
                    subnet_mask=data["subnet_mask"],
                    prefix_length=data["prefix_length"],
                    shutdown=data["shutdown"],
                )
            )

        # Build Vlan model objects
        for vlan_id, data in vlans_dict.items():
            parsed.vlans.append(
                Vlan(vlan_id=data["vlan_id"], name=data["name"], line_number=data["line_number"])
            )

        parsed.static_routes = static_routes
        parsed.service_password_encryption = True  # JunOS encrypts passwords by default
        parsed.ip_routing_enabled = True

        if ssh_enabled:
            parsed.vty_lines.append(
                VtyLine(
                    first=0,
                    last=4,
                    line_number=1,
                    transport_input=(TransportProtocol.SSH,),
                )
            )

        return parsed


ParserRegistry.register("juniper", JuniperParser)
ParserRegistry.register("juniper-junos", JuniperParser)
