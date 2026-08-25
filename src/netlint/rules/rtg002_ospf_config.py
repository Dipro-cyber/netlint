"""
RTG-002 — OSPF configuration problems.

Checks for common OSPF misconfigurations: missing backbone area 0,
processes with no networks, and missing router-id on multi-area designs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from netlint.models.finding import RuleCategory, Severity
from netlint.models.rule import Rule
from netlint.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from netlint.models.config_file import ConfigFile
    from netlint.models.finding import Finding
    from netlint.parser.cisco_ios.models import ParsedConfig


def _ospf_areas(parsed: ParsedConfig, process_id: str) -> set[str]:
    """Collect all OSPF areas for a process from networks and interfaces."""
    areas: set[str] = set()
    for proc in parsed.ospf_processes:
        if proc.process_id != process_id:
            continue
        for net in proc.networks:
            areas.add(net.area)
    for iface in parsed.interfaces:
        if iface.ospf_process_id == process_id and iface.ospf_area:
            areas.add(iface.ospf_area)
    return areas


@RuleRegistry.register
class OspfConfigRule(Rule):
    """Detect common OSPF configuration issues."""

    rule_id = "RTG002"
    title = "OSPF configuration problem"
    description = (
        "The OSPF configuration has a structural problem such as a "
        "missing backbone area 0, no network statements, or no router-id."
    )
    category = RuleCategory.ROUTING
    severity = Severity.HIGH
    recommendation = (
        "Ensure OSPF area 0 (backbone) is configured, all areas connect "
        "to the backbone, and a stable router-id is set under "
        "'router ospf <pid>'."
    )
    vendors = ("cisco-ios", "juniper", "arista", "juniper-junos", "arista-eos")

    def check(
        self,
        config: ConfigFile,
        parsed: ParsedConfig | None,
    ) -> list[Finding]:
        if parsed is None or not parsed.ospf_processes:
            return []

        findings: list[Finding] = []

        for proc in parsed.ospf_processes:
            areas = _ospf_areas(parsed, proc.process_id)
            iface_areas = [
                iface
                for iface in parsed.interfaces
                if iface.ospf_process_id == proc.process_id
            ]
            has_networks = bool(proc.networks) or bool(iface_areas)

            if not has_networks:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"OSPF process {proc.process_id} has no "
                            f"'network' statements or interface OSPF "
                            f"assignments."
                        ),
                        line_number=proc.line_number,
                        configuration_line=f"router ospf {proc.process_id}",
                    )
                )
                continue

            if areas and "0" not in areas:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"OSPF process {proc.process_id} has no "
                            f"interfaces or networks in area 0 (backbone)."
                        ),
                        line_number=proc.line_number,
                        configuration_line=f"router ospf {proc.process_id}",
                    )
                )

            if len(areas) > 1 and proc.router_id is None:
                findings.append(
                    self.finding(
                        config=config,
                        message=(
                            f"OSPF process {proc.process_id} spans "
                            f"multiple areas but has no explicit "
                            f"'router-id' configured."
                        ),
                        line_number=proc.line_number,
                        configuration_line=f"router ospf {proc.process_id}",
                        severity=Severity.MEDIUM,
                    )
                )

        return findings
