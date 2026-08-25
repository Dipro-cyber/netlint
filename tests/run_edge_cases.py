"""
Run netlint analyze against all edge-case fixtures and print a full report.
Run as: python tests/run_edge_cases.py
"""

import json
import sys
import time
from pathlib import Path

# Ensure src/ is on the path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from typer.testing import CliRunner

from netlint.cli import app
from netlint.rules.registry import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"

EDGE_FIXTURES = [
    ("edge_vrf.cfg",              "VRF same-IP — expect 0 or documented FP"),
    ("edge_subinterfaces.cfg",    "Subinterfaces — expect 0 findings"),
    ("edge_secondary_ip.cfg",     "Secondary IP — expect 0 findings"),
    ("edge_acl.cfg",              "ACL edge cases — expect 0 findings"),
    ("edge_vty_multi.cfg",        "Multiple VTY — expect 0 findings"),
    ("edge_weird_names.cfg",      "Weird interface names — no crash, 0 findings"),
    ("edge_unknown_commands.cfg", "Unknown IOS commands — no crash, 0 findings"),
    ("edge_incomplete.cfg",       "Incomplete config — no crash, warnings ok"),
    ("edge_overlapping_slash30.cfg", "Precise overlap /29//30//32 — NET002 expected"),
    ("large.cfg",                 "Large config — no crash, check performance"),
]

runner = CliRunner()

print("=" * 80)
print("NetLint Edge-Case Fixture Run")
print("=" * 80)

all_passed = True

for filename, description in EDGE_FIXTURES:
    path = FIXTURES / filename
    RuleRegistry._reset()

    print(f"\n{'─'*80}")
    print(f"FIXTURE : {filename}")
    print(f"PURPOSE : {description}")

    t0 = time.perf_counter()
    result = runner.invoke(
        app,
        ["analyze", str(path), "--format", "json"],
        catch_exceptions=False,
    )
    elapsed = time.perf_counter() - t0

    if result.exit_code == 4:
        print(f"STATUS  : *** CRASH / ERROR (exit 4) ***")
        print(f"OUTPUT  : {result.output[:500]}")
        all_passed = False
        continue

    try:
        doc = json.loads(result.output)
    except json.JSONDecodeError as e:
        print(f"STATUS  : *** INVALID JSON ({e}) ***")
        print(f"RAW     : {result.output[:300]}")
        all_passed = False
        continue

    findings = doc.get("findings", [])
    warnings = doc.get("parser_warnings", [])

    print(f"EXIT    : {result.exit_code}")
    print(f"SCORE   : {doc.get('risk_score')}/100  LEVEL: {doc.get('risk_level')}")
    print(f"FINDINGS: {len(findings)}   WARNINGS: {len(warnings)}   TIME: {elapsed*1000:.1f}ms")

    if findings:
        for f in findings:
            ln = f.get("line_number", "?")
            msg = f["message"][:72]
            print(f"  [{f['severity'].upper():8}] {f['rule_id']:8} L{ln:>4}  {msg}")

    if warnings:
        for w in warnings:
            print(f"  WARN: {w[:76]}")

print(f"\n{'='*80}")
print(f"{'ALL PASSED' if all_passed else 'FAILURES DETECTED'}")
print("=" * 80)
sys.exit(0 if all_passed else 1)
