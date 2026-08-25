# netlint

Static analyzer for network device configuration files.

netlint inspects Cisco IOS (and future vendor) configs **before deployment**
and catches problems like:

- Duplicate IP addresses
- Overlapping subnets
- Undefined VLANs / VLAN inconsistencies
- Insecure management protocols (Telnet, HTTP, SNMPv1/v2)
- Dangerous ACL configurations
- Routing conflicts
- General configuration inconsistencies

---

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

---

## Installation

### Development install (editable)

```bash
# Using uv (recommended)
uv venv
uv pip install -e ".[dev]"

# Using pip
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Supported File Extensions & Formats

netlint maintains a centralized extension registry decoupling file extensions from vendor identification. Custom extensions (e.g. `router.backup`), files with uppercase extensions (`.CFG`, `.YML`), unknown extensions (`.xyz`), and files without extensions are also fully supported when specified directly.

| Extension | Format | Vendor | Parser Status |
|---|---|---|---|
| `.cfg` | CLI | Cisco IOS, Arista, VyOS | Fully supported (Cisco IOS) |
| `.conf` | CLI | BGP/FRR, Juniper, OpenWRT | Fully supported (Cisco) / Partial (Juniper) |
| `.config` | CLI | Generic network configs | Text CLI fallback / Fully supported (Cisco) |
| `.txt` | CLI | Plain text config exports | Text CLI fallback |
| `.ios` | CLI | Cisco IOS / IOS-XE | Fully supported |
| `.set` | CLI | Juniper JunOS | Partial (JunOS set commands) |
| `.log` | CLI | Console / session logs | Text CLI fallback |
| `.cli` | CLI | Generic network CLI | Text CLI fallback |
| `.backup` | CLI | Backup configuration | Text CLI fallback |
| `.bak` | CLI | Backup configuration | Text CLI fallback |
| `.running` | CLI | Running configuration | Text CLI fallback |
| `.startup` | CLI | Startup configuration | Text CLI fallback |
| `.junos` | CLI | Juniper JunOS | Partial (JunOS parser) |
| `.nxos` | CLI | Cisco NX-OS | Recognized (Text fallback active) |
| `.eos` | CLI | Arista EOS | Partial (Arista parser) |
| `.vyos` | CLI | VyOS | Recognized (Text fallback active) |
| `.rsc` | MikroTik Script | MikroTik RouterOS | Recognized (Text fallback active) |
| `.yaml` | YAML | VyOS, Ansible | Recognized (Structured syntax check active) |
| `.yml` | YAML | VyOS, Ansible | Recognized (Structured syntax check active) |
| `.json` | JSON | Generic structured | Recognized (Structured syntax check active) |
| `.xml` | XML | Juniper JunOS XML | Recognized (Structured syntax check active) |

---

## Usage

```bash
netlint --help
netlint --version

# Analyze configuration files (.cfg, .conf, .config, .txt, .ios, .set, .log)
netlint analyze  router.cfg
netlint analyze  switch.conf
netlint analyze  core.ios
netlint analyze  configs/          # Scans directory for all network config files

# CI/CD check mode
netlint check    router.cfg
netlint check    configs/

# Config diffing & risk assessment
netlint diff     old.cfg new.conf

# List all rules
netlint rules

# Structured JSON reports
netlint report   router.cfg --format json
```

---

## Development

### Run tests

```bash
pytest
pytest --cov          # with coverage
```

### Lint & format

```bash
ruff check src tests  # lint
ruff format src tests # format
```

### Project layout

```
src/netlint/
├── cli.py            # Typer CLI entry point
├── exceptions.py     # Custom exception types
├── models/           # Pydantic domain models (ConfigFile, LintIssue, Rule …)
├── parser/           # Vendor-specific config parsers + registry
├── rules/            # Lint rules + registry
├── analyzer/         # Orchestrates parsing + rule execution
├── diff/             # Semantic config diffing
└── output/           # Output formatters (text, JSON …) + registry

tests/
├── test_cli.py
├── test_models.py
└── test_registries.py
```

---

## Adding a new vendor

1. Create `src/netlint/parser/<vendor>.py` implementing `BaseParser`.
2. Register it: `ParserRegistry.register("<vendor-id>", MyParser)`.
3. Add rules in `src/netlint/rules/` that declare `vendors=("<vendor-id>",)` in their `RuleMetadata`.

---

## License

MIT
