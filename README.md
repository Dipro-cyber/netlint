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

## Supported File Extensions

netlint automatically discovers and supports all standard network configuration file extensions:

- `.cfg` (Cisco, VyOS, Fortinet)
- `.conf` (BGP/FRR, OpenWRT, Arista)
- `.config` (Generic network configs)
- `.txt` (Plain text config exports)
- `.ios` (Cisco IOS / IOS-XE exports)
- `.set` (Juniper set-format configs)
- `.log` (Console / terminal session logs)

*Note: Custom extensions (e.g. `router.backup`) are also fully supported when specified directly.*

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
