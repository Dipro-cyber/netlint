"""
Rules subpackage — all lint rules live here.

Each rule is its own module.  The ``@RuleRegistry.register`` decorator
at the top of each class auto-enrolls it when the module is imported.
:meth:`~netlint.rules.registry.RuleRegistry.autodiscover` imports every
module in this package so you never need to maintain an explicit list.

Rule ID naming convention
-------------------------
SEC  — Security rules
NET  — General network / IP rules
VLN  — VLAN rules
RTG  — Routing rules
ACL  — ACL rules
MGT  — Management rules
"""

from netlint.rules.registry import RuleRegistry

__all__ = ["RuleRegistry"]
