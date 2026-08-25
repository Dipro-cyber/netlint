"""
RuleRegistry — central registry for all lint rules.

Rules register themselves by decorating their class with
``@RuleRegistry.register``::

    @RuleRegistry.register
    class MyRule(Rule):
        rule_id = "NET001"
        ...

The registry uses the class-level attributes (``rule_id``, ``vendors``,
``category``, ``severity``) for lookups — it never instantiates a rule
just to read its metadata, so ``get_for_vendor`` is cheap.

Auto-discovery
--------------
Call :meth:`RuleRegistry.autodiscover` once (typically from the Analyzer)
to import every module under ``netlint.rules`` so that decorated classes
are registered without any explicit import list.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netlint.models.rule import Rule


class RuleRegistry:
    """Central registry for lint rules."""

    _rules: dict[str, type[Rule]] = {}
    """Maps rule_id → rule class.  Insertion order is preserved (Python 3.7+)."""

    _discovered: bool = False

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    @classmethod
    def register(cls, rule_cls: type[Rule]) -> type[Rule]:
        """
        Register *rule_cls*.  Works as a class decorator::

            @RuleRegistry.register
            class MyRule(Rule): ...

        Raises ``ValueError`` on duplicate ``rule_id``.
        """
        rule_id: str = getattr(rule_cls, "rule_id", "")
        if not rule_id:
            raise ValueError(
                f"Rule class {rule_cls.__name__} must define a non-empty 'rule_id'."
            )
        if rule_id in cls._rules:
            existing = cls._rules[rule_id]
            if existing is not rule_cls:
                raise ValueError(
                    f"Duplicate rule_id '{rule_id}': already registered by "
                    f"{existing.__module__}.{existing.__name__}."
                )
            # Same class registered twice (e.g. module re-imported) — idempotent.
        cls._rules[rule_id] = rule_cls
        return rule_cls

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    @classmethod
    def get_for_vendor(cls, vendor: str) -> list[type[Rule]]:
        """
        Return all rule classes whose ``vendors`` tuple includes *vendor*.

        Uses class-level attributes — no rule instances are created.
        """
        return [
            r for r in cls._rules.values()
            if vendor in getattr(r, "vendors", ())
        ]

    @classmethod
    def all_rules(cls) -> list[type[Rule]]:
        """Return every registered rule class in insertion order."""
        return list(cls._rules.values())

    @classmethod
    def get(cls, rule_id: str) -> type[Rule] | None:
        """Return the rule class for *rule_id*, or ``None`` if not found."""
        return cls._rules.get(rule_id)

    @classmethod
    def supported_vendors(cls) -> list[str]:
        """Return a sorted deduplicated list of all vendor strings across all rules."""
        vendors: set[str] = set()
        for rule in cls._rules.values():
            vendors.update(getattr(rule, "vendors", ()))
        return sorted(vendors)

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    @classmethod
    def autodiscover(cls) -> None:
        """
        Import every module under ``netlint.rules`` so that
        ``@RuleRegistry.register`` decorators execute and rules are
        enrolled in the registry.

        Safe to call multiple times — discovery runs only once per
        process.  Call this from the Analyzer before executing rules.
        """
        if cls._discovered:
            return
        cls._discovered = True

        import netlint.rules as rules_pkg

        for module_info in pkgutil.walk_packages(
            path=rules_pkg.__path__,
            prefix=rules_pkg.__name__ + ".",
            onerror=lambda _name: None,
        ):
            if not module_info.ispkg:
                try:
                    importlib.import_module(module_info.name)
                except Exception as exc:  # noqa: BLE001
                    # Non-fatal — log and continue so one bad rule
                    # does not block the whole analysis.
                    import warnings
                    warnings.warn(
                        f"netlint: failed to import rule module "
                        f"'{module_info.name}': {exc}",
                        stacklevel=2,
                    )

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    @classmethod
    def _reset(cls) -> None:
        """
        Clear all registered rules and reset discovery state.

        **For use in tests only.**  Do not call in production code.

        Also removes netlint rule modules from ``sys.modules`` so that
        the next :meth:`autodiscover` call re-imports them and their
        ``@register`` decorators fire again.
        """
        import sys
        cls._rules = {}
        cls._discovered = False
        # Evict already-imported netlint rule modules so autodiscover
        # will re-execute their @RuleRegistry.register decorators.
        to_remove = [
            name for name in sys.modules
            if name.startswith("netlint.rules.") and name != "netlint.rules.registry"
        ]
        for name in to_remove:
            del sys.modules[name]
