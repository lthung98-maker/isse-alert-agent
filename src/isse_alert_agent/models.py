"""The agent's own alert model.

Deliberately its own, not imported from ``isse``. The alert agent is decoupled from
the ISSE pipeline (see README, "The contract"): the two repositories share a *data
contract* - the common alert schema payload carried on a ServiceDesk request - not
code. This model is the agent's internal shape between reading an alert from Azure and
serialising it back to that contract in :mod:`isse_alert_agent.cas`.

It mirrors the fields ISSE's own ``Alert`` reads back, and only those. Anything ISSE
does not read from the payload has no reason to exist here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Azure's five severities, in Azure's own words. Rendered on the request subject
# because "Sev1" tells a human nothing.
SEVERITY_MEANING: dict[str, str] = {
    "Sev0": "critical",
    "Sev1": "error",
    "Sev2": "warning",
    "Sev3": "informational",
    "Sev4": "verbose",
}


def severity_meaning(severity: Optional[str]) -> str:
    """"Sev1 (error)", or the raw value if Azure ever adds a sixth."""
    if not severity:
        return ""
    label = SEVERITY_MEANING.get(str(severity).strip().title())
    return f"{severity} ({label})" if label else str(severity)


def severity_rank(severity: Optional[str]) -> Optional[int]:
    """0 (critical) to 4 (verbose) from "Sev2" or "2", or None if it names no severity."""
    m = re.fullmatch(r"\s*(?:sev)?\s*([0-4])\s*", str(severity or ""), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _arm_part(resource_id: Optional[str], segment: str) -> Optional[str]:
    """The value following ``segment`` in an ARM resource id, case-insensitively."""
    parts = str(resource_id or "").strip("/").split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() == segment.lower():
            return parts[i + 1] or None
    return None


@dataclass
class AlertCondition:
    """One condition of the rule that fired, with the threshold somebody chose.

    The threshold is the only number anyone has written down for how much is too much,
    so it is carried through to the request verbatim and never invented.
    """

    metric: Optional[str] = None
    operator: Optional[str] = None        # GreaterThan, LessThan, ...
    threshold: Optional[float] = None
    observed: Optional[float] = None      # value when the rule fired
    aggregation: Optional[str] = None     # Average, Total, Count, Maximum, Minimum
    window: Optional[str] = None          # ISO-8601 duration the aggregation covers
    dimensions: list = field(default_factory=list)  # [{"name","value"}]

    def describe(self) -> str:
        parts = [self.metric or "an unnamed signal"]
        if self.aggregation:
            parts.append(f"({self.aggregation}"
                         + (f" over {self.window}" if self.window else "") + ")")
        if self.operator:
            parts.append(_spaced(self.operator))
        if self.threshold is not None:
            parts.append(f"{self.threshold:g}")
        text = " ".join(parts)
        if self.observed is not None:
            text += f", observed {self.observed:g} when it fired"
        for dim in self.dimensions or []:
            if isinstance(dim, dict) and dim.get("name"):
                text += f", where {dim.get('name')}={dim.get('value')}"
        return text


@dataclass
class Alert:
    """One Azure Monitor alert, as the agent reads it from Azure's alert store."""

    rule: Optional[str] = None
    alert_id: Optional[str] = None
    severity: Optional[str] = None            # Sev0 (critical) .. Sev4 (verbose)
    signal_type: Optional[str] = None         # Metric | Log | Activity Log
    monitor_condition: Optional[str] = None   # Fired | Resolved
    monitoring_service: Optional[str] = None  # Platform | Log Analytics | ...
    alert_state: Optional[str] = None         # New | Acknowledged | Closed
    fired_at: Optional[str] = None
    resolved_at: Optional[str] = None
    description: Optional[str] = None
    target_ids: list = field(default_factory=list)
    configuration_items: list = field(default_factory=list)
    conditions: list = field(default_factory=list)  # AlertCondition
    source: str = "read from Azure's alert store (Microsoft.AlertsManagement)"

    @property
    def fired(self) -> bool:
        return "fired" in (self.monitor_condition or "").strip().lower()

    @property
    def severity_rank(self) -> Optional[int]:
        """0 (critical) to 4 (verbose), or None if the alert carries no severity."""
        return severity_rank(self.severity)

    @property
    def target_id(self) -> Optional[str]:
        """The first virtual machine the alert names, or its first target of any kind."""
        for target in self.target_ids:
            if "/virtualmachines/" in str(target).lower():
                return str(target)
        return str(self.target_ids[0]) if self.target_ids else None

    @property
    def subscription(self) -> Optional[str]:
        return _arm_part(self.target_id, "subscriptions")

    @property
    def resource_group(self) -> Optional[str]:
        return _arm_part(self.target_id, "resourcegroups")

    @property
    def vm_name(self) -> Optional[str]:
        target = self.target_id or ""
        if "/virtualmachines/" not in target.lower():
            return None
        return target.rstrip("/").rsplit("/", 1)[-1] or None

    @property
    def machine_name(self) -> Optional[str]:
        """The VM's name in the case it was created with, where the alert carries it.

        The target id is often lower-cased by the monitor; the resource name is not.
        """
        vm = self.vm_name
        for item in self.configuration_items:
            if vm and str(item).lower() == vm.lower():
                return str(item)
        return vm

    def summary(self) -> str:
        """One line naming the rule, its urgency and where it stands."""
        bits = [f"'{self.rule}'" if self.rule else "an unnamed rule"]
        detail = [b for b in (self.severity,
                              self.signal_type and f"{self.signal_type} signal",
                              self.monitor_condition) if b]
        if detail:
            bits.append("(" + ", ".join(detail) + ")")
        if self.fired_at:
            bits.append(f"fired {self.fired_at}")
        if self.resolved_at:
            bits.append(f"resolved {self.resolved_at}")
        return " ".join(bits)


def _spaced(camel: str) -> str:
    """"GreaterThan" as "greater than", so a rendered condition reads as a sentence."""
    return re.sub(r"(?<!^)(?=[A-Z])", " ", str(camel or "")).lower().strip()
