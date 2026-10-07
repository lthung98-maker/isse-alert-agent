"""The customer register: which subscriptions belong to which customer, and where their
requests go.

One agent reads every customer's subscriptions through a single Azure identity (Azure
Lighthouse delegates ``Monitoring Reader`` on each customer subscription to it) and files
into one ServiceDesk portal, a queue per customer. What keeps customers apart is this
file, so it is validated strictly at load: a subscription listed under two customers
would let one alert land in two queues, and that is refused rather than resolved.

Without a register file the agent runs for one customer from the environment
(``AZURE_SUBSCRIPTION_ID``, ``ISSE_SANDBOX_RESOURCE_GROUP``, ``SDP_QUEUE``), which is the
single-customer deployment it started as.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Settings, get_settings
from .models import severity_rank

_SINGLE = "default"


class RegisterError(ValueError):
    """The register cannot be trusted to route alerts. Nothing is filed until it is fixed."""


@dataclass(frozen=True)
class Subscription:
    id: str
    # Resource groups whose alerts are filed. Empty means the whole subscription.
    resource_groups: tuple[str, ...] = ()

    def owns(self, subscription_id: Optional[str]) -> bool:
        return bool(subscription_id) and subscription_id.strip().lower() == self.id.lower()

    def scoped_group(self, resource_group: Optional[str]) -> Optional[str]:
        """The register's spelling of ``resource_group``, or None if it is out of scope.

        Azure Monitor often lower-cases the resource ids it reports, and ISSE's guardrail
        compares the request's resource group against its scope exactly. Writing the
        monitor's spelling onto the request would have ISSE refuse an in-scope machine,
        so the request carries the register's own spelling. With no groups listed the
        whole subscription is in scope and the monitor's spelling is all there is.
        """
        if not resource_group:
            return None
        if not self.resource_groups:
            return resource_group
        wanted = resource_group.strip().lower()
        return next((g for g in self.resource_groups if g.lower() == wanted), None)


@dataclass(frozen=True)
class Customer:
    name: str
    # The ServiceDesk group (queue) this customer's requests are filed into, and the
    # queue that customer's ISSE instance watches.
    queue: str
    subscriptions: tuple[Subscription, ...]
    # Least-severe Sev rank filed: 0 is critical only, 4 is everything.
    min_severity: int = 2
    # The customer's SLA, as the ServiceDesk priority to open a request at for each
    # alert severity. Optional: unmapped severities are filed with the portal default.
    # ISSE only ever raises a priority, so this is a floor, never a cap.
    priority_by_severity: dict[str, str] = field(default_factory=dict, hash=False)

    def priority_for(self, severity: Optional[str]) -> Optional[str]:
        rank = severity_rank(severity)
        return None if rank is None else self.priority_by_severity.get(f"Sev{rank}")


@dataclass(frozen=True)
class Register:
    customers: tuple[Customer, ...]
    source: str

    def owner_of(self, subscription_id: Optional[str]) -> Optional[Customer]:
        return next((c for c in self.customers
                     if any(s.owns(subscription_id) for s in c.subscriptions)), None)


def load_register(settings: Optional[Settings] = None) -> Register:
    s = settings or get_settings()
    path = (s.customers_file or "").strip()
    if path:
        return _from_file(Path(path), s)
    return _from_environment(s)


def _from_environment(s: Settings) -> Register:
    if not s.azure_subscription_id:
        return Register(customers=(), source="environment (AZURE_SUBSCRIPTION_ID unset)")
    customer = Customer(
        name=_SINGLE,
        queue=s.sdp_queue,
        subscriptions=(Subscription(s.azure_subscription_id.strip(),
                                    s.scope_resource_group_tuple),),
        min_severity=s.alert_min_severity,
    )
    return Register(customers=(customer,), source="environment (single customer)")


def _from_file(path: Path, s: Settings) -> Register:
    import yaml

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as e:
        raise RegisterError(f"customer register {path} does not exist") from e
    except yaml.YAMLError as e:
        raise RegisterError(f"customer register {path} is not valid YAML: {e}") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("customers"), list):
        raise RegisterError(f"customer register {path} needs a top-level 'customers' list")

    defaults = raw.get("defaults") or {}
    customers: list[Customer] = []
    names: set[str] = set()
    owners: dict[str, str] = {}
    for i, entry in enumerate(raw["customers"], start=1):
        if not isinstance(entry, dict):
            raise RegisterError(f"customer #{i} is not a mapping")
        if entry.get("enabled", True) is False:
            continue
        name = str(entry.get("name") or "").strip()
        where = f"customer '{name}'" if name else f"customer #{i}"
        if not name:
            raise RegisterError(f"{where} has no name")
        if name.lower() in names:
            raise RegisterError(f"{where} is listed twice")
        names.add(name.lower())

        queue = str(entry.get("queue") or "").strip()
        if not queue:
            raise RegisterError(f"{where} has no queue; its requests would reach no one")

        subs: list[Subscription] = []
        for sub in entry.get("subscriptions") or []:
            sub = sub if isinstance(sub, dict) else {"id": sub}
            sid = str(sub.get("id") or "").strip()
            if not sid:
                raise RegisterError(f"{where} lists a subscription with no id")
            if sid.lower() in owners:
                raise RegisterError(
                    f"subscription {sid} is listed under both '{owners[sid.lower()]}' and "
                    f"'{name}'; an alert from it could be filed into either queue")
            owners[sid.lower()] = name
            groups = sub.get("resource_groups") or []
            if isinstance(groups, str):
                groups = [g for g in groups.split(",")]
            subs.append(Subscription(sid, tuple(g.strip() for g in groups if g.strip())))
        if not subs:
            raise RegisterError(f"{where} has no subscriptions")

        floor = entry.get("min_severity", defaults.get("min_severity", s.alert_min_severity))
        try:
            floor = int(floor)
        except (TypeError, ValueError) as e:
            raise RegisterError(f"{where}: min_severity must be 0-4, not {floor!r}") from e
        if not 0 <= floor <= 4:
            raise RegisterError(f"{where}: min_severity must be 0-4, not {floor}")

        priorities = entry.get("priority_by_severity",
                               defaults.get("priority_by_severity")) or {}
        if not isinstance(priorities, dict):
            raise RegisterError(f"{where}: priority_by_severity must be a mapping")
        mapped: dict[str, str] = {}
        for sev, priority in priorities.items():
            rank = severity_rank(str(sev))
            if rank is None:
                raise RegisterError(f"{where}: '{sev}' is not an Azure severity (Sev0-Sev4)")
            mapped[f"Sev{rank}"] = str(priority).strip()

        customers.append(Customer(name=name, queue=queue, subscriptions=tuple(subs),
                                  min_severity=floor, priority_by_severity=mapped))
    return Register(customers=tuple(customers), source=str(path))
