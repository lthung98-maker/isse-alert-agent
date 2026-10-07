"""The alert agent: discover firing alerts, file one request each, record what it filed.

The whole of the agent's judgement is here, and it is deliberately small: decide *that*
an incident exists, decide *whose* it is, and give it a well-formed request in that
customer's queue. It decides nothing about what to do with the machine - that stays in
the ISSE pipeline, which picks the request up and works it unchanged. The agent has no
path that can change a machine.

Per customer, per registered subscription, per alert - each one a reason to skip
rather than file:
    the alert's machine is not in the subscription read  ->  skip (never cross-file)
    out of the subscription's scoped resource groups     ->  skip (bounds alert volume)
    below the customer's severity floor                  ->  dropped by the reader
    already filed                                        ->  skip (durable dedup)
    otherwise  ->  file a request carrying the alert payload, in the customer's queue

A subscription that cannot be read is reported and skipped; it never stops the others.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from html import escape
from typing import Iterator, Optional

from . import cas
from .azure_alerts import AlertReader, AzureAlertReader
from .config import Settings, get_settings
from .customers import Customer, Register, Subscription, load_register
from .dedup import DedupStore
from .models import Alert, severity_meaning
from .servicedesk import RequestFiler, ServiceDeskAuthError, ServiceDeskFiler

log = logging.getLogger("isse_alert_agent")


@dataclass
class RaisedIncident:
    alert_id: Optional[str]
    rule: Optional[str]
    vm_name: Optional[str]
    severity: Optional[str]
    ticket_id: Optional[str]
    created: bool
    detail: str
    customer: str = ""
    queue: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Discovered:
    """One firing alert, with the customer and subscription it was read from."""

    customer: Customer
    subscription: Subscription
    alert: Alert

    @property
    def group(self) -> Optional[str]:
        """The register's spelling of the alert's resource group, or None if out of scope."""
        return self.subscription.scoped_group(self.alert.resource_group)

    @property
    def misrouted(self) -> bool:
        """The alert's machine is not in the subscription it was read from."""
        sub = self.alert.subscription
        return bool(sub) and not self.subscription.owns(sub)


@dataclass
class Discovery:
    found: list[Discovered] = field(default_factory=list)
    # "customer / subscription: error", one per subscription that could not be read.
    errors: list[str] = field(default_factory=list)
    # Customers every one of whose subscriptions was read this pass.
    reached: list[str] = field(default_factory=list)


@dataclass
class CycleReport:
    """What one poll found and did, for the log line, the CLI and the heartbeat."""

    discovered: int = 0
    out_of_scope: int = 0
    misrouted: int = 0
    already_filed: int = 0
    raised: list[RaisedIncident] = field(default_factory=list)
    read_errors: list[str] = field(default_factory=list)
    reached: list[str] = field(default_factory=list)
    customers: int = 0

    @property
    def filed(self) -> list[RaisedIncident]:
        return [r for r in self.raised if r.created]

    @property
    def failed(self) -> list[RaisedIncident]:
        return [r for r in self.raised if r.detail.startswith("create failed")]

    @property
    def reached_nothing(self) -> bool:
        """No customer could be read at all - an outage, not one bad subscription."""
        return self.customers > 0 and not self.reached


class AlertAgent:
    def __init__(self, settings: Optional[Settings] = None,
                 reader: Optional[AlertReader] = None,
                 filer: Optional[RequestFiler] = None,
                 dedup: Optional[DedupStore] = None,
                 register: Optional[Register] = None) -> None:
        self._s = settings or get_settings()
        self.register = register or load_register(self._s)
        self._reader = reader or AzureAlertReader(self._s)
        # Built lazily: a read-only `list` must not need ServiceDesk credentials.
        self._filer = filer
        self._dedup = dedup or DedupStore(self._s.dedup_db_path)

    @property
    def filer(self) -> RequestFiler:
        if self._filer is None:
            self._filer = ServiceDeskFiler(self._s)
        return self._filer

    # ---- read-only ----
    def _sweep(self) -> Iterator[tuple[Customer, Subscription, Optional[list[Alert]], str]]:
        for customer in self.register.customers:
            for sub in customer.subscriptions:
                try:
                    alerts = self._reader.list_fired_alerts(
                        sub.id, hours=self._s.alert_lookback_hours,
                        max_rank=customer.min_severity)
                except Exception as e:  # noqa: BLE001 - one subscription must not stop the rest
                    yield customer, sub, None, f"{type(e).__name__}: {e}"
                    continue
                yield customer, sub, alerts, ""

    def discover(self) -> Discovery:
        """Firing VM alerts across every registered subscription, worst first per
        subscription. No side effects."""
        out = Discovery()
        failed: set[str] = set()
        for customer, sub, alerts, error in self._sweep():
            if alerts is None:
                failed.add(customer.name)
                out.errors.append(f"{customer.name} / {sub.id}: {error}")
                log.error("cannot read alerts for %s, subscription %s: %s",
                          customer.name, sub.id, error)
                continue
            out.found += [Discovered(customer, sub, a) for a in alerts]
        out.reached = [c.name for c in self.register.customers if c.name not in failed]
        return out

    # ---- the one cycle ----
    def poll(self, create: Optional[bool] = None) -> list[RaisedIncident]:
        return self.cycle(create).raised

    def cycle(self, create: Optional[bool] = None) -> CycleReport:
        """One discovery pass: file a request for each new in-scope firing alert.

        ``create`` defaults to the inverse of ``dry_run`` - a dry run discovers and
        reports but files nothing, the safe first run against a new subscription.

        A failure filing one alert does not stop the others; it is reported and, not
        being recorded as filed, retried next cycle. A credential failure does stop the
        cycle, because every customer files through the same portal and it will fail
        identically for every alert after it.
        """
        if create is None:
            create = not self._s.dry_run
        discovery = self.discover()
        report = CycleReport(read_errors=discovery.errors, reached=discovery.reached,
                             customers=len(self.register.customers))
        for item in discovery.found:
            alert = item.alert
            report.discovered += 1
            if item.misrouted:
                report.misrouted += 1
                log.warning("not filed: alert %s names a machine in subscription %s, read "
                            "from %s's subscription %s", alert.alert_id, alert.subscription,
                            item.customer.name, item.subscription.id)
                continue
            group = item.group
            if group is None:
                report.out_of_scope += 1
                continue
            if self._dedup.seen(alert.alert_id):
                report.already_filed += 1
                continue
            raised = self._raise(item, group, create)
            report.raised.append(raised)
            log.info("%s: %s on %s for %s -> %s %s (%s)",
                     "filed" if raised.created else "not filed", alert.rule, raised.vm_name,
                     item.customer.name, item.customer.queue, raised.ticket_id or "-",
                     raised.detail)
        log.info("cycle: %d customer(s), %d reached; %d firing in window, %d out of scope, "
                 "%d misrouted, %d already filed, %d filed, %d failed, %d read error(s)",
                 report.customers, len(report.reached), report.discovered,
                 report.out_of_scope, report.misrouted, report.already_filed,
                 len(report.filed), len(report.failed), len(report.read_errors))
        return report

    def _raise(self, item: Discovered, group: str, create: bool) -> RaisedIncident:
        alert, customer = item.alert, item.customer
        vm = alert.machine_name

        def result(created: bool, detail: str, ticket: Optional[str] = None):
            return RaisedIncident(alert_id=alert.alert_id, rule=alert.rule, vm_name=vm,
                                  severity=alert.severity, ticket_id=ticket,
                                  created=created, detail=detail, customer=customer.name,
                                  queue=customer.queue)

        if not create:
            return result(False, "discovered; not filed (dry run)")

        udf = {"udf_char1": vm, "udf_char2": group} if vm else {}
        try:
            created = self.filer.create_request(
                self.subject(alert), self.description(alert, group, customer.name),
                udf_fields=udf or None, queue=customer.queue,
                priority=customer.priority_for(alert.severity))
        except ServiceDeskAuthError:
            raise
        except Exception as e:  # noqa: BLE001 - one alert must not stop the rest
            return result(False, f"create failed: {type(e).__name__}: {e}")
        if not created.ok:
            # Not recorded as filed: a request that did not land is retried next cycle.
            return result(False, f"create failed: {created.detail}")

        self._dedup.record(alert.alert_id, ticket_id=created.id, rule=alert.rule,
                           vm_name=vm, customer=customer.name)
        return result(True, f"request filed ({created.detail})", created.id)

    # ---- the request the pipeline will read ----
    @staticmethod
    def subject(alert: Alert) -> str:
        where = alert.machine_name or (alert.configuration_items[0]
                                       if alert.configuration_items else "an Azure resource")
        sev = severity_meaning(alert.severity)
        rule = alert.rule or "Azure Monitor alert"
        return f"[Azure Monitor] {where}: {rule}" + (f" - {sev}" if sev else "")

    @staticmethod
    def description(alert: Alert, group: Optional[str] = None,
                    customer: Optional[str] = None) -> str:
        """The request body: a human lead-in, then the payload the pipeline parses.

        ServiceDesk renders descriptions as HTML, so lines are escaped and joined with
        ``<br>`` - and a real newline too, because ISSE's ticket parser anchors labelled
        fields to line starts. The ``Target:`` line comes first on purpose: ISSE reads
        ``<resource group> / <machine>`` before anything else, and the payload further
        down contains a resource id that must not be the first such match.
        """
        vm = alert.machine_name
        group = group or alert.resource_group
        lines = ["Raised automatically by the ISSE alert agent from an Azure Monitor alert."]
        if vm and group:
            lines.append(f"Target: {group} / {vm}")
        if customer:
            lines.append(f"Customer: {customer}")
        if alert.subscription:
            lines.append(f"Subscription: {alert.subscription}")
        if vm:
            lines.append(f"VM: {vm}")
        if group:
            lines.append(f"Resource group: {group}")
        lines += ["", f"Alert: {alert.summary()}"]
        if alert.description:
            lines.append(f"Rule description: {alert.description}")
        for condition in alert.conditions:
            lines.append(f"Condition: {condition.describe()}")
        lines += ["", "Azure Monitor common alert schema payload:"]
        body = "<br>\n".join(escape(line, quote=False) for line in lines)
        return f"{body}<br>\n{_html_safe_json(cas.to_common_schema(alert))}"


def _html_safe_json(payload: dict) -> str:
    """JSON that is also inert HTML, so it reads back identically whether or not the
    portal unescapes it: ``< > &`` become JSON unicode escapes, which mean the same
    characters to any JSON parser and nothing at all to an HTML one."""
    return (json.dumps(payload)
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e"))
