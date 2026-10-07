"""The alert agent: discover firing alerts, file one request each, record what it filed.

The whole of the agent's judgement is here, and it is deliberately small: decide *that*
an incident exists and give it a well-formed request. It decides nothing about what to
do with the machine - that stays in the ISSE pipeline, which picks the request up and
works it unchanged. The agent has no path that can change a machine.

Order of checks per alert, each one a reason to skip rather than file:
    out of the scoped resource groups  ->  skip (bounds alert volume)
    below the severity floor           ->  skip (dropped by the reader already)
    already filed                      ->  skip (durable dedup)
    otherwise                          ->  file a request carrying the alert payload
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from html import escape
from typing import Optional

from . import cas
from .azure_alerts import AlertReader, AzureAlertReader
from .config import Settings, get_settings
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

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class CycleReport:
    """What one poll found and did, for the log line and the CLI."""

    discovered: int = 0
    out_of_scope: int = 0
    already_filed: int = 0
    raised: list[RaisedIncident] = field(default_factory=list)

    @property
    def filed(self) -> list[RaisedIncident]:
        return [r for r in self.raised if r.created]

    @property
    def failed(self) -> list[RaisedIncident]:
        return [r for r in self.raised if r.detail.startswith("create failed")]


class AlertAgent:
    def __init__(self, settings: Optional[Settings] = None,
                 reader: Optional[AlertReader] = None,
                 filer: Optional[RequestFiler] = None,
                 dedup: Optional[DedupStore] = None) -> None:
        self._s = settings or get_settings()
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
    def discover(self) -> list[Alert]:
        """Firing VM alerts Azure holds, worst first. No side effects."""
        return self._reader.list_fired_alerts(
            hours=self._s.alert_lookback_hours,
            max_rank=self._s.alert_min_severity,
        )

    # ---- the one cycle ----
    def poll(self, create: Optional[bool] = None) -> list[RaisedIncident]:
        return self.cycle(create).raised

    def cycle(self, create: Optional[bool] = None) -> CycleReport:
        """One discovery pass: file a request for each new in-scope firing alert.

        ``create`` defaults to the inverse of ``dry_run`` - a dry run discovers and
        reports but files nothing, the safe first run against a new subscription.

        A failure filing one alert does not stop the others; it is reported and, not
        being recorded as filed, retried next cycle. A credential failure does stop the
        cycle, because it will fail identically for every alert after it.
        """
        if create is None:
            create = not self._s.dry_run
        report = CycleReport()
        for alert in self.discover():
            report.discovered += 1
            group = self._s.scoped_group(alert.resource_group)
            if group is None:
                report.out_of_scope += 1
                continue
            if self._dedup.seen(alert.alert_id):
                report.already_filed += 1
                continue
            raised = self._raise(alert, group, create)
            report.raised.append(raised)
            log.info("%s: %s on %s -> %s (%s)",
                     "filed" if raised.created else "not filed", alert.rule,
                     raised.vm_name, raised.ticket_id or "-", raised.detail)
        log.info("cycle: %d firing in window, %d out of scope, %d already filed, "
                 "%d filed, %d failed", report.discovered, report.out_of_scope,
                 report.already_filed, len(report.filed), len(report.failed))
        return report

    def _raise(self, alert: Alert, group: str, create: bool) -> RaisedIncident:
        vm = alert.machine_name

        def result(created: bool, detail: str, ticket: Optional[str] = None):
            return RaisedIncident(alert_id=alert.alert_id, rule=alert.rule, vm_name=vm,
                                  severity=alert.severity, ticket_id=ticket,
                                  created=created, detail=detail)

        if not create:
            return result(False, "discovered; not filed (dry run)")

        udf = {"udf_char1": vm, "udf_char2": group} if vm else {}
        try:
            created = self.filer.create_request(self.subject(alert),
                                                self.description(alert, group),
                                                udf_fields=udf or None)
        except ServiceDeskAuthError:
            raise
        except Exception as e:  # noqa: BLE001 - one alert must not stop the rest
            return result(False, f"create failed: {type(e).__name__}: {e}")
        if not created.ok:
            # Not recorded as filed: a request that did not land is retried next cycle.
            return result(False, f"create failed: {created.detail}")

        self._dedup.record(alert.alert_id, ticket_id=created.id, rule=alert.rule, vm_name=vm)
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
    def description(alert: Alert, group: Optional[str] = None) -> str:
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
