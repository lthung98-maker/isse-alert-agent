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
from dataclasses import asdict, dataclass
from typing import Optional

from . import cas
from .azure_alerts import AlertReader, AzureAlertReader
from .config import Settings, get_settings
from .dedup import DedupStore
from .models import Alert, severity_meaning
from .servicedesk import RequestFiler, ServiceDeskFiler


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


class AlertAgent:
    def __init__(self, settings: Optional[Settings] = None,
                 reader: Optional[AlertReader] = None,
                 filer: Optional[RequestFiler] = None,
                 dedup: Optional[DedupStore] = None) -> None:
        self._s = settings or get_settings()
        self._reader = reader or AzureAlertReader(self._s)
        self._filer = filer or ServiceDeskFiler(self._s)
        self._dedup = dedup or DedupStore(self._s.dedup_db_path)

    # ---- read-only ----
    def discover(self) -> list[Alert]:
        """Firing VM alerts Azure holds, worst first. No side effects."""
        return self._reader.list_fired_alerts(
            hours=self._s.alert_lookback_hours,
            max_rank=self._s.alert_min_severity,
        )

    def _in_scope(self, alert: Alert) -> bool:
        groups = self._s.scope_resource_group_tuple
        if not groups:
            return True
        rg = (alert.resource_group or "").lower()
        return any(rg == g.lower() for g in groups)

    # ---- the one cycle ----
    def poll(self, create: Optional[bool] = None) -> list[RaisedIncident]:
        """One discovery pass: file a request for each new in-scope firing alert.

        ``create`` defaults to the inverse of ``dry_run`` - a dry run discovers and
        reports but files nothing, the safe first run against a new subscription.
        """
        if create is None:
            create = not self._s.dry_run
        raised: list[RaisedIncident] = []
        for alert in self.discover():
            if not self._in_scope(alert):
                continue
            if self._dedup.seen(alert.alert_id):
                continue
            raised.append(self._raise(alert, create))
        return raised

    def _raise(self, alert: Alert, create: bool) -> RaisedIncident:
        subject = self._subject(alert)
        if not create:
            return RaisedIncident(
                alert_id=alert.alert_id, rule=alert.rule, vm_name=alert.vm_name,
                severity=alert.severity, ticket_id=None, created=False,
                detail="discovered; not filed (dry run)")

        udf: dict = {}
        if alert.vm_name:
            udf["udf_char1"] = alert.vm_name
        if alert.resource_group:
            udf["udf_char2"] = alert.resource_group
        result = self._filer.create_request(subject, self._description(alert),
                                             udf_fields=udf or None)
        if not result.ok:
            # Not recorded as seen: a request that was not filed must be retried next
            # cycle, not swallowed.
            return RaisedIncident(
                alert_id=alert.alert_id, rule=alert.rule, vm_name=alert.vm_name,
                severity=alert.severity, ticket_id=result.id, created=False,
                detail=f"create failed: {result.detail}")

        self._dedup.record(alert.alert_id, ticket_id=result.id,
                           rule=alert.rule, vm_name=alert.vm_name)
        return RaisedIncident(
            alert_id=alert.alert_id, rule=alert.rule, vm_name=alert.vm_name,
            severity=alert.severity, ticket_id=result.id, created=True,
            detail=f"request filed ({result.detail})")

    # ---- the request the pipeline will read ----
    @staticmethod
    def _subject(alert: Alert) -> str:
        where = alert.vm_name or (alert.configuration_items[0]
                                  if alert.configuration_items else "an Azure resource")
        sev = severity_meaning(alert.severity)
        rule = alert.rule or "Azure Monitor alert"
        return f"[Azure Monitor] {rule} on {where}" + (f" ({sev})" if sev else "")

    @staticmethod
    def _description(alert: Alert) -> str:
        """A human lead-in, then the common alert schema payload the pipeline parses."""
        lines = [
            "Raised automatically by the ISSE alert agent from an Azure Monitor alert.",
            "",
            alert.summary(),
        ]
        if alert.vm_name:
            lines.append("Affected machine: " + alert.vm_name
                         + (f" in {alert.resource_group}" if alert.resource_group else ""))
        for target in alert.target_ids:
            lines.append(f"Resource id: {target}")
        for condition in alert.conditions:
            lines.append(f"Condition: {condition.describe()}")
        lines += [
            "",
            "Azure Monitor common alert schema payload:",
            json.dumps(cas.to_common_schema(alert)),
        ]
        return "\n".join(lines)
