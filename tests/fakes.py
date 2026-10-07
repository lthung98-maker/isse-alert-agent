"""Offline doubles for the two external systems, and a sample alert factory.

Lets the whole suite run with no Azure and no ServiceDesk - and no credentials - which
is what keeps CI able to run on every pull request.
"""

from __future__ import annotations

from isse_alert_agent.models import Alert, AlertCondition
from isse_alert_agent.servicedesk import CreatedRequest

_SUB = "00000000-0000-0000-0000-00000000test"
_RG = "RG-GG4-STANDALONE-TEST"


def sample_alert(vm: str = "GG4DAXPRD03", rule: str = "VM heartbeat lost",
                 severity: str = "Sev1", alert_id: str = "mock-alert-1",
                 rg: str = _RG, signal: str = "Log",
                 conditions=None, sub: str = _SUB) -> Alert:
    return Alert(
        rule=rule, alert_id=alert_id, severity=severity, signal_type=signal,
        monitor_condition="Fired", monitoring_service="Log Analytics",
        alert_state="New", fired_at="2026-09-20T10:00:00Z",
        description="Heartbeat not received",
        target_ids=[f"/subscriptions/{sub}/resourceGroups/{rg}/providers/"
                    f"Microsoft.Compute/virtualMachines/{vm}"],
        configuration_items=[vm],
        conditions=conditions or [],
    )


def sample_alert_with_condition() -> Alert:
    return sample_alert(
        rule="High CPU", severity="Sev2", alert_id="mock-alert-cpu", signal="Metric",
        conditions=[AlertCondition(metric="Percentage CPU", operator="GreaterThan",
                                   threshold=90.0, observed=97.5, aggregation="Average",
                                   window="PT5M")],
    )


class FakeReader:
    """An :class:`isse_alert_agent.azure_alerts.AlertReader`.

    ``alerts`` is either one list, returned for every subscription, or a mapping of
    subscription id to the alerts Azure holds there. A subscription in ``failing``
    raises, as an unreadable or undelegated one does.
    """

    def __init__(self, alerts, failing: tuple[str, ...] = ()) -> None:
        self._alerts = alerts
        self._failing = {f.lower() for f in failing}
        self.calls: list[tuple[str, int]] = []

    def list_fired_alerts(self, subscription: str, hours: int = 1,
                          max_rank: int = 4) -> list[Alert]:
        self.calls.append((subscription, max_rank))
        if subscription.lower() in self._failing:
            raise PermissionError(f"AuthorizationFailed on {subscription}")
        held = (self._alerts.get(subscription, []) if isinstance(self._alerts, dict)
                else self._alerts)
        kept = [a for a in held
                if a.fired and (a.severity_rank is None or a.severity_rank <= max_rank)]
        kept.sort(key=lambda a: a.severity_rank if a.severity_rank is not None else 9)
        return kept


class FakeFiler:
    """An :class:`isse_alert_agent.servicedesk.RequestFiler` that records what it got."""

    def __init__(self, ok: bool = True) -> None:
        self._ok = ok
        self.created: list[dict] = []

    def create_request(self, subject: str, description: str,
                       udf_fields=None, queue=None, priority=None) -> CreatedRequest:
        self.created.append({"subject": subject, "description": description,
                             "udf": udf_fields, "queue": queue, "priority": priority})
        return CreatedRequest(
            id=f"INC-{len(self.created)}" if self._ok else None,
            ok=self._ok,
            detail="HTTP 201" if self._ok else "HTTP 500",
        )
