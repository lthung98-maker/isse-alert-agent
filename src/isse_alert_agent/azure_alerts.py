"""Reading the alerts Azure is already holding.

A thin read over Microsoft.AlertsManagement at *subscription* scope - the same call
ISSE makes per-VM for evidence, taken estate-wide so the agent can go looking rather
than waiting for a payload on a ticket. This is the only Azure surface the agent
touches, and it is read-only, which is why the service principal needs just
``Monitoring Reader`` at subscription scope and nothing that can change a machine.

The Azure SDK import is deferred into the call so importing this module (for its
``AlertReader`` type, or in a test that injects a fake) never requires the SDK.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from .config import Settings, get_settings
from .models import Alert, AlertCondition


class AlertReader(Protocol):
    """What the agent needs from a source of alerts. A fake satisfies this in tests."""

    def list_fired_alerts(self, hours: int = 1, max_rank: int = 4) -> list[Alert]:
        ...


def _time_range(hours: int) -> str:
    """Azure's alert query takes one of four fixed ranges; pick the smallest that fits."""
    for limit, name in ((1, "1h"), (24, "1d"), (24 * 7, "7d")):
        if hours <= limit:
            return name
    return "30d"


def _plain(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(getattr(value, "value", value)).strip()
    return text or None


def _conditions(context: Any) -> list[AlertCondition]:
    """Conditions from the alert's ``context``, for signal types that carry a threshold."""
    if not isinstance(context, dict):
        return []
    inner = context.get("context") if isinstance(context.get("context"), dict) else context
    condition = inner.get("condition") if isinstance(inner, dict) else None
    blocks = (condition.get("allOf") if isinstance(condition, dict) else None) or []
    window = (condition.get("windowSize") if isinstance(condition, dict) else None)
    out: list[AlertCondition] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        out.append(AlertCondition(
            metric=block.get("metricName") or block.get("metricMeasureColumn"),
            operator=block.get("operator"),
            threshold=_number(block.get("threshold")),
            observed=_number(block.get("metricValue")),
            aggregation=block.get("timeAggregation") or block.get("metricAggregation"),
            window=block.get("windowSize") or window,
            dimensions=[d for d in (block.get("dimensions") or []) if isinstance(d, dict)],
        ))
    return out


def _number(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_alert(item: Any) -> Alert:
    """One alert from Microsoft.AlertsManagement, read defensively."""
    e = getattr(getattr(item, "properties", None), "essentials", None)
    target = _plain(getattr(e, "target_resource", None))
    alert = Alert(
        rule=_plain(getattr(e, "alert_rule", None)),
        alert_id=_plain(getattr(item, "name", None)) or _plain(getattr(item, "id", None)),
        severity=_plain(getattr(e, "severity", None)),
        signal_type=_plain(getattr(e, "signal_type", None)),
        monitor_condition=_plain(getattr(e, "monitor_condition", None)),
        monitoring_service=_plain(getattr(e, "monitor_service", None)),
        alert_state=_plain(getattr(e, "alert_state", None)),
        fired_at=str(getattr(e, "start_date_time", "") or "") or None,
        resolved_at=str(getattr(e, "monitor_condition_resolved_date_time", "") or "") or None,
        description=_plain(getattr(e, "description", None)),
        target_ids=[target] if target else [],
    )
    name = _plain(getattr(e, "target_resource_name", None))
    if name:
        alert.configuration_items = [name]
    alert.conditions = _conditions(getattr(getattr(item, "properties", None), "context", None))
    return alert


class AzureAlertReader:
    """Lists firing VM alerts across the subscription via Microsoft.AlertsManagement."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._s = settings or get_settings()

    def _client(self):
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.alertsmanagement import AlertsManagementClient

        cid, secret, tenant = (self._s.azure_client_id, self._s.azure_client_secret,
                               self._s.azure_tenant_id)
        if cid and secret and tenant:
            cred = ClientSecretCredential(tenant_id=tenant, client_id=cid, client_secret=secret)
        else:
            cred = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        return AlertsManagementClient(cred, self._s.azure_subscription_id)

    def list_fired_alerts(self, hours: int = 1, max_rank: int = 4) -> list[Alert]:
        """Every still-firing VM alert Azure holds, worst severity first.

        Filtered to targets that are virtual machines and to severities at or above the
        floor (``max_rank`` is the least-severe rank to include: 0 keeps only critical,
        4 keeps everything). Closed and resolved alerts are dropped - the agent only
        files work for something currently firing.
        """
        found = self._client().alerts.get_all(
            time_range=_time_range(hours),
            monitor_condition="Fired",
            alert_state="New",
            include_context=True,
        )
        out: list[Alert] = []
        for item in found:
            alert = _to_alert(item)
            if not alert.fired or alert.vm_name is None:
                continue
            rank = alert.severity_rank
            if rank is not None and rank > max_rank:
                continue
            out.append(alert)
        out.sort(key=lambda a: a.severity_rank if a.severity_rank is not None else 9)
        return out
