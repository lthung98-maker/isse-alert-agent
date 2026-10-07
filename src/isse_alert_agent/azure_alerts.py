"""Reading the alerts Azure is already holding.

A thin read over Microsoft.AlertsManagement at *subscription* scope - the same call
ISSE makes per-VM for evidence, taken estate-wide so the agent can go looking rather
than waiting for a payload on a ticket. This is the only Azure surface the agent
touches, and it is read-only, which is why the identity needs just ``Monitoring
Reader`` on each subscription and nothing that can change a machine.

One credential serves every subscription. Under Azure Lighthouse the customers'
subscriptions are delegated to an identity in our own tenant, so the same token reads
all of them; only the client, which is bound to a subscription, differs.

The Azure SDK import is deferred into the client so importing this module (for its
``AlertReader`` type, or in a test that injects a fake) never requires the SDK.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from .config import Settings, get_settings
from .models import Alert, AlertCondition


class AlertReader(Protocol):
    """What the agent needs from a source of alerts. A fake satisfies this in tests."""

    def list_fired_alerts(self, subscription: str, hours: int = 1,
                          max_rank: int = 4) -> list[Alert]:
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


def _when(value: Any) -> Optional[str]:
    """ISO-8601 for a datetime, the text itself for anything else."""
    if value is None or value == "":
        return None
    iso = getattr(value, "isoformat", None)
    return iso() if callable(iso) else (str(value).strip() or None)


def _rule_name(alert_rule: Optional[str]) -> Optional[str]:
    """The rule's name from the ARM id the store returns for it.

    Essentials carry the rule as ``/subscriptions/.../metricalerts/High CPU``; the
    common alert schema, and every person reading the ticket, call it "High CPU".
    """
    if not alert_rule:
        return None
    return alert_rule.rstrip("/").rsplit("/", 1)[-1] or alert_rule


def _number(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _conditions(context: Any) -> list[AlertCondition]:
    """Conditions from the alert's ``context``, for signal types that carry a threshold."""
    if not isinstance(context, dict):
        return []
    inner = context.get("context") if isinstance(context.get("context"), dict) else context
    condition = inner.get("condition") if isinstance(inner, dict) else None
    blocks = (condition.get("allOf") if isinstance(condition, dict) else None) or []
    window = condition.get("windowSize") if isinstance(condition, dict) else None
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


def to_alert(item: Any) -> Alert:
    """One alert from Microsoft.AlertsManagement, read defensively.

    The identifier is the alert's own resource id, never its ``name``. The store sets
    ``name`` to the *rule* name, so deduplicating on it would file the first alert a
    rule ever raised and silently drop every later one, on every machine.
    """
    props = getattr(item, "properties", None)
    e = getattr(props, "essentials", None)
    target = _plain(getattr(e, "target_resource", None))
    rule = _rule_name(_plain(getattr(e, "alert_rule", None)))
    alert = Alert(
        rule=rule or _plain(getattr(item, "name", None)),
        alert_id=_plain(getattr(item, "id", None)),
        severity=_plain(getattr(e, "severity", None)),
        signal_type=_plain(getattr(e, "signal_type", None)),
        monitor_condition=_plain(getattr(e, "monitor_condition", None)),
        monitoring_service=_plain(getattr(e, "monitor_service", None)),
        alert_state=_plain(getattr(e, "alert_state", None)),
        fired_at=_when(getattr(e, "start_date_time", None)),
        resolved_at=_when(getattr(e, "monitor_condition_resolved_date_time", None)),
        description=_plain(getattr(e, "description", None)),
        target_ids=[target] if target else [],
    )
    # The resource's own name, in the case it was created with. The target id is often
    # lower-cased by the monitor, and the name is what a person and ISSE both look for.
    name = _plain(getattr(e, "target_resource_name", None))
    if name:
        alert.configuration_items = [name]
    alert.conditions = _conditions(getattr(props, "context", None))
    return alert


class AzureAlertReader:
    """Lists firing VM alerts in a subscription via Microsoft.AlertsManagement."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._s = settings or get_settings()
        self._cred = None
        self._clients: dict[str, Any] = {}

    def _credential(self):
        # Built once and shared: the credential holds the token cache, and a new one per
        # poll would mint a fresh token every thirty seconds for every subscription.
        if self._cred is None:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential

            if self._s.azure_service_principal:
                self._cred = ClientSecretCredential(tenant_id=self._s.azure_tenant_id,
                                                    client_id=self._s.azure_client_id,
                                                    client_secret=self._s.azure_client_secret)
            else:
                # Never the interactive browser: under systemd it would wait for a click
                # that never comes, and the agent would look alive while doing nothing.
                self._cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return self._cred

    def _client(self, subscription: str):
        key = subscription.lower()
        if key not in self._clients:
            from azure.mgmt.alertsmanagement import AlertsManagementClient

            self._clients[key] = AlertsManagementClient(self._credential(), subscription)
        return self._clients[key]

    def list_fired_alerts(self, subscription: str, hours: int = 1,
                          max_rank: int = 4) -> list[Alert]:
        """Every still-firing, unacknowledged VM alert in ``subscription``, worst first.

        ``max_rank`` is the least-severe rank to include: 0 keeps only critical, 4 keeps
        everything. ``alert_state="New"`` leaves out alerts a person has already
        acknowledged or closed in the portal - somebody is on those.
        """
        if not subscription:
            raise RuntimeError("no subscription to read alerts from")
        found = self._client(subscription).alerts.get_all(
            time_range=_time_range(hours),
            monitor_condition="Fired",
            alert_state="New",
            include_context=True,
        )
        out: list[Alert] = []
        for item in found:
            alert = to_alert(item)
            if not alert.fired or alert.vm_name is None or not alert.alert_id:
                continue
            rank = alert.severity_rank
            if rank is not None and rank > max_rank:
                continue
            out.append(alert)
        out.sort(key=lambda a: a.severity_rank if a.severity_rank is not None else 9)
        return out
