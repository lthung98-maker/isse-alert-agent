"""Mapping Microsoft.AlertsManagement objects into the agent's Alert.

The objects are built in the SDK's own attribute names (azure-mgmt-alertsmanagement
1.0.x: ``Alert.id/name/properties``, ``properties.essentials/context``), so a test here
breaking is the SDK shape changing under the reader.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace as NS

from isse_alert_agent.azure_alerts import AzureAlertReader, to_alert

_SUB = "00000000-0000-0000-0000-00000000test"
_VM_ID = (f"/subscriptions/{_SUB}/resourcegroups/rg-gg4-standalone-test/providers/"
          "microsoft.compute/virtualmachines/gg4daxprd03")


def _item(alert_guid="6d2f9a8b-1111-2222-3333-444455556666", rule="High CPU",
          vm_id=_VM_ID, vm_name="GG4DAXPRD03", severity="Sev2", condition="Fired",
          state="New", context=None):
    essentials = NS(
        alert_rule=(f"/subscriptions/{_SUB}/resourceGroups/rg-monitor/providers/"
                    f"microsoft.insights/metricalerts/{rule}"),
        severity=NS(value=severity), signal_type=NS(value="Metric"),
        monitor_condition=NS(value=condition), monitor_service=NS(value="Platform"),
        alert_state=NS(value=state),
        start_date_time=datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc),
        monitor_condition_resolved_date_time=None,
        description="CPU above 90%", target_resource=vm_id,
        target_resource_name=vm_name,
    )
    return NS(
        id=f"/subscriptions/{_SUB}/providers/Microsoft.AlertsManagement/alerts/{alert_guid}",
        # The store sets `name` to the RULE name. This is what made it unusable as a key.
        name=rule,
        properties=NS(essentials=essentials, context=context),
    )


def test_identifier_is_the_alert_resource_id_not_the_rule_name():
    a = to_alert(_item())
    assert a.alert_id.endswith("/alerts/6d2f9a8b-1111-2222-3333-444455556666")
    # Two firings of the same rule are two alerts, so they need two identifiers.
    b = to_alert(_item(alert_guid="other-guid"))
    assert a.alert_id != b.alert_id
    assert a.rule == b.rule == "High CPU"


def test_rule_name_is_taken_from_the_rule_resource_id():
    assert to_alert(_item(rule="VM heartbeat lost")).rule == "VM heartbeat lost"


def test_fired_time_is_iso_8601():
    assert to_alert(_item()).fired_at == "2026-09-20T10:00:00+00:00"


def test_machine_name_keeps_its_case_when_the_target_id_is_lowercased():
    a = to_alert(_item())
    assert a.vm_name == "gg4daxprd03"
    assert a.machine_name == "GG4DAXPRD03"
    assert a.resource_group == "rg-gg4-standalone-test"


def test_metric_condition_is_read_from_context():
    context = {"condition": {"windowSize": "PT5M", "allOf": [{
        "metricName": "Percentage CPU", "operator": "GreaterThan", "threshold": "90",
        "metricValue": 97.5, "timeAggregation": "Average"}]}}
    c = to_alert(_item(context=context)).conditions[0]
    assert (c.metric, c.operator, c.threshold, c.observed, c.window) == (
        "Percentage CPU", "GreaterThan", 90.0, 97.5, "PT5M")


class _FakeAlertsClient:
    def __init__(self, items):
        self.items = items
        self.kwargs = None
        self.alerts = self

    def get_all(self, **kwargs):
        self.kwargs = kwargs
        return iter(self.items)


def test_reader_queries_fired_new_alerts_and_keeps_only_vms_at_or_above_the_floor(monkeypatch):
    storage_id = (f"/subscriptions/{_SUB}/resourcegroups/rg/providers/"
                  "microsoft.storage/storageaccounts/s1")
    client = _FakeAlertsClient([
        _item(alert_guid="a", severity="Sev3"),                    # below the floor
        _item(alert_guid="b", severity="Sev1"),                    # kept
        _item(alert_guid="c", severity="Sev2", vm_id=storage_id),  # not a VM
        _item(alert_guid="d", severity="Sev0"),                    # kept, worst first
    ])
    reader = AzureAlertReader(settings=NS(azure_subscription_id=_SUB))
    monkeypatch.setattr(reader, "_client", lambda: client)

    alerts = reader.list_fired_alerts(hours=1, max_rank=2)

    assert [a.alert_id.rsplit("/", 1)[-1] for a in alerts] == ["d", "b"]
    assert client.kwargs["monitor_condition"] == "Fired"
    assert client.kwargs["alert_state"] == "New"
    assert client.kwargs["time_range"] == "1h"
    assert client.kwargs["include_context"] is True
