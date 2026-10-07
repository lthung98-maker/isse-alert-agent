"""The contract: serialise an alert into the Azure Monitor common alert schema.

This is the one thing the alert agent and the ISSE pipeline agree on. The agent reads
an alert from Azure's store, turns it into this envelope, and writes the envelope onto
the ServiceDesk request it files. ISSE's ``isse.identification.alerts.from_ticket``
reads it straight back and confirms the machine from ``alertTargetIDs`` - so the agent
changes how work *arrives* and nothing about how it is judged.

Every key here is a key ISSE reads. The field names are Azure Monitor's own, because
ISSE's parser matches them to Azure Monitor's own; renaming one would silently drop it.
The round trip is pinned by ``tests/test_cas_contract.py`` against a frozen snapshot of
ISSE's reader, so a drift on either side fails a build rather than a production ticket.
"""

from __future__ import annotations

from typing import Optional

from .models import Alert, AlertCondition

# The schema id an action group posts when "common alert schema" is enabled. ISSE
# lower-cases this before comparing, so the canonical mixed-case form is written here
# and either side may spell it however it likes.
SCHEMA_ID = "azureMonitorCommonAlertSchema"


def to_common_schema(alert: Alert) -> dict:
    """An alert as the common-alert-schema envelope ISSE parses from a request."""
    essentials = {
        "alertId": alert.alert_id,
        "alertRule": alert.rule,
        "severity": alert.severity,
        "signalType": alert.signal_type,
        "monitorCondition": alert.monitor_condition,
        "monitoringService": alert.monitoring_service,
        "alertState": alert.alert_state,
        "firedDateTime": alert.fired_at,
        "resolvedDateTime": alert.resolved_at,
        "description": alert.description,
        "alertTargetIDs": list(alert.target_ids or []),
        "configurationItems": list(alert.configuration_items or []),
    }
    essentials = {k: v for k, v in essentials.items() if v not in (None, "", [])}

    data: dict = {"essentials": essentials}
    context = _context(alert.conditions)
    if context:
        data["alertContext"] = context
    return {"schemaId": SCHEMA_ID, "data": data}


def _context(conditions) -> dict:
    """``alertContext`` carrying each condition's threshold, or ``{}`` if none has one.

    The shape mirrors what a metric rule's context carries, which is what ISSE's
    ``conditions_from_context`` reads: a ``condition.allOf`` list of blocks, each with
    the metric, the comparison, the threshold and the value observed when it fired.
    """
    blocks: list[dict] = []
    window: Optional[str] = None
    for c in conditions or []:
        if not isinstance(c, AlertCondition):
            continue
        block = {
            "metricName": c.metric,
            "operator": c.operator,
            "threshold": None if c.threshold is None else str(c.threshold),
            "metricValue": None if c.observed is None else str(c.observed),
            "timeAggregation": c.aggregation,
            "dimensions": list(c.dimensions or []),
        }
        block = {k: v for k, v in block.items() if v not in (None, "", [])}
        if c.window:
            block["windowSize"] = c.window
            window = window or c.window
        if block:
            blocks.append(block)
    if not blocks:
        return {}
    condition: dict = {"allOf": blocks}
    if window:
        condition["windowSize"] = window
    return {"condition": condition}
