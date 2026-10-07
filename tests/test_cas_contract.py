"""M1: the contract between this repo and ISSE, pinned.

The alert agent's only promise to the ISSE pipeline is that the payload it writes onto
a request is one ISSE reads back. To hold that promise without coupling the two
repositories, this test round-trips the agent's payload through a FROZEN SNAPSHOT of
ISSE's own parser - copied, byte-for-byte, from ``isse.identification.alerts`` at the
version this agent targets.

If ISSE's parser changes, update the snapshot here *and* in isse-agent's CI fixture in
the same change, and this test is where the mismatch surfaces - in a build, not on a
production ticket. Do not "improve" the snapshot; its only job is to be what ISSE is.
"""

from __future__ import annotations

from typing import Optional

from isse_alert_agent import cas
from fakes import sample_alert, sample_alert_with_condition

# ---- FROZEN SNAPSHOT of isse.identification.alerts (do not edit to "fix" a test) ----

_SCHEMA_ID_LC = "azuremonitorcommonalertschema"


def _t(value) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _num(value) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _frozen_conditions(context) -> list[dict]:
    if not isinstance(context, dict):
        return []
    condition = context.get("condition")
    blocks = (condition.get("allOf") if isinstance(condition, dict) else None) or []
    window = (condition.get("windowSize") if isinstance(condition, dict) else None) \
        or context.get("windowSize")
    out: list[dict] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        out.append({
            "metric": _t(block.get("metricName") or block.get("metricMeasureColumn")
                         or ("rows returned by the rule's log query"
                             if block.get("searchQuery") else None)),
            "operator": _t(block.get("operator")),
            "threshold": _num(block.get("threshold")),
            "observed": _num(block.get("metricValue")),
            "aggregation": _t(block.get("timeAggregation") or block.get("metricAggregation")),
            "window": _t(block.get("windowSize") or window),
            "dimensions": [d for d in (block.get("dimensions") or []) if isinstance(d, dict)],
        })
    return out


def _frozen_isse_parse(obj: dict) -> Optional[dict]:
    schema = str(obj.get("schemaId") or "").strip().lower()
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj
    essentials = data.get("essentials") if isinstance(data, dict) else None
    if not isinstance(essentials, dict):
        return None
    if schema and schema != _SCHEMA_ID_LC:
        return None
    alert = {
        "rule": _t(essentials.get("alertRule")),
        "alert_id": _t(essentials.get("alertId")),
        "severity": _t(essentials.get("severity")),
        "signal_type": _t(essentials.get("signalType")),
        "monitor_condition": _t(essentials.get("monitorCondition")),
        "monitoring_service": _t(essentials.get("monitoringService")),
        "alert_state": _t(essentials.get("alertState")),
        "fired_at": _t(essentials.get("firedDateTime")),
        "resolved_at": _t(essentials.get("resolvedDateTime")),
        "description": _t(essentials.get("description")),
        "target_ids": [str(t) for t in (essentials.get("alertTargetIDs") or []) if t],
        "configuration_items": [str(c) for c in (essentials.get("configurationItems") or [])
                                if c],
    }
    if not any((alert["rule"], alert["alert_id"], alert["fired_at"], alert["target_ids"])):
        return None
    alert["conditions"] = _frozen_conditions(
        data.get("alertContext") if isinstance(data, dict) else None)
    return alert


# ---- the contract tests ----

def test_schema_id_is_what_isse_matches():
    payload = cas.to_common_schema(sample_alert())
    assert payload["schemaId"].lower() == _SCHEMA_ID_LC


def test_essentials_round_trip_through_frozen_isse_parser():
    alert = sample_alert()
    parsed = _frozen_isse_parse(cas.to_common_schema(alert))
    assert parsed is not None
    assert parsed["rule"] == alert.rule
    assert parsed["alert_id"] == alert.alert_id
    assert parsed["severity"] == alert.severity
    assert parsed["monitor_condition"] == alert.monitor_condition
    assert parsed["fired_at"] == alert.fired_at
    # The machine ISSE will confirm from the payload rather than infer from prose.
    assert parsed["target_ids"] == alert.target_ids
    assert "/virtualMachines/GG4DAXPRD03" in parsed["target_ids"][0]


def test_metric_threshold_survives_the_round_trip():
    alert = sample_alert_with_condition()
    parsed = _frozen_isse_parse(cas.to_common_schema(alert))
    assert parsed is not None
    assert len(parsed["conditions"]) == 1
    c = parsed["conditions"][0]
    assert c["metric"] == "Percentage CPU"
    assert c["operator"] == "GreaterThan"
    assert c["threshold"] == 90.0
    assert c["observed"] == 97.5
    assert c["aggregation"] == "Average"
    assert c["window"] == "PT5M"


def test_alert_with_no_conditions_has_no_context():
    payload = cas.to_common_schema(sample_alert())
    assert "alertContext" not in payload["data"]


def test_empty_fields_are_dropped_not_sent_as_null():
    payload = cas.to_common_schema(sample_alert())
    essentials = payload["data"]["essentials"]
    assert "resolvedDateTime" not in essentials  # the alert is firing, not resolved
    assert all(v not in (None, "", []) for v in essentials.values())
