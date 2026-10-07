"""Interop against ISSE's real code, not a snapshot of it.

Skipped unless the ISSE pipeline is importable: set ``ISSE_AGENT_SRC`` to its ``src``
directory, or keep ``isse-agent`` checked out next to this repository. This repo's CI
does neither, which keeps the two decoupled; ``test_cas_contract.py`` is the pin that
always runs. This file is the stronger check for anyone holding both:

* a request as the live portal returns it is read by ISSE's own ServiceDesk parser and
  alert reader as the right machine, with the alert confirming it - not contradicting it;
* a request the agent files is worked end to end by ISSE's real orchestrator (sim mode,
  recommend-only), with the alert time and target taken from the agent's payload.
"""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path

import pytest

_SRC = os.environ.get("ISSE_AGENT_SRC") or str(
    Path(__file__).resolve().parents[2] / "isse-agent" / "src")
if Path(_SRC).is_dir() and _SRC not in sys.path:
    sys.path.append(_SRC)
pytest.importorskip("isse.identification.alerts")

from fakes import FakeReader, sample_alert, sample_alert_with_condition  # noqa: E402

from isse_alert_agent.agent import AlertAgent  # noqa: E402
from isse_alert_agent.config import Settings  # noqa: E402
from isse_alert_agent.models import Alert, AlertCondition  # noqa: E402
from isse_alert_agent.servicedesk import CreatedRequest  # noqa: E402

_SUB = "00000000-0000-0000-0000-00000000test"
_RG = "RG-GG4-STANDALONE-TEST"


def _portal_row(alert: Alert, *, udfs: bool = True, escape_quotes: bool = False) -> dict:
    """The request object ServiceDesk returns for what the agent filed."""
    description = AlertAgent.description(alert, _RG)
    if escape_quotes:  # some portals store the body with every quote entity-escaped
        description = html.escape(html.unescape(description), quote=True).replace(
            "&lt;br&gt;", "<br>")
    row = {"id": "1001", "subject": AlertAgent.subject(alert), "description": description,
           "status": {"name": "Open"}, "created_time": {"value": "1789900000000"}}
    if udfs:
        row["udf_fields"] = {"udf_char1": alert.machine_name, "udf_char2": _RG}
    return row


@pytest.mark.parametrize("udfs,escape_quotes", [(True, False), (False, False), (True, True)],
                         ids=["with-udfs", "portal-without-udfs", "quote-escaped-body"])
def test_isse_reads_the_filed_request_as_the_right_machine(udfs, escape_quotes):
    from isse.connectors.manageengine import ManageEngineConnector
    from isse.identification import alerts as isse_alerts

    alert = sample_alert_with_condition()
    ticket = ManageEngineConnector._to_ticket(_portal_row(alert, udfs=udfs,
                                                          escape_quotes=escape_quotes))
    assert (ticket.vm_name, ticket.resource_group) == ("GG4DAXPRD03", _RG)

    read = isse_alerts.from_ticket(ticket)
    assert read is not None, "ISSE found no alert payload on the request"
    assert read.alert_id == alert.alert_id
    assert read.fired_at == alert.fired_at
    assert read.vm_name == "GG4DAXPRD03"
    assert read.conditions and read.conditions[0].threshold == 90.0

    agreement = isse_alerts.reconcile(read, ticket, _SUB)
    assert agreement is not None and not agreement.conflict, agreement and agreement.detail
    assert agreement.confirmed


def test_lowercased_monitor_ids_still_confirm_rather_than_conflict():
    from isse.connectors.manageengine import ManageEngineConnector
    from isse.identification import alerts as isse_alerts

    alert = sample_alert(rg="rg-gg4-standalone-test", vm="gg4daxprd03")
    alert.configuration_items = ["GG4DAXPRD03"]
    ticket = ManageEngineConnector._to_ticket(_portal_row(alert))
    agreement = isse_alerts.reconcile(isse_alerts.from_ticket(ticket), ticket, _SUB)
    assert not agreement.conflict, agreement.detail


class _IsseQueueFiler:
    """Files into ISSE's own (mock) ServiceDesk, exactly as the live filer would."""

    def __init__(self, itsm):
        self._itsm = itsm

    def create_request(self, subject, description, udf_fields=None):
        t = self._itsm.create_ticket(subject, description, udf_fields=udf_fields)
        return CreatedRequest(id=t.id, ok=True, detail="mock portal")


def _as_agent_alert(a) -> Alert:
    fields = {f: getattr(a, f) for f in Alert.__dataclass_fields__ if hasattr(a, f)}
    fields["conditions"] = [AlertCondition(**{k: getattr(c, k) for k in
                                              AlertCondition.__dataclass_fields__})
                            for c in (a.conditions or [])]
    return Alert(**fields)


def test_isse_works_a_request_the_agent_filed_end_to_end(tmp_path, monkeypatch):
    for key in ("OPENAI_BASE_URL", "OPENSHELL_SANDBOX", "ISSE_KILL_SWITCH",
                "ISSE_ARMED_CLASSES"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ISSE_MODE", "sim")
    monkeypatch.setenv("ISSE_ALLOW_REMEDIATION", "false")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", _SUB)
    monkeypatch.setenv("ISSE_SANDBOX_RESOURCE_GROUP", _RG)
    monkeypatch.setenv("ISSE_AUDIT_DB", str(tmp_path / "isse-audit.db"))
    monkeypatch.setenv("ISSE_ALERT_DEDUP_DB", str(tmp_path / "seen.db"))
    monkeypatch.setenv("ISSE_LOG_JSON", "false")

    import isse.audit.log as isse_audit
    import isse.config as isse_config
    isse_config.get_settings(reload=True)
    monkeypatch.setattr(isse_audit, "_audit", None, raising=False)
    from isse.workflow import Orchestrator

    orch = Orchestrator(isse_config.get_settings())
    # The alert ISSE's own mock estate holds for a machine somebody deallocated.
    firing = orch.cloud.get_active_alerts(_RG, "GG4DAXPRD03").firing
    assert firing, "mock estate holds no firing alert for GG4DAXPRD03"

    agent = AlertAgent(Settings(), reader=FakeReader([_as_agent_alert(firing[0])]),
                       filer=_IsseQueueFiler(orch.itsm))
    report = agent.cycle()
    assert len(report.filed) == 1
    ticket = orch.itsm.get_ticket(report.filed[0].ticket_id)

    result = orch.handle(ticket)

    events = {e["action"]: e for e in orch.audit.events_for(result.correlation_id)}
    assert '"alert": null' not in events["intake"]["detail"], "ISSE did not read the alert"
    assert events["alert_target"]["decision"] == "confirmed"
    assert result.incident_class == "A_stopped_or_deallocated_vm"
    assert "conflict" not in (result.guardrail_reason or "")
    # Recommend-only: nothing on the machine was changed.
    assert result.action_taken is None
    # A second cycle files nothing: the alert is already a request.
    assert agent.cycle().filed == []
