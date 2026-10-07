"""The agent's judgement: scope, dedup, and what it writes onto the request."""

from __future__ import annotations

import json

from isse_alert_agent.agent import AlertAgent
from isse_alert_agent.config import Settings
from fakes import FakeFiler, FakeReader, sample_alert


def _settings(tmp_path, monkeypatch, scope="RG-GG4-STANDALONE-TEST", dry=False):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-00000000test")
    monkeypatch.setenv("ISSE_SANDBOX_RESOURCE_GROUP", scope)
    monkeypatch.setenv("ISSE_ALERT_DEDUP_DB", str(tmp_path / "seen.db"))
    monkeypatch.setenv("ISSE_ALERT_DRY_RUN", "true" if dry else "false")
    return Settings()


def test_poll_files_one_request_per_new_alert(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch)
    reader = FakeReader([sample_alert(alert_id="a1"),
                         sample_alert(vm="GG4RDGPRD01", alert_id="a2")])
    filer = FakeFiler()
    agent = AlertAgent(s, reader=reader, filer=filer)

    raised = agent.poll()

    assert sum(r.created for r in raised) == 2
    assert len(filer.created) == 2
    # The payload the pipeline will read is on the request.
    assert "azureMonitorCommonAlertSchema" in filer.created[0]["description"]
    # The machine is carried in the UDFs as well as the payload.
    assert filer.created[0]["udf"]["udf_char1"] == "GG4DAXPRD03"


def test_dedup_is_durable_across_a_second_poll(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch)
    reader = FakeReader([sample_alert(alert_id="a1")])
    filer = FakeFiler()
    agent = AlertAgent(s, reader=reader, filer=filer)

    agent.poll()
    second = agent.poll()

    assert sum(r.created for r in second) == 0
    assert len(filer.created) == 1  # not filed twice


def test_out_of_scope_alert_is_not_filed(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch, scope="RG-SOME-OTHER-GROUP")
    reader = FakeReader([sample_alert(alert_id="a1")])  # in RG-GG4-STANDALONE-TEST
    filer = FakeFiler()
    agent = AlertAgent(s, reader=reader, filer=filer)

    raised = agent.poll()

    assert raised == []
    assert filer.created == []


def test_a_failed_create_is_retried_not_deduped(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch)
    reader = FakeReader([sample_alert(alert_id="a1")])
    filer = FakeFiler(ok=False)
    agent = AlertAgent(s, reader=reader, filer=filer)

    first = agent.poll()
    second = agent.poll()

    assert all(not r.created for r in first)
    assert len(filer.created) == 2  # attempted again, because the first did not land


def test_dry_run_discovers_but_files_nothing(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch, dry=True)
    reader = FakeReader([sample_alert(alert_id="a1")])
    filer = FakeFiler()
    agent = AlertAgent(s, reader=reader, filer=filer)

    raised = agent.poll()

    assert len(raised) == 1
    assert raised[0].created is False
    assert filer.created == []


def test_description_payload_is_valid_json(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch)
    reader = FakeReader([sample_alert(alert_id="a1")])
    filer = FakeFiler()
    AlertAgent(s, reader=reader, filer=filer).poll()

    description = filer.created[0]["description"]
    payload_line = description.splitlines()[-1]
    payload = json.loads(payload_line)
    assert payload["schemaId"].lower() == "azuremonitorcommonalertschema"
    assert payload["data"]["essentials"]["alertRule"] == "VM heartbeat lost"
