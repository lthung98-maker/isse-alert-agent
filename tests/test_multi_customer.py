"""Many customers, many subscriptions, one agent: routing and isolation."""

from __future__ import annotations

import json

from fakes import FakeFiler, FakeReader, sample_alert
from typer.testing import CliRunner

from isse_alert_agent.agent import AlertAgent
from isse_alert_agent.config import Settings
from isse_alert_agent.customers import Customer, Register, Subscription

_A1 = "aaaaaaaa-0000-0000-0000-000000000001"
_A2 = "aaaaaaaa-0000-0000-0000-000000000002"
_B1 = "bbbbbbbb-0000-0000-0000-000000000001"

_REGISTER = Register(source="test", customers=(
    Customer(name="Customer A", queue="ISSE-CustomerA", min_severity=2,
             priority_by_severity={"Sev0": "High", "Sev1": "Medium"},
             subscriptions=(Subscription(_A1, ("RG-A-PRD",)), Subscription(_A2))),
    Customer(name="Customer B", queue="ISSE-CustomerB", min_severity=0,
             subscriptions=(Subscription(_B1, ("RG-B-PRD",)),)),
))


def _settings(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSE_ALERT_DEDUP_DB", str(tmp_path / "seen.db"))
    monkeypatch.setenv("ISSE_ALERT_DRY_RUN", "false")
    return Settings()


def _agent(tmp_path, monkeypatch, alerts, failing=(), filer=None):
    reader = FakeReader(alerts, failing=failing)
    filer = filer or FakeFiler()
    agent = AlertAgent(_settings(tmp_path, monkeypatch), reader=reader, filer=filer,
                       register=_REGISTER)
    return agent, reader, filer


def test_each_alert_is_filed_into_its_own_customers_queue(tmp_path, monkeypatch):
    agent, reader, filer = _agent(tmp_path, monkeypatch, {
        _A1: [sample_alert(vm="AAAWEB01", rg="RG-A-PRD", sub=_A1, alert_id="a1",
                           severity="Sev0")],
        _A2: [sample_alert(vm="AAADB01", rg="RG-A-ANY", sub=_A2, alert_id="a2",
                           severity="Sev2")],
        _B1: [sample_alert(vm="BBBAPP01", rg="RG-B-PRD", sub=_B1, alert_id="b1",
                           severity="Sev0")],
    })

    report = agent.cycle()

    assert [r[0] for r in reader.calls] == [_A1, _A2, _B1]
    routed = {f["udf"]["udf_char1"]: (f["queue"], f["priority"]) for f in filer.created}
    assert routed == {
        "AAAWEB01": ("ISSE-CustomerA", "High"),
        "AAADB01": ("ISSE-CustomerA", None),     # Sev2 has no SLA mapping
        "BBBAPP01": ("ISSE-CustomerB", None),    # B maps no priorities
    }
    assert {r.customer for r in report.filed} == {"Customer A", "Customer B"}
    assert "Customer: Customer B" in filer.created[2]["description"]
    assert f"Subscription: {_B1}" in filer.created[2]["description"]


def test_each_customer_has_its_own_severity_floor(tmp_path, monkeypatch):
    agent, reader, _ = _agent(tmp_path, monkeypatch, [])
    agent.cycle()
    assert dict(reader.calls) == {_A1: 2, _A2: 2, _B1: 0}


def test_a_machine_from_another_subscription_is_never_cross_filed(tmp_path, monkeypatch):
    # Whatever Azure returns for B's subscription, an alert naming a machine in A's
    # subscription is not B's to file - and not A's either, since A's own read did
    # not return it.
    stray = sample_alert(vm="AAAWEB01", rg="RG-B-PRD", sub=_A1, alert_id="stray",
                         severity="Sev0")
    agent, _, filer = _agent(tmp_path, monkeypatch, {_B1: [stray]})

    report = agent.cycle()

    assert filer.created == []
    assert report.misrouted == 1


def test_an_unreadable_subscription_does_not_stop_the_other_customers(tmp_path, monkeypatch):
    agent, _, filer = _agent(tmp_path, monkeypatch, {
        _B1: [sample_alert(vm="BBBAPP01", rg="RG-B-PRD", sub=_B1, alert_id="b1",
                           severity="Sev0")],
    }, failing=(_A2,))

    report = agent.cycle()

    assert len(filer.created) == 1 and filer.created[0]["queue"] == "ISSE-CustomerB"
    assert report.reached == ["Customer B"]          # A is not reached: one of its subs failed
    assert len(report.read_errors) == 1 and _A2 in report.read_errors[0]
    assert not report.reached_nothing


def test_nothing_reachable_is_an_outage(tmp_path, monkeypatch):
    agent, _, _ = _agent(tmp_path, monkeypatch, [], failing=(_A1, _A2, _B1))
    assert agent.cycle().reached_nothing


def test_scope_is_per_subscription(tmp_path, monkeypatch):
    agent, _, filer = _agent(tmp_path, monkeypatch, {
        _A1: [sample_alert(vm="AAAWEB01", rg="RG-A-OTHER", sub=_A1, alert_id="a1")],
        _A2: [sample_alert(vm="AAADB01", rg="RG-A-OTHER", sub=_A2, alert_id="a2")],
    })

    report = agent.cycle()

    # A1 is scoped to RG-A-PRD; A2 lists no groups and so takes the whole subscription.
    assert [f["udf"]["udf_char1"] for f in filer.created] == ["AAADB01"]
    assert report.out_of_scope == 1


def _cli_env(tmp_path, monkeypatch, register_yaml: str):
    path = tmp_path / "customers.yaml"
    path.write_text(register_yaml, encoding="utf-8")
    monkeypatch.setenv("ISSE_ALERT_CUSTOMERS_FILE", str(path))
    monkeypatch.setenv("ISSE_ALERT_HEARTBEAT_FILE", str(tmp_path / "beat"))
    monkeypatch.setenv("ISSE_POLL_INTERVAL_SECONDS", "30")


def test_health_is_per_customer(tmp_path, monkeypatch):
    from isse_alert_agent import cli

    _cli_env(tmp_path, monkeypatch, f"""
customers:
  - {{name: A, queue: QA, subscriptions: ["{_A1}"]}}
  - {{name: B, queue: QB, subscriptions: ["{_B1}"]}}
""")
    s = Settings()
    cli._beat(s, ["A", "B"])
    runner = CliRunner()
    assert runner.invoke(cli.app, ["health"]).exit_code == 0

    # B has not been read since long before the limit; A is fresh.
    beats = json.loads((tmp_path / "beat").read_text())
    beats["customers"]["B"] -= 3600
    (tmp_path / "beat").write_text(json.dumps(beats))
    result = runner.invoke(cli.app, ["health"])
    assert result.exit_code == 1
    assert "B: last read" in result.output and "STALE" in result.output

    # A later cycle that reaches only A keeps B's last success, so B stays stale.
    cli._beat(s, ["A"])
    assert runner.invoke(cli.app, ["health"]).exit_code == 1


def test_a_bad_register_stops_the_cli_before_anything_is_read(tmp_path, monkeypatch):
    from isse_alert_agent import cli

    _cli_env(tmp_path, monkeypatch, f"""
customers:
  - {{name: A, queue: QA, subscriptions: ["{_A1}"]}}
  - {{name: B, queue: QB, subscriptions: ["{_A1}"]}}
""")
    result = CliRunner().invoke(cli.app, ["list"])
    assert result.exit_code == 2
    assert "register rejected" in result.output
