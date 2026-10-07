"""The customer register: what keeps one customer's alerts out of another's queue."""

from __future__ import annotations

import textwrap

import pytest

from isse_alert_agent.config import Settings
from isse_alert_agent.customers import RegisterError, load_register

_A1 = "aaaaaaaa-0000-0000-0000-000000000001"
_A2 = "aaaaaaaa-0000-0000-0000-000000000002"
_B1 = "bbbbbbbb-0000-0000-0000-000000000001"


def _register(tmp_path, monkeypatch, body: str):
    path = tmp_path / "customers.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    monkeypatch.setenv("ISSE_ALERT_CUSTOMERS_FILE", str(path))
    return load_register(Settings())


def test_a_register_with_two_customers_and_three_subscriptions(tmp_path, monkeypatch):
    reg = _register(tmp_path, monkeypatch, f"""
        defaults:
          min_severity: 2
          priority_by_severity: {{Sev0: High, Sev1: Medium}}
        customers:
          - name: Customer A
            queue: ISSE-CustomerA
            subscriptions:
              - id: {_A1}
                resource_groups: [RG-A-PRD]
              - id: {_A2}
          - name: Customer B
            queue: ISSE-CustomerB
            min_severity: 1
            priority_by_severity: {{"0": Urgent}}
            subscriptions: ["{_B1}"]
    """)

    a, b = reg.customers
    assert [s.id for s in a.subscriptions] == [_A1, _A2]
    assert a.subscriptions[0].resource_groups == ("RG-A-PRD",)
    assert a.subscriptions[1].resource_groups == ()
    assert a.min_severity == 2 and b.min_severity == 1
    assert a.priority_for("Sev0") == "High" and a.priority_for("Sev3") is None
    # A customer's own SLA replaces the default, it does not merge with it.
    assert b.priority_for("Sev0") == "Urgent" and b.priority_for("Sev1") is None
    assert reg.owner_of(_B1.upper()) is b
    assert reg.owner_of("cccccccc-0000-0000-0000-000000000000") is None


def test_a_subscription_under_two_customers_is_refused(tmp_path, monkeypatch):
    with pytest.raises(RegisterError, match="both 'A' and 'B'"):
        _register(tmp_path, monkeypatch, f"""
            customers:
              - {{name: A, queue: QA, subscriptions: ["{_A1}"]}}
              - {{name: B, queue: QB, subscriptions: ["{_A1.upper()}"]}}
        """)


@pytest.mark.parametrize("entry, message", [
    (f'{{queue: Q, subscriptions: ["{_A1}"]}}', "no name"),
    (f'{{name: A, subscriptions: ["{_A1}"]}}', "no queue"),
    ("{name: A, queue: Q}", "no subscriptions"),
    (f'{{name: A, queue: Q, min_severity: 7, subscriptions: ["{_A1}"]}}', "0-4"),
    (f'{{name: A, queue: Q, priority_by_severity: {{P1: High}}, subscriptions: ["{_A1}"]}}',
     "not an Azure severity"),
])
def test_an_entry_that_cannot_route_is_refused(tmp_path, monkeypatch, entry, message):
    with pytest.raises(RegisterError, match=message):
        _register(tmp_path, monkeypatch, f"customers:\n  - {entry}\n")


def test_the_same_customer_twice_is_refused(tmp_path, monkeypatch):
    with pytest.raises(RegisterError, match="listed twice"):
        _register(tmp_path, monkeypatch, f"""
            customers:
              - {{name: A, queue: QA, subscriptions: ["{_A1}"]}}
              - {{name: a, queue: QB, subscriptions: ["{_B1}"]}}
        """)


def test_a_disabled_customer_is_left_out(tmp_path, monkeypatch):
    reg = _register(tmp_path, monkeypatch, f"""
        customers:
          - {{name: A, queue: QA, subscriptions: ["{_A1}"]}}
          - {{name: B, queue: QB, enabled: false, subscriptions: ["{_B1}"]}}
    """)
    assert [c.name for c in reg.customers] == ["A"]


def test_a_missing_register_file_is_an_error_not_an_empty_estate(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSE_ALERT_CUSTOMERS_FILE", str(tmp_path / "nope.yaml"))
    with pytest.raises(RegisterError, match="does not exist"):
        load_register(Settings())


def test_without_a_register_the_environment_is_one_customer(monkeypatch):
    monkeypatch.delenv("ISSE_ALERT_CUSTOMERS_FILE", raising=False)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", _A1)
    monkeypatch.setenv("ISSE_SANDBOX_RESOURCE_GROUP", "RG-ONE, RG-TWO")
    monkeypatch.setenv("SDP_QUEUE", "ISSE-Standby")

    (only,) = load_register(Settings()).customers
    assert only.queue == "ISSE-Standby"
    assert only.subscriptions[0].id == _A1
    assert only.subscriptions[0].resource_groups == ("RG-ONE", "RG-TWO")


def test_the_example_register_loads(monkeypatch):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "deploy" / "customers.example.yaml"
    monkeypatch.setenv("ISSE_ALERT_CUSTOMERS_FILE", str(example))
    assert len(load_register(Settings()).customers) >= 2
