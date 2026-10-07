"""The durable dedup store."""

from __future__ import annotations

from isse_alert_agent.dedup import DedupStore


def test_record_then_seen(tmp_path):
    store = DedupStore(str(tmp_path / "d.db"))
    assert store.seen("alert-1") is False
    store.record("alert-1", ticket_id="INC-1", rule="High CPU", vm_name="VM1")
    assert store.seen("alert-1") is True
    assert store.count() == 1


def test_record_is_idempotent(tmp_path):
    store = DedupStore(str(tmp_path / "d.db"))
    store.record("alert-1", ticket_id="INC-1")
    store.record("alert-1", ticket_id="INC-2")  # same id again
    assert store.count() == 1


def test_blank_alert_id_is_never_seen_or_recorded(tmp_path):
    store = DedupStore(str(tmp_path / "d.db"))
    assert store.seen("") is False
    assert store.seen(None) is False
    store.record("")
    store.record(None)
    assert store.count() == 0


def test_survives_reopen(tmp_path):
    path = str(tmp_path / "d.db")
    first = DedupStore(path)
    first.record("alert-1", ticket_id="INC-1")
    first.close()

    second = DedupStore(path)
    assert second.seen("alert-1") is True
