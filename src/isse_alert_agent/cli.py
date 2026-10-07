"""Command line: check the setup, look at what Azure holds, file requests, run the loop.

    isse-alerts doctor   read-only preflight: register, every subscription, ServiceDesk token
    isse-alerts list     read-only: the firing VM alerts Azure holds, per customer
    isse-alerts once     one poll cycle (files requests unless ISSE_ALERT_DRY_RUN)
    isse-alerts watch    poll forever at ISSE_POLL_INTERVAL_SECONDS
    isse-alerts health   exit non-zero if any customer has not been read recently
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time
from pathlib import Path

import typer

from .config import Settings, get_settings

app = typer.Typer(add_completion=False, help="ISSE alert agent: Azure Monitor intake.")
log = logging.getLogger("isse_alert_agent")

# Backoff ceiling after consecutive failed cycles: a transient outage is retried soon,
# a long one is not hammered every thirty seconds.
_MAX_BACKOFF_FACTOR = 8


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"ts": record.created, "level": record.levelname,
                           "logger": record.name, "msg": record.getMessage()})


def _configure_logging(s: Settings) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if (s.log_format or "text").strip().lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s",
                                               datefmt="%H:%M:%S"))
    root = logging.getLogger("isse_alert_agent")
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False
    # The Azure SDK logs every HTTP request at INFO; that is noise in an operator's journal.
    logging.getLogger("azure").setLevel(logging.WARNING)
    # A failed token is raised to the caller, which reports it per subscription; the
    # library's own multi-line warning would only repeat it.
    logging.getLogger("azure.identity").setLevel(logging.ERROR)


def _settings() -> Settings:
    s = get_settings(reload=True)
    _configure_logging(s)
    return s


def _agent(s: Settings):
    """The agent, or a clean exit if the register cannot be trusted to route alerts."""
    from .agent import AlertAgent
    from .customers import RegisterError

    try:
        return AlertAgent(s)
    except RegisterError as e:
        typer.echo(f"Customer register rejected: {e}")
        raise typer.Exit(code=2) from e


@app.command()
def doctor() -> None:
    """Read-only preflight. Files nothing; exits non-zero if the agent cannot run."""
    from .customers import RegisterError, load_register

    s = _settings()
    problems: list[str] = []

    def line(ok: bool, label: str, detail: str, warn: bool = False) -> None:
        mark = "ok" if ok else ("warn" if warn else "FAIL")
        typer.echo(f"  [{mark}] {label}: {detail}")
        if not ok and not warn:
            problems.append(label)

    typer.echo("Configuration")
    register = None
    try:
        register = load_register(s)
        line(bool(register.customers), "Customer register",
             f"{len(register.customers)} customer(s) from {register.source}"
             if register.customers else
             f"no customers ({register.source}); set ISSE_ALERT_CUSTOMERS_FILE")
    except RegisterError as e:
        line(False, "Customer register", str(e))
    for c in register.customers if register else ():
        prio = (", ".join(f"{k}->{v}" for k, v in sorted(c.priority_by_severity.items()))
                or "portal default")
        typer.echo(f"    {c.name}: queue '{c.queue}'; Sev0..Sev{c.min_severity}; "
                   f"priority {prio}")
        for sub in c.subscriptions:
            typer.echo(f"      [{'ok' if sub.resource_groups else 'warn'}] {sub.id}: "
                       + (", ".join(sub.resource_groups) if sub.resource_groups else
                          "no resource groups listed - the WHOLE subscription is in scope"))
    line(s.azure_service_principal, "Azure credential",
         "service principal (tenant " + str(s.azure_tenant_id) + ")"
         if s.azure_service_principal else
         "DefaultAzureCredential (managed identity / az login); use a service "
         "principal for unattended running", warn=True)
    typer.echo(f"  [ok] Lookback {s.alert_lookback_hours}h; "
               f"dry run {'ON' if s.dry_run else 'off'}")
    line(s.sdp_is_configured, "ServiceDesk",
         f"portal {s.sdp_portal}" if s.sdp_is_configured else
         "needs SDP_PORTAL, SDP_CLIENT_ID, SDP_CLIENT_SECRET, SDP_REFRESH_TOKEN")

    typer.echo("Reachability (read-only)")
    if register and register.customers:
        from .azure_alerts import AzureAlertReader

        reader = AzureAlertReader(s)
        for c in register.customers:
            for sub in c.subscriptions:
                label = f"Alerts {c.name} / {sub.id}"
                try:
                    found = reader.list_fired_alerts(sub.id, hours=s.alert_lookback_hours,
                                                     max_rank=c.min_severity)
                    line(True, label, f"{len(found)} firing VM alert(s) in the window")
                except Exception as e:  # noqa: BLE001
                    text = " ".join(str(e).split())
                    hint = (" - the identity needs Monitoring Reader on this subscription "
                            "(for a customer tenant, delegated through Azure Lighthouse)"
                            if "authoriz" in text.lower() or "403" in text
                            or "not found" in text.lower() else "")
                    line(False, label, f"{type(e).__name__}: {text[:200]}{hint}")
    if s.sdp_is_configured:
        try:
            from .servicedesk import ServiceDeskFiler

            ServiceDeskFiler(s).access_token()
            line(True, "ServiceDesk token", "refresh token accepted")
        except Exception as e:  # noqa: BLE001
            line(False, "ServiceDesk token", str(e)[:200])

    if problems:
        typer.echo(f"\n{len(problems)} problem(s): {', '.join(problems)}")
        raise typer.Exit(code=1)
    typer.echo("\nReady.")


@app.command("list")
def list_alerts() -> None:
    """Read-only: the firing VM alerts Azure holds, and whether each would be filed."""
    s = _settings()
    discovery = _agent(s).discover()
    for d in discovery.found:
        a = d.alert
        if d.misrouted:
            verdict = f"NOT FILED - machine is in subscription {a.subscription}"
        elif d.group:
            verdict = f"in scope ({d.group}) -> queue '{d.customer.queue}'"
        else:
            verdict = f"OUT of scope ({a.resource_group})"
        typer.echo(f"  {d.customer.name}  [{a.severity or '?'}] {a.machine_name}: {a.rule} "
                   f"fired {a.fired_at or '?'} - {verdict}")
    for error in discovery.errors:
        typer.echo(f"  could not read {error}")
    typer.echo(f"\n{len(discovery.found)} firing alert(s); "
               f"{len(discovery.errors)} subscription(s) unreadable.")
    if discovery.errors:
        raise typer.Exit(code=1)


@app.command()
def once() -> None:
    """One poll cycle, then exit. Exit code 1 if any request failed or any
    subscription could not be read."""
    s = _settings()
    report = _agent(s).cycle()
    _beat(s, report.reached)
    if report.failed or report.read_errors:
        raise typer.Exit(code=1)


@app.command()
def watch(interval: float = typer.Option(None, help="Seconds between polls")) -> None:
    """Poll Azure Monitor until stopped, filing a request per new alert."""
    from .servicedesk import ServiceDeskAuthError

    s = _settings()
    poll = interval if interval is not None else s.poll_interval_seconds
    agent = _agent(s)
    stop = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        stop["flag"] = True

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    log.info("ISSE alert agent started: %s; %d customer(s) from %s; interval=%.0fs",
             "DRY RUN (files nothing)" if s.dry_run else "filing requests",
             len(agent.register.customers), agent.register.source, poll)
    failures = 0
    while not stop["flag"]:
        start = time.time()
        try:
            report = agent.cycle()
            _beat(s, report.reached)
            # One unreadable customer is reported in the cycle and by `health`; only
            # an outage that reaches nobody slows the loop down.
            failures = failures + 1 if report.reached_nothing else 0
        except ServiceDeskAuthError as e:
            failures += 1
            log.error("ServiceDesk credentials unusable - a person must re-mint them: %s", e)
        except Exception as e:  # noqa: BLE001 - one bad cycle must not end the watcher
            failures += 1
            log.error("cycle failed (%d in a row): %s: %s", failures, type(e).__name__, e)
        wait = poll * min(2 ** failures, _MAX_BACKOFF_FACTOR) if failures else poll
        remaining = max(0.0, wait - (time.time() - start))
        while remaining > 0 and not stop["flag"]:
            nap = min(1.0, remaining)
            time.sleep(nap)
            remaining -= nap
    log.info("stopped")


@app.command()
def health(max_age: float = typer.Option(0, help="Seconds; default 4x the poll interval")) -> None:
    """Exit 0 if every registered customer was read recently, 1 otherwise."""
    from .customers import RegisterError, load_register

    s = get_settings(reload=True)
    limit = max_age or max(120.0, s.poll_interval_seconds * 4)
    try:
        names = [c.name for c in load_register(s).customers]
    except RegisterError as e:
        typer.echo(f"customer register rejected: {e}")
        raise typer.Exit(code=1) from e
    beats = _read_beats(Path(s.heartbeat_file))
    if beats is None:
        typer.echo(f"no heartbeat at {s.heartbeat_file}")
        raise typer.Exit(code=1)
    now = time.time()
    stale = []
    for name in names:
        last = beats.get(name)
        if last is None:
            stale.append(name)
            typer.echo(f"  {name}: never read: STALE")
            continue
        age = now - last
        ok = age <= limit
        if not ok:
            stale.append(name)
        typer.echo(f"  {name}: last read {age:.0f}s ago: {'healthy' if ok else 'STALE'}")
    typer.echo(f"limit {limit:.0f}s; {len(names) - len(stale)}/{len(names)} healthy")
    if stale or not names:
        raise typer.Exit(code=1)


def _read_beats(path: Path) -> dict[str, float] | None:
    """Last successful read per customer, from the heartbeat file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {}
    customers = data.get("customers") if isinstance(data, dict) else None
    if not isinstance(customers, dict):
        return {}
    return {str(k): float(v) for k, v in customers.items() if isinstance(v, (int, float))}


def _beat(s: Settings, reached: list[str]) -> None:
    """Record which customers this cycle read, keeping the last success of the rest."""
    path = Path(s.heartbeat_file)
    try:
        beats = _read_beats(path) or {}
        now = time.time()
        beats.update({name: now for name in reached})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ts": now, "customers": beats}), encoding="utf-8")
    except OSError as e:
        log.warning("heartbeat not written: %s", e)


if __name__ == "__main__":
    app()
