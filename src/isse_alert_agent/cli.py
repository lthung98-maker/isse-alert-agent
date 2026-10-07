"""Command line: check the setup, look at what Azure holds, file requests, run the loop.

    isse-alerts doctor   read-only preflight: config, Azure alert read, ServiceDesk token
    isse-alerts list     read-only: print the firing VM alerts Azure holds in scope
    isse-alerts once     one poll cycle (files requests unless ISSE_ALERT_DRY_RUN)
    isse-alerts watch    poll forever at ISSE_POLL_INTERVAL_SECONDS
    isse-alerts health   exit non-zero if the watcher has not completed a cycle recently
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


def _agent(s: Settings):
    from .agent import AlertAgent

    return AlertAgent(s)


def _settings() -> Settings:
    s = get_settings(reload=True)
    _configure_logging(s)
    return s


@app.command()
def doctor() -> None:
    """Read-only preflight. Files nothing; exits non-zero if the agent cannot run."""
    s = _settings()
    problems: list[str] = []

    def line(ok: bool, label: str, detail: str) -> None:
        typer.echo(f"  [{'ok' if ok else 'FAIL'}] {label}: {detail}")
        if not ok:
            problems.append(label)

    typer.echo("Configuration")
    line(s.azure_is_configured, "Azure subscription",
         s.azure_subscription_id or "AZURE_SUBSCRIPTION_ID unset")
    sp = bool(s.azure_client_id and s.azure_client_secret and s.azure_tenant_id)
    typer.echo(f"  [{'ok' if sp else 'warn'}] Azure credential: "
               + ("service principal" if sp else
                  "DefaultAzureCredential (managed identity / az login); use a service "
                  "principal for unattended running"))
    groups = s.scope_resource_group_tuple
    typer.echo(f"  [{'ok' if groups else 'warn'}] Scope: "
               + (", ".join(groups) if groups else
                  "ISSE_SANDBOX_RESOURCE_GROUP unset - the WHOLE subscription is in scope"))
    typer.echo(f"  [ok] Severity floor: Sev0..Sev{s.alert_min_severity}; "
               f"lookback {s.alert_lookback_hours}h; dry run {'ON' if s.dry_run else 'off'}")
    line(s.sdp_is_configured, "ServiceDesk",
         f"portal {s.sdp_portal}" if s.sdp_is_configured else
         "needs SDP_PORTAL, SDP_CLIENT_ID, SDP_CLIENT_SECRET, SDP_REFRESH_TOKEN")

    typer.echo("Reachability (read-only)")
    if s.azure_is_configured:
        try:
            alerts = _agent(s).discover()
            line(True, "Azure alert read", f"{len(alerts)} firing VM alert(s) in the window")
        except Exception as e:  # noqa: BLE001
            hint = (" - the identity needs Monitoring Reader at SUBSCRIPTION scope"
                    if "authoriz" in str(e).lower() or "403" in str(e) else "")
            line(False, "Azure alert read", f"{type(e).__name__}: {str(e)[:200]}{hint}")
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
    try:
        discovered = _agent(s).discover()
    except Exception as e:  # noqa: BLE001
        typer.echo(f"Could not read alerts: {type(e).__name__}: {e}\n"
                   f"Run `isse-alerts doctor` for a full check.")
        raise typer.Exit(code=1) from e
    if not discovered:
        typer.echo("No firing VM alerts in the window.")
        return
    for a in discovered:
        group = s.scoped_group(a.resource_group)
        scope = f"in scope ({group})" if group else f"OUT of scope ({a.resource_group})"
        typer.echo(f"  [{a.severity or '?'}] {a.machine_name}: {a.rule} "
                   f"fired {a.fired_at or '?'} - {scope}")
    typer.echo(f"\n{len(discovered)} firing alert(s).")


@app.command()
def once() -> None:
    """One poll cycle, then exit. Exit code 1 if any request failed to file."""
    s = _settings()
    report = _agent(s).cycle()
    if report.failed:
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

    log.info("ISSE alert agent started: %s; scope=%s; Sev0..Sev%d; interval=%.0fs",
             "DRY RUN (files nothing)" if s.dry_run else "filing requests",
             ", ".join(s.scope_resource_group_tuple) or "whole subscription",
             s.alert_min_severity, poll)
    failures = 0
    while not stop["flag"]:
        start = time.time()
        try:
            agent.cycle()
            failures = 0
            _beat(s)
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
    """Exit 0 if the watcher completed a cycle recently, 1 otherwise."""
    s = get_settings(reload=True)
    limit = max_age or max(120.0, s.poll_interval_seconds * 4)
    path = Path(s.heartbeat_file)
    if not path.exists():
        typer.echo(f"no heartbeat at {path}")
        raise typer.Exit(code=1)
    age = time.time() - path.stat().st_mtime
    ok = age <= limit
    typer.echo(f"last cycle {age:.0f}s ago (limit {limit:.0f}s): {'healthy' if ok else 'STALE'}")
    if not ok:
        raise typer.Exit(code=1)


def _beat(s: Settings) -> None:
    try:
        path = Path(s.heartbeat_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(time.time()), encoding="utf-8")
    except OSError as e:
        log.warning("heartbeat not written: %s", e)


if __name__ == "__main__":
    app()
