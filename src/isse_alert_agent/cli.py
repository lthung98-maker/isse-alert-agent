"""Command line: look at what Azure holds, file requests, or run the loop.

    isse-alerts list     read-only: print the firing VM alerts Azure holds
    isse-alerts once     one poll cycle (files requests unless ISSE_ALERT_DRY_RUN)
    isse-alerts watch    poll forever at ISSE_POLL_INTERVAL_SECONDS
"""

from __future__ import annotations

import time

import typer

from .config import get_settings

app = typer.Typer(add_completion=False, help="ISSE alert agent: Azure Monitor intake.")


def _agent():
    from .agent import AlertAgent

    return AlertAgent(get_settings(reload=True))


@app.command()
def list() -> None:  # noqa: A001 - the verb is the command name
    """Read-only: the firing VM alerts Azure holds for the scoped resource groups."""
    agent = _agent()
    discovered = agent.discover()
    if not discovered:
        typer.echo("No firing VM alerts in scope.")
        raise typer.Exit()
    for a in discovered:
        where = a.vm_name or "?"
        typer.echo(f"  [{a.severity or '?'}] {a.rule or 'alert'} on {where} "
                   f"fired {a.fired_at or '?'}  (alert_id={a.alert_id})")
    typer.echo(f"\n{len(discovered)} firing alert(s) in scope.")


@app.command()
def once() -> None:
    """One poll cycle: file a request per new in-scope alert, then exit."""
    _run_cycle(_agent())


@app.command()
def watch(interval: float = typer.Option(None, help="Seconds between polls")) -> None:
    """Poll Azure Monitor forever, filing a request per new alert."""
    s = get_settings(reload=True)
    poll = interval if interval is not None else s.poll_interval_seconds
    agent = _agent()
    mode = "DRY RUN (files nothing)" if s.dry_run else "filing requests"
    scope = ", ".join(s.scope_resource_group_tuple) or "whole subscription"
    typer.echo(f"ISSE alert agent - {mode}; scope={scope}; "
               f"min severity rank={s.alert_min_severity}; interval={poll:.0f}s")
    try:
        while True:
            start = time.time()
            _run_cycle(agent)
            remaining = max(0.0, poll - (time.time() - start))
            time.sleep(remaining)
    except KeyboardInterrupt:
        typer.echo("stopped")


def _run_cycle(agent) -> None:
    raised = agent.poll()
    filed = [r for r in raised if r.created]
    if not raised:
        typer.echo(f"{_ts()}  nothing new")
        return
    for r in raised:
        flag = "filed" if r.created else "skipped"
        typer.echo(f"{_ts()}  {flag}: {r.rule} on {r.vm_name} -> "
                   f"{r.ticket_id or '-'} ({r.detail})")
    typer.echo(f"{_ts()}  {len(filed)} request(s) filed this cycle")


def _ts() -> str:
    return time.strftime("%H:%M:%S", time.localtime())


if __name__ == "__main__":
    app()
