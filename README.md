# ISSE Alert Agent

Azure Monitor alert intake for ISSE. Reads the alerts Azure is already holding and
files **one ServiceDesk request per new alert**, carrying the alert's payload so the
ISSE pipeline can confirm the machine and work the incident unchanged.

This implements Phase 2 §3.1 / §5 ("Azure Monitor agent — all our alerts"). It is a
separate repository on purpose: the agent decides *that* an incident exists; it decides
nothing about what to do with a machine, and it has no code path that can change one.

## The contract (why this can be a separate repo)

The agent and the ISSE pipeline share a **data contract, not code**:

| | |
|---|---|
| Agent → ServiceDesk (write) | Creates a request whose description carries the Azure Monitor **common alert schema** JSON, plus VM/RG in `udf_char1`/`udf_char2`. |
| ISSE ← ServiceDesk (read) | The existing pipeline parses that payload (`isse.identification.alerts.from_ticket`) and confirms the machine from `alertTargetIDs`. **No change to `isse-agent` is required.** |
| Dedup | By the alert's own `alertId`, in this agent's own SQLite store. ISSE independently dedups the resulting ticket via its audit DB. Two independent guards, no shared DB. |

The payload shape ISSE reads is pinned by `tests/test_cas_contract.py`, which
round-trips the agent's payload through a **frozen snapshot** of ISSE's parser. If
ISSE's parser ever changes, update that snapshot (and ISSE's CI fixture) in the same
change — the mismatch fails a build rather than a production ticket.

## What it does, per alert

```
in the scoped resource groups?   no → skip   (bounds alert volume)
at/above the severity floor?     no → skip
already filed (durable dedup)?   yes → skip
                                 otherwise → file a request carrying the payload
```

## Usage

```bash
pip install -e ".[dev]"

isse-alerts doctor   # read-only preflight: config, Azure read, ServiceDesk token
isse-alerts list     # read-only: firing VM alerts Azure holds, marked in/out of scope
isse-alerts once     # one poll cycle (files requests unless ISSE_ALERT_DRY_RUN=true)
isse-alerts watch    # poll forever at ISSE_POLL_INTERVAL_SECONDS
isse-alerts health   # exit 0 if `watch` completed a cycle recently (for a monitor)
```

Bringing up a new customer, in order: `doctor` until it exits 0, then `list`, then
`once` with `ISSE_ALERT_DRY_RUN=true` (discovers and logs, files nothing), then `once`
for real, then `watch`.

`watch` survives transient failures: a failed cycle is logged and retried with backoff
(up to 8x the poll interval), and one bad alert never blocks the others. A ServiceDesk
**authentication** failure is logged as needing a person (a refresh token does not fix
itself) but the loop keeps trying, so the agent recovers once the token is replaced.

Resource-group scope matching is case-insensitive (Azure Monitor lowercases resource
IDs), and the request carries the group **as spelled in `ISSE_SANDBOX_RESOURCE_GROUP`**,
because the pipeline's guardrail scope check is case-sensitive.

## Configuration

See [`deploy/env.example`](deploy/env.example). Alias names are shared with the ISSE
pipeline, so one per-customer `.env` can serve both. The agent needs only:

- **Azure** `Monitoring Reader` at **subscription** scope (read-only), and
- **ServiceDesk** permission to create a request.

That is a strict subset of ISSE's own IAM — nothing here can change a machine.

## Deployment

One isolated instance per customer (own subscription/tenant/SP, own queue, own dedup
DB), via the templated `deploy/isse-alerts@.service`:

```bash
sudo systemctl enable --now isse-alerts@acme   # reads /srv/isse/acme/.env
```

For monitoring, run `isse-alerts health` (same environment) from a timer or
monitoring agent; it fails if no cycle has reached Azure within 4x the poll interval,
which catches a process that is alive but stuck.

A `Dockerfile` is provided for local development; no GPU and no baked-in credentials.

## Tests

```bash
pytest -q
```

The suite runs fully offline against fakes (`tests/fakes.py`) — no Azure, no
ServiceDesk, no credentials — which is what lets CI run on every pull request.

`tests/test_isse_interop.py` goes further: it feeds a request this agent filed into the
**real** ISSE pipeline (parser, alert reconciliation, and a sim-mode orchestrator run)
and checks the machine is confirmed from the alert. It looks for ISSE at
`$ISSE_AGENT_SRC` or a sibling `../isse-agent/src`, and skips if neither exists.

## Not in scope

- No remediation. The agent only files requests.
- No multi-tenant process. One instance per customer, same as the pipeline.
- No classification or routing logic — that stays in `isse-agent`.
