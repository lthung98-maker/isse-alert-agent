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

isse-alerts list     # read-only: print firing VM alerts Azure holds in scope
isse-alerts once     # one poll cycle (files requests unless ISSE_ALERT_DRY_RUN=true)
isse-alerts watch    # poll forever at ISSE_POLL_INTERVAL_SECONDS
```

Set `ISSE_ALERT_DRY_RUN=true` for a first run against a new subscription: it discovers
and logs but files nothing.

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

A `Dockerfile` is provided for local development; no GPU and no baked-in credentials.

## Tests

```bash
pytest -q
```

The suite runs fully offline against fakes (`tests/fakes.py`) — no Azure, no
ServiceDesk, no credentials — which is what lets CI run on every pull request.

## Not in scope

- No remediation. The agent only files requests.
- No multi-tenant process. One instance per customer, same as the pipeline.
- No classification or routing logic — that stays in `isse-agent`.
