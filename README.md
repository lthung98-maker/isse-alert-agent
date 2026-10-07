# ISSE Alert Agent

Azure Monitor alert intake for ISSE, across **many customers and many subscriptions**.
Reads the alerts Azure is already holding in every registered subscription and files
**one ServiceDesk request per new alert, into that customer's queue**, carrying the
alert's payload so the ISSE pipeline can confirm the machine and work the incident.

This implements Phase 2 §3.1 / §5 ("Azure Monitor agent — all our alerts"). It is a
separate repository on purpose: the agent decides *that* an incident exists and *whose*
it is; it decides nothing about what to do with a machine, and it has no code path that
can change one.

## How it fits

```
customer subscriptions ──(Lighthouse: Monitoring Reader)──► alert agent (one process)
   A1  A2  B1  B2  B3                                          │ customer register
                                                               ▼
                               ServiceDesk (one portal) ─ queue ISSE-CustomerA ─► ISSE for A
                                                        └ queue ISSE-CustomerB ─► ISSE for B
```

- **One Azure identity** in our tenant reads every customer subscription. Each customer
  delegates `Monitoring Reader` to it through **Azure Lighthouse**
  ([`deploy/lighthouse/`](deploy/lighthouse/alert-agent-monitoring-reader.json)).
- **One ServiceDesk portal**, a **queue (group) per customer**. Each customer's ISSE
  instance watches only its queue (`SDP_QUEUE` + `ISSE_SDP_QUEUE_FILTER=true`).
- **The customer register** ([`deploy/customers.example.yaml`](deploy/customers.example.yaml))
  is the only thing that maps a subscription to a customer. No secrets in it.

## The contract (why this can be a separate repo)

The agent and the ISSE pipeline share a **data contract, not code**:

| | |
|---|---|
| Agent → ServiceDesk (write) | Creates a request in the customer's group, whose description carries the Azure Monitor **common alert schema** JSON, plus VM/RG in `udf_char1`/`udf_char2`. Optionally an opening priority from the customer's SLA. |
| ISSE ← ServiceDesk (read) | Each ISSE instance works its own queue, parses the payload (`isse.identification.alerts.from_ticket`), confirms the machine from `alertTargetIDs`, and reads it **in the subscription the alert names** if that is one of its `AZURE_SUBSCRIPTION_ID` / `AZURE_SUBSCRIPTION_IDS`. Any other subscription is a conflict for a person. |
| Dedup | By the alert's own `alertId`, in this agent's own SQLite store. ISSE independently dedups the resulting ticket via its audit DB. Two independent guards, no shared DB. |

The payload shape ISSE reads is pinned by `tests/test_cas_contract.py`, which
round-trips the agent's payload through a **frozen snapshot** of ISSE's parser. If
ISSE's parser ever changes, update that snapshot (and ISSE's CI fixture) in the same
change — the mismatch fails a build rather than a production ticket.

## What it does, per customer, per subscription, per alert

```
subscription unreadable?                 → report it, carry on with the rest
alert's machine not in that subscription → skip   (never cross-filed)
outside the subscription's scoped groups → skip   (bounds alert volume)
below the customer's severity floor      → skip
already filed (durable dedup)?           → skip
otherwise → file a request in the customer's queue, carrying the payload
```

Resource-group scope matching is case-insensitive (Azure Monitor lowercases resource
IDs), and the request carries the group **as spelled in the register**, because the
pipeline's guardrail scope check is case-sensitive.

## Usage

```bash
pip install -e ".[dev]"

isse-alerts doctor   # read-only preflight: register, every subscription, ServiceDesk token
isse-alerts list     # read-only: firing VM alerts per customer, and where each would go
isse-alerts once     # one poll cycle (files requests unless ISSE_ALERT_DRY_RUN=true)
isse-alerts watch    # poll forever at ISSE_POLL_INTERVAL_SECONDS
isse-alerts health   # exit 0 only if every customer was read recently (for a monitor)
```

Onboarding a customer, in order:

1. The customer deploys the Lighthouse template on **each** subscription:
   `az deployment sub create --location <region> --template-file
   deploy/lighthouse/alert-agent-monitoring-reader.json --parameters
   managedByTenantId=<our tenant> principalId=<agent SP object id>`.
2. Create the customer's group (queue) in ServiceDesk.
3. Add the customer to the register with `enabled: false`, then `true`.
4. `doctor` until it exits 0, then `list`, then `once` with `ISSE_ALERT_DRY_RUN=true`.
5. Bring up that customer's ISSE instance on the queue, then let `watch` file for real.

`watch` survives partial failure: an unreadable subscription is logged and the other
customers are still served; one bad alert never blocks the others; a cycle that reaches
no customer at all backs off (up to 8x the poll interval). A ServiceDesk
**authentication** failure is logged as needing a person (a refresh token does not fix
itself) — it stops filing for everyone, since all customers share the portal — but the
loop keeps trying, so the agent recovers once the token is replaced.

The register is validated at start: a subscription under two customers, a customer
without a queue or subscriptions, or an unknown severity stops the agent with exit code
2 rather than guessing where an alert goes.

## Configuration

- [`deploy/customers.example.yaml`](deploy/customers.example.yaml) — the register, per
  customer: `queue`, `subscriptions` (each with optional `resource_groups`),
  `min_severity`, `priority_by_severity` (the SLA). Point `ISSE_ALERT_CUSTOMERS_FILE` at it.
- [`deploy/env.example`](deploy/env.example) — the one Azure identity, the one portal,
  the loop.

Without `ISSE_ALERT_CUSTOMERS_FILE` the agent runs for a single customer from
`AZURE_SUBSCRIPTION_ID` / `ISSE_SANDBOX_RESOURCE_GROUP` / `SDP_QUEUE`, as it started.

The agent needs only:

- **Azure** `Monitoring Reader` on each registered subscription (read-only), and
- **ServiceDesk** permission to create a request in each customer's group.

Nothing here can change a machine.

`priority_by_severity` sets the priority a request **opens** at. ISSE only ever raises
a priority (it never lowers what is on a ticket), so treat the mapping as a floor.

## Deployment

One process for all customers, via `deploy/isse-alerts@.service` (the instance name is
just the deployment's directory):

```bash
sudo systemctl enable --now isse-alerts@estate   # reads /srv/isse/estate/.env
```

For monitoring, run `isse-alerts health` (same environment) from a timer or monitoring
agent. It reports each customer separately and fails if any of them has not been read
within 4x the poll interval — so one customer's revoked delegation is caught even while
the others are fine.

A `Dockerfile` is provided for local development; no GPU and no baked-in credentials.

## Tests

```bash
pytest -q
```

The suite runs fully offline against fakes (`tests/fakes.py`) — no Azure, no
ServiceDesk, no credentials — which is what lets CI run on every pull request.
`tests/test_multi_customer.py` and `tests/test_customers.py` pin the routing: each
alert into its own customer's queue, never across, and one customer's failure never
stopping another's.

`tests/test_isse_interop.py` goes further: it feeds a request this agent filed into the
**real** ISSE pipeline (parser, alert reconciliation, and a sim-mode orchestrator run),
including one from a customer's second subscription, and checks the machine is
confirmed from the alert and read in the right subscription. It looks for ISSE at
`$ISSE_AGENT_SRC` or a sibling `../isse-agent/src`, and skips if neither exists.

## Not in scope

- No remediation. The agent only files requests.
- No classification or runbook selection — that stays in `isse-agent`.
- No credentials per customer. One identity via Lighthouse; a credential agent / vault
  is a later phase.
