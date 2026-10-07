"""Configuration for the alert agent.

Same conventions as ISSE: pydantic-settings, read once at process start, loaded from the
process environment and an optional ``.env`` in the repo root. The alias names are kept
identical to ISSE's where the two read the same thing (``AZURE_*``, ``SDP_*``,
``ISSE_SANDBOX_RESOURCE_GROUP``, ``ISSE_POLL_INTERVAL_SECONDS``). Which customers there
are, and where their alerts go, is not here: it is the customer register
(:mod:`isse_alert_agent.customers`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILES = (str(REPO_ROOT / ".env"),)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Customers ----
    # The customer register (YAML): each customer's subscriptions, scoped resource
    # groups, queue and SLA. See deploy/customers.example.yaml. Unset = one customer
    # from AZURE_SUBSCRIPTION_ID / ISSE_SANDBOX_RESOURCE_GROUP / SDP_QUEUE below.
    customers_file: str = Field("", alias="ISSE_ALERT_CUSTOMERS_FILE")

    # ---- Azure (read-only: Monitoring Reader on every registered subscription) ----
    # One identity for every customer: in our own tenant, with Monitoring Reader
    # delegated to it on each customer subscription through Azure Lighthouse.
    azure_tenant_id: Optional[str] = Field(None, alias="AZURE_TENANT_ID")
    azure_client_id: Optional[str] = Field(None, alias="AZURE_CLIENT_ID")
    azure_client_secret: Optional[str] = Field(None, alias="AZURE_CLIENT_SECRET")

    # ---- Single-customer mode (no register file) ----
    azure_subscription_id: Optional[str] = Field(None, alias="AZURE_SUBSCRIPTION_ID")
    # Resource groups the agent will file requests for. Shared alias with ISSE so the
    # agent is scoped to exactly the estate the pipeline is allowed to work - which is
    # what keeps alert volume bounded (Phase 2 plan, risk 1). Empty = the whole
    # subscription, which should only be used in a sandbox.
    scope_resource_groups: str = Field("", alias="ISSE_SANDBOX_RESOURCE_GROUP")

    # ---- Which alerts become requests ----
    # Only alerts at or above this severity raise a request, as an Azure Sev *rank*:
    # 0 is critical and 4 is verbose, so 2 means Sev0/Sev1/Sev2 and drops the two
    # informational tiers. The monitor's own severity, never the agent's judgement.
    # The default for customers whose register entry sets none.
    alert_min_severity: int = Field(2, alias="ISSE_ALERT_MIN_SEVERITY")
    # How far back each poll looks. Azure buckets this to 1h / 1d / 7d / 30d.
    alert_lookback_hours: int = Field(1, alias="ISSE_ALERT_LOOKBACK_HOURS")

    # ---- Loop + dedup ----
    poll_interval_seconds: float = Field(30.0, alias="ISSE_POLL_INTERVAL_SECONDS")
    # Durable, so a 30-second poll never files the same alert twice across a restart.
    # One store for every customer: an alert id embeds its subscription, so ids from
    # different customers never collide.
    dedup_db_path: str = Field(str(REPO_ROOT / "data" / "alerts-seen.db"),
                               alias="ISSE_ALERT_DEDUP_DB")
    # Discover and log, but do not file anything. The safe default for a first run
    # against a new subscription.
    dry_run: bool = Field(False, alias="ISSE_ALERT_DRY_RUN")
    # Touched after every cycle that reached Azure, so `isse-alerts health` (and a
    # monitor behind it) can tell a working agent from a process that is merely alive.
    heartbeat_file: str = Field(str(REPO_ROOT / "data" / "alerts-heartbeat"),
                                alias="ISSE_ALERT_HEARTBEAT_FILE")
    # "text" for a person watching the journal, "json" for a log shipper.
    log_format: str = Field("text", alias="ISSE_LOG_FORMAT")

    # ---- ManageEngine ServiceDesk Plus Cloud (the one write path) ----
    sdp_data_center: str = Field("com", alias="SDP_DATA_CENTER")
    sdp_portal: Optional[str] = Field(None, alias="SDP_PORTAL")
    sdp_api_base: str = Field("https://sdpondemand.manageengine.com", alias="SDP_API_BASE")
    sdp_oauth_base: str = Field("https://accounts.zoho.com", alias="SDP_OAUTH_BASE")
    sdp_client_id: Optional[str] = Field(None, alias="SDP_CLIENT_ID")
    sdp_client_secret: Optional[str] = Field(None, alias="SDP_CLIENT_SECRET")
    sdp_refresh_token: Optional[str] = Field(None, alias="SDP_REFRESH_TOKEN")
    # Single-customer mode only; with a register each customer names its own queue.
    sdp_queue: str = Field("ISSE-Standby", alias="SDP_QUEUE")

    @property
    def scope_resource_group_tuple(self) -> tuple[str, ...]:
        return tuple(rg.strip() for rg in (self.scope_resource_groups or "").split(",")
                     if rg.strip())

    @property
    def azure_service_principal(self) -> bool:
        return bool(self.azure_client_id and self.azure_client_secret and self.azure_tenant_id)

    @property
    def sdp_is_configured(self) -> bool:
        return bool(self.sdp_portal and self.sdp_client_id and self.sdp_client_secret
                    and self.sdp_refresh_token)


_settings: Optional[Settings] = None


def get_settings(reload: bool = False) -> Settings:
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings
