"""The one write path: file a ServiceDesk Plus request.

Thin on purpose. The agent creates requests and does nothing else to ServiceDesk, so
this is the Zoho OAuth refresh-token exchange and a single ``create_request`` call -
the same portal and the same self-client flow ISSE uses, carried in its own small
client so the two repositories stay decoupled.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Protocol

from .config import Settings, get_settings


@dataclass
class CreatedRequest:
    id: Optional[str]
    ok: bool
    detail: str = ""


class RequestFiler(Protocol):
    """What the agent needs to file a request. A fake satisfies this in tests."""

    def create_request(self, subject: str, description: str,
                       udf_fields: Optional[dict] = None) -> CreatedRequest:
        ...


class ServiceDeskFiler:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._s = settings or get_settings()
        self._base = f"{self._s.sdp_api_base.rstrip('/')}/api/v3"
        self._token: Optional[str] = None

    def _access_token(self) -> str:
        import httpx

        if self._token:
            return self._token
        r = httpx.post(
            f"{self._s.sdp_oauth_base.rstrip('/')}/oauth/v2/token",
            params={
                "refresh_token": self._s.sdp_refresh_token,
                "client_id": self._s.sdp_client_id,
                "client_secret": self._s.sdp_client_secret,
                "grant_type": "refresh_token",
            },
            timeout=30.0,
        )
        r.raise_for_status()
        token = r.json().get("access_token")
        if not token:
            raise RuntimeError(f"ServiceDesk OAuth returned no access_token: {r.text[:200]}")
        self._token = token
        return token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Zoho-oauthtoken {self._access_token()}",
            "Accept": "application/vnd.manageengine.sdp.v3+json",
        }

    def create_request(self, subject: str, description: str,
                       udf_fields: Optional[dict] = None) -> CreatedRequest:
        import httpx

        request: dict = {"subject": subject, "description": description}
        if udf_fields:
            request["udf_fields"] = udf_fields
        payload = {"input_data": json.dumps({"request": request})}
        r = httpx.post(f"{self._base}/requests", headers=self._headers(),
                       data=payload, timeout=30.0)
        ok = r.status_code < 300
        body = _safe_json(r)
        rid = ((body.get("request") or {}).get("id")) if isinstance(body, dict) else None
        return CreatedRequest(id=rid, ok=ok, detail=f"HTTP {r.status_code}")


def _safe_json(response) -> dict:
    try:
        return response.json()
    except Exception:  # noqa: BLE001
        return {}
