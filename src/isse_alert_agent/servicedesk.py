"""The one write path: file a ServiceDesk Plus request.

Thin on purpose. The agent creates requests and does nothing else to ServiceDesk, so
this is the Zoho OAuth refresh-token exchange and a single ``create_request`` call -
the same portal, the same self-client flow and the same URL shape ISSE's own connector
uses (``{SDP_API_BASE}/app/{SDP_PORTAL}/api/v3``), carried in its own small client so the
two repositories stay decoupled.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional, Protocol

from .config import Settings, get_settings

_V3_ACCEPT = "application/vnd.manageengine.sdp.v3+json"


class ServiceDeskAuthError(RuntimeError):
    """The credentials are unusable. Retrying will not help; a person must re-mint them."""


@dataclass
class CreatedRequest:
    id: Optional[str]
    ok: bool
    detail: str = ""


class RequestFiler(Protocol):
    """What the agent needs to file a request. A fake satisfies this in tests."""

    def create_request(self, subject: str, description: str,
                       udf_fields: Optional[dict] = None, queue: Optional[str] = None,
                       priority: Optional[str] = None) -> CreatedRequest:
        ...


class ServiceDeskFiler:
    def __init__(self, settings: Optional[Settings] = None, client=None) -> None:
        import httpx

        self._s = settings or get_settings()
        if not self._s.sdp_portal:
            raise RuntimeError("SDP_PORTAL is not set; required to file ServiceDesk requests")
        self._base = f"{self._s.sdp_api_base.rstrip('/')}/app/{self._s.sdp_portal}/api/v3"
        self._client = client or httpx.Client(timeout=30.0)
        self._token: Optional[str] = None
        self._token_exp = 0.0

    def access_token(self) -> str:
        """A live access token, minted from the refresh token and cached until near expiry."""
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        try:
            r = self._client.post(
                f"{self._s.sdp_oauth_base.rstrip('/')}/oauth/v2/token",
                data={
                    "refresh_token": self._s.sdp_refresh_token,
                    "client_id": self._s.sdp_client_id,
                    "client_secret": self._s.sdp_client_secret,
                    "grant_type": "refresh_token",
                },
            )
        except Exception as e:  # noqa: BLE001
            raise ServiceDeskAuthError(
                f"cannot reach Zoho OAuth at {self._s.sdp_oauth_base}: {e}") from e
        # Zoho rejects a bad refresh token with HTTP 200 and an `error` field.
        data = _safe_json(r)
        token = data.get("access_token")
        if not token:
            reason = data.get("error") or f"HTTP {r.status_code}"
            raise ServiceDeskAuthError(
                f"ServiceDesk token refresh rejected ({reason}). SDP_REFRESH_TOKEN is "
                "invalid, revoked, or missing a scope.")
        self._token = token
        self._token_exp = time.time() + int(data.get("expires_in", 3600))
        return token

    def _post_request(self, request: dict):
        return self._client.post(
            f"{self._base}/requests",
            headers={"Authorization": f"Zoho-oauthtoken {self.access_token()}",
                     "Accept": _V3_ACCEPT},
            data={"input_data": json.dumps({"request": request})},
        )

    def create_request(self, subject: str, description: str,
                       udf_fields: Optional[dict] = None, queue: Optional[str] = None,
                       priority: Optional[str] = None) -> CreatedRequest:
        """File one request into ``queue`` (the customer's ServiceDesk group).

        The queue is what routes a request to its customer's ISSE, so it is never
        dropped to make a request land: a request outside its queue reaches no one, or
        the wrong customer. UDFs and priority are conveniences and are dropped on a
        rejection, because the target is also in the description and ISSE derives its
        own priority anyway.
        """
        essential: dict = {"subject": subject, "description": description}
        if queue:
            essential["group"] = {"name": queue}
        request = dict(essential)
        if udf_fields:
            request["udf_fields"] = udf_fields
        if priority:
            request["priority"] = {"name": priority}
        r = self._post_request(request)
        if r.status_code == 401:
            # Revoked or expired early; mint once more before calling it a failure.
            self._token = None
            r = self._post_request(request)
            if r.status_code == 401:
                raise ServiceDeskAuthError("ServiceDesk refused the access token (HTTP 401)")

        result = _result(r)
        if not result.ok and request != essential:
            # A portal whose request template lacks these UDFs, or that names its
            # priorities differently, rejects the whole request. File without them
            # rather than not at all, and say so.
            dropped = " and ".join(label for key, label in (("udf_fields", "UDFs"),
                                                            ("priority", "priority"))
                                   if key in request)
            retry = _result(self._post_request(essential))
            retry.detail = f"{retry.detail}; filed without {dropped} after: {result.detail}"
            return retry
        return result


def _result(r) -> CreatedRequest:
    body = _safe_json(r)
    code, msg = _api_status(body)
    # SDP can answer HTTP 200 and still refuse in the body; 2000 is its success code.
    ok = r.status_code < 300 and (code is None or code == 2000)
    rid = (body.get("request") or {}).get("id") if isinstance(body, dict) else None
    detail = f"HTTP {r.status_code}" + (f", api {code}: {msg}" if code not in (None, 2000) else "")
    return CreatedRequest(id=str(rid) if rid else None, ok=ok and bool(rid), detail=detail)


def _api_status(body: dict) -> tuple[Optional[int], str]:
    rs = (body or {}).get("response_status")
    if isinstance(rs, list):
        rs = rs[0] if rs else {}
    if not isinstance(rs, dict):
        return None, ""
    code = rs.get("status_code")
    msg = rs.get("messages") or rs.get("status") or ""
    return (int(code) if isinstance(code, int) else None), str(msg)


def _safe_json(response) -> dict:
    try:
        body = response.json()
        return body if isinstance(body, dict) else {}
    except Exception:  # noqa: BLE001
        return {}
