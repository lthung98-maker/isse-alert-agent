"""The ServiceDesk client against a mock HTTP transport - the portal's real answers."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS
from urllib.parse import parse_qs

import httpx
import pytest

from isse_alert_agent.servicedesk import ServiceDeskAuthError, ServiceDeskFiler

_SETTINGS = NS(sdp_portal="itdesk", sdp_api_base="https://sdpondemand.manageengine.com",
               sdp_oauth_base="https://accounts.zoho.com", sdp_client_id="cid",
               sdp_client_secret="secret", sdp_refresh_token="refresh")


class Portal:
    """Answers the two endpoints the agent uses, and records every call."""

    def __init__(self, request_answers=None, token_answer=None):
        self.calls: list[httpx.Request] = []
        self.request_answers = list(request_answers or [])
        self.token_answer = token_answer or {"access_token": "tok", "expires_in": 3600}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == "/oauth/v2/token":
            return httpx.Response(200, json=self.token_answer)
        status, body = (self.request_answers.pop(0) if self.request_answers else
                        (201, {"request": {"id": "1001"},
                               "response_status": {"status_code": 2000}}))
        return httpx.Response(status, json=body)

    def filer(self) -> ServiceDeskFiler:
        return ServiceDeskFiler(_SETTINGS, client=httpx.Client(
            transport=httpx.MockTransport(self.handler)))

    @property
    def request_calls(self):
        return [c for c in self.calls if c.url.path.endswith("/requests")]


def _sent(request: httpx.Request) -> dict:
    form = parse_qs(request.content.decode())
    return json.loads(form["input_data"][0])["request"]


def test_posts_to_the_portal_scoped_v3_url_with_the_oauth_token():
    portal = Portal()
    created = portal.filer().create_request("subj", "desc", {"udf_char1": "VM1"})

    assert created.ok and created.id == "1001"
    call = portal.request_calls[0]
    assert str(call.url) == "https://sdpondemand.manageengine.com/app/itdesk/api/v3/requests"
    assert call.headers["Authorization"] == "Zoho-oauthtoken tok"
    assert _sent(call) == {"subject": "subj", "description": "desc",
                           "udf_fields": {"udf_char1": "VM1"}}


def test_token_is_cached_across_requests():
    portal = Portal()
    filer = portal.filer()
    filer.create_request("a", "a")
    filer.create_request("b", "b")
    assert sum(1 for c in portal.calls if c.url.path == "/oauth/v2/token") == 1


def test_rejected_refresh_token_is_an_auth_error():
    portal = Portal(token_answer={"error": "invalid_code"})
    with pytest.raises(ServiceDeskAuthError, match="invalid_code"):
        portal.filer().create_request("a", "a")


def test_a_401_mints_a_new_token_once_and_retries():
    portal = Portal(request_answers=[(401, {}), (201, {"request": {"id": "7"}})])
    created = portal.filer().create_request("a", "a")
    assert created.ok and created.id == "7"
    assert sum(1 for c in portal.calls if c.url.path == "/oauth/v2/token") == 2


def test_http_200_with_an_api_error_in_the_body_is_a_failure():
    refusal = (200, {"response_status": {"status_code": 4000, "messages": ["bad field"]}})
    portal = Portal(request_answers=[refusal])
    created = portal.filer().create_request("a", "a")
    assert not created.ok
    assert "4000" in created.detail


def test_a_request_refused_with_udfs_is_filed_again_without_them():
    refusal = (400, {"response_status": {"status_code": 4000, "messages": ["udf_char1"]}})
    portal = Portal(request_answers=[refusal, (201, {"request": {"id": "8"}})])
    created = portal.filer().create_request("a", "a", {"udf_char1": "VM1"})

    assert created.ok and created.id == "8"
    assert "udf_fields" in _sent(portal.request_calls[0])
    assert "udf_fields" not in _sent(portal.request_calls[1])
    assert "without UDFs" in created.detail


def test_missing_portal_is_refused_at_construction():
    with pytest.raises(RuntimeError, match="SDP_PORTAL"):
        ServiceDeskFiler(NS(**{**vars(_SETTINGS), "sdp_portal": None}))


def test_the_customers_queue_and_sla_priority_are_on_the_request():
    portal = Portal()
    portal.filer().create_request("s", "d", {"udf_char1": "VM1"}, queue="ISSE-CustomerA",
                                  priority="High")

    sent = _sent(portal.request_calls[0])
    assert sent["group"] == {"name": "ISSE-CustomerA"}
    assert sent["priority"] == {"name": "High"}


def test_a_rejected_request_drops_udfs_and_priority_but_never_the_queue():
    refusal = (400, {"response_status": {"status_code": 4000, "messages": ["priority"]}})
    portal = Portal(request_answers=[refusal, (201, {"request": {"id": "9"}})])
    created = portal.filer().create_request("s", "d", {"udf_char1": "VM1"},
                                            queue="ISSE-CustomerA", priority="Sev-High")

    retry = _sent(portal.request_calls[1])
    assert created.ok
    assert retry == {"subject": "s", "description": "d", "group": {"name": "ISSE-CustomerA"}}
    assert "without UDFs and priority" in created.detail


def test_a_queue_the_portal_refuses_is_a_failure_not_a_request_without_one():
    refusal = (400, {"response_status": {"status_code": 4000, "messages": ["group"]}})
    portal = Portal(request_answers=[refusal])
    created = portal.filer().create_request("s", "d", queue="No-Such-Queue")

    assert not created.ok
    assert len(portal.request_calls) == 1
