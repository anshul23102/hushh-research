# tests/test_webhook_json_parse_exception_leak.py
"""
CWE-209: Three webhook endpoints returned raw json.JSONDecodeError text in 400
responses, exposing line/column offsets and partial payload content to callers.

Affected endpoints (all unauthenticated -- called by external services):
  POST /gmail/webhook    (kai/gmail.py)
  POST /plaid/webhook    (kai/plaid.py)
  POST /email/webhook    (one/email.py)

After this fix the "message" field is the static string
"Webhook payload is not valid JSON." in all three cases.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


_LEAK_TERMS = [
    "Expecting",
    "line ",
    "column ",
    "char ",
    "JSONDecodeError",
    "json.decoder",
    "utf-8",
    "codec",
]

_BAD_BODIES = [
    b"{bad json",
    b"\xff\xfe",       # invalid UTF-8
    b"",
]


# ---------------------------------------------------------------------------
# Gmail webhook
# ---------------------------------------------------------------------------


def _gmail_client():
    from api.routes.kai.gmail import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("body", _BAD_BODIES)
def test_gmail_webhook_json_error_is_opaque(body):
    client = _gmail_client()
    resp = client.post(
        "/gmail/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    for term in _LEAK_TERMS:
        assert term not in str(detail), f"gmail webhook leaked: {term!r}"


def test_gmail_webhook_json_error_static_message():
    client = _gmail_client()
    resp = client.post(
        "/gmail/webhook",
        content=b"{bad",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    assert detail.get("message") == "Webhook payload is not valid JSON."
    assert detail.get("code") == "GMAIL_WEBHOOK_INVALID_JSON"


# ---------------------------------------------------------------------------
# Plaid webhook
# ---------------------------------------------------------------------------


def _plaid_client():
    from api.routes.kai.plaid import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("body", _BAD_BODIES)
def test_plaid_webhook_json_error_is_opaque(body):
    client = _plaid_client()
    resp = client.post(
        "/plaid/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    for term in _LEAK_TERMS:
        assert term not in str(detail), f"plaid webhook leaked: {term!r}"


def test_plaid_webhook_json_error_static_message():
    client = _plaid_client()
    resp = client.post(
        "/plaid/webhook",
        content=b"{bad",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    assert detail.get("message") == "Webhook payload is not valid JSON."
    assert detail.get("code") == "PLAID_WEBHOOK_INVALID_JSON"


# ---------------------------------------------------------------------------
# One email webhook
# ---------------------------------------------------------------------------


def _email_client():
    from api.routes.one.email import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("body", _BAD_BODIES)
def test_one_email_webhook_json_error_is_opaque(body):
    client = _email_client()
    resp = client.post(
        "/api/one/email/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    for term in _LEAK_TERMS:
        assert term not in str(detail), f"email webhook leaked: {term!r}"


def test_one_email_webhook_json_error_static_message():
    client = _email_client()
    resp = client.post(
        "/api/one/email/webhook",
        content=b"{bad",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", {})
    assert detail.get("message") == "Webhook payload is not valid JSON."
    assert detail.get("code") == "ONE_EMAIL_WEBHOOK_INVALID_JSON"
