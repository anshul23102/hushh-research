"""
Regression tests for CWE-400 query parameter bounds on consent and RIA routes.

CWE-400 -- Uncontrolled Resource Consumption.

GET /api/ria/universe's tier Query parameter had no max_length, allowing an
arbitrarily large value to reach the Renaissance universe service. Fixed by
adding max_length=64 in api/routes/ria.py::renaissance_universe.

GET /api/consent/center/list and GET /api/consent/center/summary already
enforce max_length on actor, surface, mode, and q in
api/routes/consent.py::get_consent_center_list and get_consent_center_summary.
Those endpoints needed no production change; the tests below add regression
coverage for the existing bound so a future refactor cannot drop it silently.

Attach point: api/routes/consent.py, api/routes/ria.py
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes import consent as consent_mod
from api.routes import ria as ria_mod
from api.routes.consent import require_firebase_auth

_UID = "test-uid-cwe400"
_VAULT_TOKEN = {"user_id": _UID, "token": "fake", "scope": "vault.owner"}


@pytest.fixture(scope="module")
def consent_client() -> TestClient:
    app = FastAPI()
    app.include_router(consent_mod.router)
    app.dependency_overrides[require_firebase_auth] = lambda: _UID
    app.dependency_overrides[require_vault_owner_token] = lambda: _VAULT_TOKEN
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def ria_client() -> TestClient:
    app = FastAPI()
    app.include_router(ria_mod.router)
    app.dependency_overrides[require_firebase_auth] = lambda: _UID
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# /api/consent/center/list (existing bounds, regression coverage only)
# ---------------------------------------------------------------------------


def test_consent_list_actor_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/list", params={"actor": "x" * 100})
    assert resp.status_code == 422, resp.text


def test_consent_list_surface_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/list", params={"surface": "x" * 100})
    assert resp.status_code == 422, resp.text


def test_consent_list_mode_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/list", params={"mode": "x" * 100})
    assert resp.status_code == 422, resp.text


def test_consent_list_q_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/list", params={"q": "x" * 500})
    assert resp.status_code == 422, resp.text


def test_consent_list_valid_params_not_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get(
        "/api/consent/center/list",
        params={"actor": "investor", "surface": "pending", "mode": "consents"},
    )
    assert resp.status_code != 422, resp.text


# ---------------------------------------------------------------------------
# /api/consent/center/summary (existing bounds, regression coverage only)
# ---------------------------------------------------------------------------


def test_consent_summary_actor_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/summary", params={"actor": "x" * 100})
    assert resp.status_code == 422, resp.text


def test_consent_summary_mode_over_max_rejected(consent_client: TestClient) -> None:
    resp = consent_client.get("/api/consent/center/summary", params={"mode": "x" * 100})
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# /api/ria/universe (real fix: tier had no bound before this PR)
# ---------------------------------------------------------------------------


def test_ria_universe_tier_over_max_rejected(ria_client: TestClient) -> None:
    resp = ria_client.get("/api/ria/universe", params={"tier": "x" * 200})
    assert resp.status_code == 422, resp.text


def test_ria_universe_valid_tier_not_rejected(ria_client: TestClient) -> None:
    resp = ria_client.get("/api/ria/universe", params={"tier": "core"})
    assert resp.status_code != 422, resp.text
