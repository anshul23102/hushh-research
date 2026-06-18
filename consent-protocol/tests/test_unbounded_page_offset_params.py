# tests/test_unbounded_page_offset_params.py
"""
PR attach points:
  GET /api/ria/clients                (api/routes/ria.py :: ria_clients)
  GET /api/consent/center/list        (api/routes/consent.py :: get_consent_center_list)
  GET /api/consent/handshake/history  (api/routes/consent.py :: get_handshake_history)

Verifies that unbounded page Query params are now capped with le=10_000,
preventing authenticated DoS via arbitrarily deep DB offset scans.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth, require_vault_owner_token

_UID = "test-uid-page"


@pytest.fixture()
def client():
    from api.main import app

    app.dependency_overrides[require_firebase_auth] = lambda: _UID
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": _UID,
        "token": "fake",
        "scope": "vault.owner",
    }
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/ria/clients — page le=10_000
# ---------------------------------------------------------------------------


def test_ria_clients_page_over_cap_rejected(client: TestClient) -> None:
    """page > 10_000 must be rejected with 422."""
    resp = client.get("/api/ria/clients?page=99999")
    assert resp.status_code == 422, resp.text


def test_ria_clients_page_at_cap_accepted(client: TestClient) -> None:
    """page = 10_000 must NOT be rejected with 422 (boundary value)."""
    resp = client.get("/api/ria/clients?page=10000")
    assert resp.status_code != 422, f"Boundary page=10000 rejected: {resp.status_code}"


# ---------------------------------------------------------------------------
# GET /api/consent/center/list — page le=10_000
# ---------------------------------------------------------------------------


def test_consent_center_list_page_over_cap_rejected(client: TestClient) -> None:
    """page > 10_000 must be rejected with 422."""
    resp = client.get("/api/consent/center/list?page=99999")
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# GET /api/consent/handshake/history — page le=10_000
# ---------------------------------------------------------------------------


def test_handshake_history_page_over_cap_rejected(client: TestClient) -> None:
    """page > 10_000 must be rejected with 422."""
    resp = client.get(
        "/api/consent/handshake/history?counterpart_id=some-ria&page=99999"
    )
    assert resp.status_code == 422, resp.text

