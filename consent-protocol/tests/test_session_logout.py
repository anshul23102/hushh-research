"""Tests for POST /api/consent/logout — token revocation on logout."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import hushh_mcp.consent.token as token_mod
from api.middleware import require_vault_owner_token
from api.routes import session


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(session.router)
    return app


def _vault_owner_dep(user_id: str = "user_123", bearer: str = "tok_abc") -> dict:
    return {"user_id": user_id, "token": bearer}


# ---------------------------------------------------------------------------
# Auth guards
# ---------------------------------------------------------------------------


def test_logout_requires_vault_owner_token():
    """Logout without a valid VAULT_OWNER token must be rejected."""
    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})
    assert response.status_code == 401


def test_logout_rejects_user_id_mismatch(monkeypatch):
    """Token user_id must match request.userId to prevent cross-user logout."""
    monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="other_user"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 403
    assert response.json()["detail"] == "userId mismatch"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_logout_revokes_presenting_token_in_memory(monkeypatch):
    """The presenting VAULT_OWNER token is added to the in-memory revocation set."""
    revoked: list[str] = []
    monkeypatch.setattr(token_mod, "revoke_token", lambda t: revoked.append(t))

    class _FakeDB:
        async def get_active_internal_tokens(self, user_id, agent_id=None):
            return []

        async def insert_event(self, **kwargs):
            return 1

    monkeypatch.setattr(session, "ConsentDBService", _FakeDB)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="user_123", bearer="tok_presenting"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 200
    assert "tok_presenting" in revoked


def test_logout_writes_revoked_event_per_active_token(monkeypatch):
    """A REVOKED DB event is written for every active internal session token."""
    monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

    inserted: list[dict] = []

    class _FakeDB:
        async def get_active_internal_tokens(self, user_id, agent_id=None):
            return [
                {"scope": "vault.owner", "token_id": "tok_1"},
                {"scope": "vault.owner", "token_id": "tok_2"},
            ]

        async def insert_event(self, **kwargs):
            inserted.append(kwargs)
            return 1

    monkeypatch.setattr(session, "ConsentDBService", _FakeDB)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="user_123"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 200
    assert response.json()["revoked"] == 2
    assert all(ev["action"] == "REVOKED" for ev in inserted)
    assert all(ev["user_id"] == "user_123" for ev in inserted)
    assert all(ev["agent_id"] == "self" for ev in inserted)
    assert {ev["scope"] for ev in inserted} == {"vault.owner"}


def test_logout_returns_success_payload(monkeypatch):
    """Response body contains status, message, and revoked count."""
    monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

    class _FakeDB:
        async def get_active_internal_tokens(self, user_id, agent_id=None):
            return [{"scope": "vault.owner", "token_id": "tok_x"}]

        async def insert_event(self, **kwargs):
            return 1

    monkeypatch.setattr(session, "ConsentDBService", _FakeDB)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="user_123"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["revoked"] == 1


# ---------------------------------------------------------------------------
# Resilience: DB failure must not block the response
# ---------------------------------------------------------------------------


def test_logout_succeeds_even_if_db_raises(monkeypatch):
    """DB failure must not prevent logout — in-memory revocation already fired."""
    monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

    class _FailingDB:
        async def get_active_internal_tokens(self, user_id, agent_id=None):
            raise RuntimeError("supabase is down")

        async def insert_event(self, **kwargs):  # pragma: no cover
            raise RuntimeError("supabase is down")

    monkeypatch.setattr(session, "ConsentDBService", _FailingDB)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="user_123"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["revoked"] == 0


def test_logout_skips_tokens_with_missing_scope(monkeypatch):
    """Tokens without a scope field are silently skipped — no REVOKED event written."""
    monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

    inserted: list[dict] = []

    class _FakeDB:
        async def get_active_internal_tokens(self, user_id, agent_id=None):
            return [
                {"scope": "", "token_id": "malformed"},
                {"scope": "vault.owner", "token_id": "valid_tok"},
            ]

        async def insert_event(self, **kwargs):
            inserted.append(kwargs)
            return 1

    monkeypatch.setattr(session, "ConsentDBService", _FakeDB)

    app = _build_app()
    app.dependency_overrides[require_vault_owner_token] = lambda: _vault_owner_dep(
        user_id="user_123"
    )

    client = TestClient(app)
    response = client.post("/api/consent/logout", json={"userId": "user_123"})

    assert response.status_code == 200
    assert len(inserted) == 1
    assert inserted[0]["scope"] == "vault.owner"
