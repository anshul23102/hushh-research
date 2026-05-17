"""Backend proof for POST /api/consent/logout token revocation.

Canonical attach point:
    api.routes.session.logout_session
    -> POST /api/consent/logout

These tests prove:
- The logout route is reachable and calls actual revocation (not a stub no-op).
- The presenting token is marked revoked in-memory immediately.
- A REVOKED DB event is written for every active internal session token.
- DB failure does not block the HTTP response (in-memory revocation already fired).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import hushh_mcp.consent.token as token_mod
from api.middleware import require_vault_owner_token
from api.routes import session

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(session.router)
    return app


def _vault_stub(user_id: str = "user_revoke_001", bearer: str = "tok_presenting") -> dict:
    return {"user_id": user_id, "token": bearer}


class _FakeDB:
    """In-memory stub that records insert_event calls."""

    def __init__(self, active_tokens: list[dict] | None = None):
        self.active_tokens = active_tokens or []
        self.inserted: list[dict] = []

    async def get_active_internal_tokens(self, user_id: str, agent_id: str | None = None):
        return list(self.active_tokens)

    async def insert_event(self, **kwargs):
        self.inserted.append(kwargs)
        return 1


# ---------------------------------------------------------------------------
# class TestLogoutTokenRevocationHTTPProof
# ---------------------------------------------------------------------------


class TestLogoutTokenRevocationHTTPProof:
    """HTTP-level proof that logout revokes tokens rather than performing a stub no-op."""

    # -- Route reachability --

    def test_logout_route_is_reachable(self, monkeypatch):
        """POST /api/consent/logout must respond 200 when called with a valid token."""
        monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)
        fake_db = _FakeDB()
        monkeypatch.setattr(session, "ConsentDBService", lambda: fake_db)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub()
        client = TestClient(app)

        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})
        assert response.status_code == 200

    def test_logout_requires_vault_owner_token(self):
        """Requests without a valid VAULT_OWNER token must be rejected with 401."""
        client = TestClient(_build_app(), raise_server_exceptions=False)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})
        assert response.status_code == 401

    def test_logout_rejects_user_id_mismatch(self, monkeypatch):
        """Token user_id must match request.userId to prevent cross-user logout."""
        monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub(
            user_id="other_user"
        )
        client = TestClient(app)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})

        assert response.status_code == 403

    # -- Actual revocation (not stub no-op) --

    def test_presenting_token_is_revoked_in_memory(self, monkeypatch):
        """revoke_token must be called with the presenting bearer token."""
        revoked: list[str] = []
        monkeypatch.setattr(token_mod, "revoke_token", lambda t: revoked.append(t))
        fake_db = _FakeDB()
        monkeypatch.setattr(session, "ConsentDBService", lambda: fake_db)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub(
            user_id="user_revoke_001", bearer="tok_presenting"
        )
        client = TestClient(app)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})

        assert response.status_code == 200
        assert "tok_presenting" in revoked, (
            "Presenting token must be passed to revoke_token immediately on logout"
        )

    def test_active_tokens_receive_revoked_db_event(self, monkeypatch):
        """A REVOKED event must be written to the DB for every active internal session token."""
        monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

        fake_db = _FakeDB(
            active_tokens=[
                {"scope": "vault.owner", "token_id": "tok_alpha"},
                {"scope": "vault.owner", "token_id": "tok_beta"},
            ]
        )
        monkeypatch.setattr(session, "ConsentDBService", lambda: fake_db)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub()
        client = TestClient(app)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})

        assert response.status_code == 200
        assert response.json()["revoked"] == 2
        assert all(ev["action"] == "REVOKED" for ev in fake_db.inserted)
        assert all(ev["user_id"] == "user_revoke_001" for ev in fake_db.inserted)

    def test_token_marked_revoked_count_in_response(self, monkeypatch):
        """Response body must include the number of tokens revoked in the DB."""
        monkeypatch.setattr(token_mod, "revoke_token", lambda _t: None)

        fake_db = _FakeDB(active_tokens=[{"scope": "vault.owner", "token_id": "tok_x"}])
        monkeypatch.setattr(session, "ConsentDBService", lambda: fake_db)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub()
        client = TestClient(app)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})

        body = response.json()
        assert body["status"] == "success"
        assert body["revoked"] == 1

    def test_db_failure_does_not_block_response(self, monkeypatch):
        """In-memory revocation fires before the DB call so DB failure must not block logout."""
        revoked: list[str] = []
        monkeypatch.setattr(token_mod, "revoke_token", lambda t: revoked.append(t))

        class _FailDB:
            async def get_active_internal_tokens(self, user_id, agent_id=None):
                raise RuntimeError("db unavailable")

            async def insert_event(self, **kwargs):
                raise RuntimeError("db unavailable")

        monkeypatch.setattr(session, "ConsentDBService", _FailDB)

        app = _build_app()
        app.dependency_overrides[require_vault_owner_token] = lambda: _vault_stub(
            bearer="tok_even_if_db_down"
        )
        client = TestClient(app)
        response = client.post("/api/consent/logout", json={"userId": "user_revoke_001"})

        assert response.status_code == 200
        assert "tok_even_if_db_down" in revoked
        assert response.json()["revoked"] == 0
