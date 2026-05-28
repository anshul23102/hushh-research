# tests/test_iam_schema_hint_leak.py
"""
CWE-209: _iam_schema_not_ready_response leaked DB migration commands and
exception detail from IAMSchemaNotReadyError in iam.py and invites.py.

Before this fix the 503 body contained:
  {"error": "<exc msg>", "code": "IAM_SCHEMA_NOT_READY",
   "hint": "Run `python db/migrate.py --iam` and `python db/verify/verify_iam_schema.py`."}

After this fix the body is:
  {"error": "IAM service is temporarily unavailable.", "code": "IAM_SCHEMA_NOT_READY"}

No migration command strings, no internal exception detail.
"""

import pytest
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LEAK_TERMS = [
    "db/migrate.py",
    "verify_iam_schema",
    "hint",
    "IAMSchemaNotReadyError",
    "schema migration",
]


def _make_iam_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.middleware as mw
    from api.routes.iam import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[mw.require_firebase_auth] = lambda: "stub-uid"
    return TestClient(app, raise_server_exceptions=False)


def _make_invites_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes.invites import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# iam.py -- /api/iam/persona/switch
# ---------------------------------------------------------------------------


class TestIamSwitchPersonaSchemaNotReady:
    def test_does_not_leak_migration_commands(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        client = _make_iam_client()
        with patch(
            "api.routes.iam.RIAIAMService",
        ) as MockSvc:
            instance = MockSvc.return_value
            instance.switch_persona = AsyncMock(
                side_effect=IAMSchemaNotReadyError("schema not ready")
            )
            resp = client.post(
                "/api/iam/persona/switch", json={"persona": "ria"}
            )

        assert resp.status_code == 503
        body = resp.text
        for term in _LEAK_TERMS:
            assert term not in body, f"503 response leaked: {term!r}"

    def test_returns_opaque_error(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        client = _make_iam_client()
        with patch("api.routes.iam.RIAIAMService") as MockSvc:
            instance = MockSvc.return_value
            instance.switch_persona = AsyncMock(
                side_effect=IAMSchemaNotReadyError("internal detail")
            )
            resp = client.post(
                "/api/iam/persona/switch", json={"persona": "investor"}
            )

        data = resp.json()
        assert data["code"] == "IAM_SCHEMA_NOT_READY"
        assert "hint" not in data
        assert "unavailable" in data["error"].lower()
        assert "internal detail" not in data["error"]


class TestIamMarketplaceOptInSchemaNotReady:
    def test_does_not_leak_migration_commands(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        client = _make_iam_client()
        with patch("api.routes.iam.RIAIAMService") as MockSvc:
            instance = MockSvc.return_value
            instance.set_marketplace_opt_in = AsyncMock(
                side_effect=IAMSchemaNotReadyError("schema error")
            )
            resp = client.post("/api/iam/marketplace/opt-in", json={"enabled": True})

        assert resp.status_code == 503
        for term in _LEAK_TERMS:
            assert term not in resp.text, f"503 leaked: {term!r}"


# ---------------------------------------------------------------------------
# invites.py -- /api/invites/{token}
# ---------------------------------------------------------------------------


class TestInviteGetSchemaNotReady:
    def test_does_not_leak_migration_commands(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        client = _make_invites_client()
        with patch("api.routes.invites.RIAIAMService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_ria_invite = AsyncMock(
                side_effect=IAMSchemaNotReadyError("schema not ready")
            )
            resp = client.get("/api/invites/tok-abc123")

        assert resp.status_code == 503
        for term in _LEAK_TERMS:
            assert term not in resp.text, f"503 leaked: {term!r}"

    def test_returns_opaque_error(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        client = _make_invites_client()
        with patch("api.routes.invites.RIAIAMService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_ria_invite = AsyncMock(
                side_effect=IAMSchemaNotReadyError("internal DB info")
            )
            resp = client.get("/api/invites/tok-xyz")

        data = resp.json()
        assert data["code"] == "IAM_SCHEMA_NOT_READY"
        assert "hint" not in data
        assert "internal DB info" not in data["error"]


class TestInviteAcceptSchemaNotReady:
    def test_does_not_leak_migration_commands(self):
        from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

        import api.middleware as mw
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from api.routes.invites import router

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[mw.require_firebase_auth] = lambda: "stub-uid"
        client = TestClient(app, raise_server_exceptions=False)

        with patch("api.routes.invites.RIAIAMService") as MockSvc:
            instance = MockSvc.return_value
            instance.accept_ria_invite = AsyncMock(
                side_effect=IAMSchemaNotReadyError("schema migration pending")
            )
            resp = client.post("/api/invites/tok-abc/accept")

        assert resp.status_code == 503
        for term in _LEAK_TERMS:
            assert term not in resp.text, f"503 leaked: {term!r}"
