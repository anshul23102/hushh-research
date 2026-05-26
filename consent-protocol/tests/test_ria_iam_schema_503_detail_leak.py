"""
Tests: CWE-209 -- RIA 503 responses must not leak IAM schema internals.

When IAMSchemaNotReadyError is raised, the HTTP response previously
included the raw exception message (which contains internal script paths
and migration commands) and a hint field that explicitly listed those
paths. Both must be absent from the response.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth
from api.routes.ria import router
from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError, RIAIAMService


def _build_client(overrides: dict) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides.update(overrides)
    return TestClient(app, raise_server_exceptions=False)


def _auth_override(uid: str):
    async def _dep():
        return uid

    return _dep


class TestIAMSchemaNotReadyResponseDoesNotLeak:
    """503 response for IAMSchemaNotReadyError must omit internal details."""

    def test_503_does_not_contain_hint_with_script_paths(self, monkeypatch):
        async def _raise(*_a, **_kw):
            raise IAMSchemaNotReadyError()

        monkeypatch.setattr(RIAIAMService, "submit_ria_onboarding", _raise)
        client = _build_client({require_firebase_auth: _auth_override("uid1")})
        resp = client.post(
            "/api/ria/onboarding/submit",
            json={"display_name": "Test RIA"},
        )
        assert resp.status_code == 503
        body = resp.json()
        body_str = str(body)
        assert "db/migrate.py" not in body_str
        assert "verify_iam_schema.py" not in body_str
        assert "python" not in body_str

    def test_503_does_not_contain_raw_exception_message(self, monkeypatch):
        async def _raise(*_a, **_kw):
            raise IAMSchemaNotReadyError(
                "IAM schema is not ready. Run `python db/migrate.py --iam`"
            )

        monkeypatch.setattr(RIAIAMService, "submit_ria_onboarding", _raise)
        client = _build_client({require_firebase_auth: _auth_override("uid1")})
        resp = client.post(
            "/api/ria/onboarding/submit",
            json={"display_name": "Test RIA"},
        )
        body = resp.json()
        body_str = str(body)
        assert "db/migrate.py" not in body_str
        assert "--iam" not in body_str

    def test_503_code_is_present(self, monkeypatch):
        async def _raise(*_a, **_kw):
            raise IAMSchemaNotReadyError()

        monkeypatch.setattr(RIAIAMService, "submit_ria_onboarding", _raise)
        client = _build_client({require_firebase_auth: _auth_override("uid1")})
        resp = client.post(
            "/api/ria/onboarding/submit",
            json={"display_name": "Test RIA"},
        )
        body = resp.json()
        assert body.get("code") == "IAM_SCHEMA_NOT_READY"

    def test_503_response_is_opaque(self, monkeypatch):
        async def _raise(*_a, **_kw):
            raise IAMSchemaNotReadyError()

        monkeypatch.setattr(RIAIAMService, "submit_ria_onboarding", _raise)
        client = _build_client({require_firebase_auth: _auth_override("uid1")})
        resp = client.post(
            "/api/ria/onboarding/submit",
            json={"display_name": "Test RIA"},
        )
        body = resp.json()
        assert "hint" not in body
        assert "hint" not in str(body)
