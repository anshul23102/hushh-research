"""Tests: RIA route IAM schema error must not leak internal hints or exc detail.

Covers a sample of the RIA routes that catch IAMSchemaNotReadyError:
  POST /api/ria/onboarding/submit
  GET  /api/ria/onboarding/status
  GET  /api/ria/home
  GET  /api/ria/clients
  GET  /api/ria/invites

Each must return 503 with an opaque message -- no migration commands,
no file paths, no raw exception text.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth

INTERNAL_STRINGS = [
    "db/migrate.py",
    "verify_iam_schema",
    "python ",
    "--iam",
    "hint",
    "schema is not ready",
]


def _make_app():
    from fastapi import FastAPI

    from api.routes.ria import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_firebase_auth] = lambda: "stub-uid"
    return app


@pytest.fixture()
def client():
    return TestClient(_make_app(), raise_server_exceptions=False)


def _patch_not_ready(method_name: str):
    from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError

    target = f"api.routes.ria.RIAIAMService.{method_name}"
    return patch(target, new_callable=AsyncMock, side_effect=IAMSchemaNotReadyError())


def _assert_opaque_503(resp):
    assert resp.status_code == 503
    body = resp.json()
    assert "hint" not in body
    text = resp.text.lower()
    for s in INTERNAL_STRINGS:
        assert s not in text, f"Leaked internal string: {s!r}"
    assert body.get("code") == "IAM_SCHEMA_NOT_READY"


class TestOnboardingSubmitIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("submit_ria_onboarding"):
            resp = client.post(
                "/api/ria/onboarding/submit",
                json={"display_name": "Test Advisor"},
            )
        _assert_opaque_503(resp)


class TestOnboardingStatusIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("get_ria_onboarding_status"):
            resp = client.get("/api/ria/onboarding/status")
        _assert_opaque_503(resp)


class TestRiaHomeIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("get_ria_home"):
            resp = client.get("/api/ria/home")
        _assert_opaque_503(resp)


class TestRiaInvitesIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("list_ria_invites"):
            resp = client.get("/api/ria/invites")
        _assert_opaque_503(resp)


class TestRiaRequestBundlesIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("list_ria_request_bundles"):
            resp = client.get("/api/ria/request-bundles")
        _assert_opaque_503(resp)


class TestRiaPicksIAMLeak:
    def test_opaque_503(self, client):
        with _patch_not_ready("get_active_ria_pick_package"):
            resp = client.get("/api/ria/picks")
        _assert_opaque_503(resp)
