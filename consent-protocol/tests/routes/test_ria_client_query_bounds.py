"""Hermetic tests: RIA /clients query-string length bounds.

FastAPI validates Query(max_length=...) and returns 422 before the handler
is reached, so no real DB or network is needed.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth
from api.routes import ria
from hushh_mcp.services.ria_iam_service import RIAIAMService


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(ria.router)
    # Bypass Firebase auth - tests focus on query-param validation only.
    app.dependency_overrides[require_firebase_auth] = lambda: "test_ria_uid"
    return app


@pytest.fixture(scope="module")
def client(monkeypatch_session=None):
    """Module-scoped test client; stubs out RIA verification and client listing."""
    app = _build_app()

    async def _noop_verify(self, uid: str) -> None:  # noqa: ARG002
        return None

    async def _empty_clients(self, uid: str, **kwargs) -> dict:  # noqa: ARG002
        return {"items": [], "total": 0}

    # Patch at class level so they apply regardless of how _build_app imports.
    RIAIAMService.require_ria_verified = _noop_verify  # type: ignore[method-assign]
    RIAIAMService.list_ria_clients = _empty_clients  # type: ignore[method-assign]

    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(client: TestClient, **params) -> object:
    return client.get("/api/ria/clients", params={k: v for k, v in params.items() if v is not None})


# ---------------------------------------------------------------------------
# q param - max_length=200
# ---------------------------------------------------------------------------


class TestQParam:
    def test_q_exactly_200_chars_accepted(self, client):
        resp = _get(client, q="a" * 200)
        assert resp.status_code == 200

    def test_q_201_chars_rejected(self, client):
        resp = _get(client, q="a" * 201)
        assert resp.status_code == 422

    def test_q_empty_string_accepted(self, client):
        resp = _get(client, q="")
        assert resp.status_code == 200

    def test_q_omitted_accepted(self, client):
        resp = _get(client)
        assert resp.status_code == 200

    def test_q_normal_search_term_accepted(self, client):
        resp = _get(client, q="John Doe")
        assert resp.status_code == 200

    def test_q_very_long_string_rejected(self, client):
        resp = _get(client, q="x" * 500)
        assert resp.status_code == 422

    def test_q_422_body_mentions_q(self, client):
        resp = _get(client, q="z" * 201)
        assert resp.status_code == 422
        body = resp.json()
        detail = str(body.get("detail", ""))
        assert (
            "q" in detail.lower()
            or "string_too_long" in detail.lower()
            or "max_length" in detail.lower()
        )


# ---------------------------------------------------------------------------
# status param - max_length=50
# ---------------------------------------------------------------------------


class TestStatusParam:
    def test_status_exactly_50_chars_accepted(self, client):
        resp = _get(client, status="s" * 50)
        assert resp.status_code == 200

    def test_status_51_chars_rejected(self, client):
        resp = _get(client, status="s" * 51)
        assert resp.status_code == 422

    def test_status_omitted_accepted(self, client):
        resp = _get(client)
        assert resp.status_code == 200

    def test_status_active_accepted(self, client):
        resp = _get(client, status="active")
        assert resp.status_code == 200

    def test_status_pending_accepted(self, client):
        resp = _get(client, status="pending")
        assert resp.status_code == 200

    def test_status_very_long_rejected(self, client):
        resp = _get(client, status="x" * 200)
        assert resp.status_code == 422

    def test_status_422_body_mentions_status(self, client):
        resp = _get(client, status="y" * 51)
        assert resp.status_code == 422
        body = resp.json()
        detail = str(body.get("detail", ""))
        assert "status" in detail.lower() or "string_too_long" in detail.lower()


# ---------------------------------------------------------------------------
# Combined params
# ---------------------------------------------------------------------------


class TestCombinedParams:
    def test_both_at_limit_accepted(self, client):
        resp = _get(client, q="a" * 200, status="s" * 50)
        assert resp.status_code == 200

    def test_q_over_limit_status_fine_rejected(self, client):
        resp = _get(client, q="a" * 201, status="active")
        assert resp.status_code == 422

    def test_q_fine_status_over_limit_rejected(self, client):
        resp = _get(client, q="hello", status="s" * 51)
        assert resp.status_code == 422

    def test_both_over_limit_rejected(self, client):
        resp = _get(client, q="a" * 201, status="s" * 51)
        assert resp.status_code == 422

    def test_with_pagination_params_accepted(self, client):
        resp = _get(client, q="Smith", status="active", page=2, limit=25)
        assert resp.status_code == 200
