"""Hermetic tests: marketplace query-string length bounds.

GET /api/marketplace/rias and /api/marketplace/investors accept string
query params that are now bounded by max_length.  FastAPI validates these
before the handler fires and returns 422, so no DB or network needed.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import marketplace
from hushh_mcp.services.ria_iam_service import RIAIAMService


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(marketplace.router)
    return app


@pytest.fixture(scope="module")
def client():
    """Module-scoped client; stubs out IAM service so no DB is hit."""

    async def _empty_rias(self, **kwargs) -> list:  # noqa: ARG002
        return []

    async def _empty_investors(self, **kwargs) -> list:  # noqa: ARG002
        return []

    RIAIAMService.search_marketplace_rias = _empty_rias  # type: ignore[method-assign]
    RIAIAMService.search_marketplace_investors = _empty_investors  # type: ignore[method-assign]

    return TestClient(_build_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rias(client: TestClient, **params) -> object:
    return client.get(
        "/api/marketplace/rias", params={k: v for k, v in params.items() if v is not None}
    )


def _investors(client: TestClient, **params) -> object:
    return client.get(
        "/api/marketplace/investors", params={k: v for k, v in params.items() if v is not None}
    )


# ---------------------------------------------------------------------------
# GET /rias - query param (max_length=200)
# ---------------------------------------------------------------------------


class TestRiasQueryParam:
    def test_query_200_chars_accepted(self, client):
        assert _rias(client, query="a" * 200).status_code == 200

    def test_query_201_chars_rejected(self, client):
        assert _rias(client, query="a" * 201).status_code == 422

    def test_query_omitted_accepted(self, client):
        assert _rias(client).status_code == 200

    def test_query_normal_term_accepted(self, client):
        assert _rias(client, query="Smith Advisory").status_code == 200

    def test_query_very_long_rejected(self, client):
        assert _rias(client, query="x" * 500).status_code == 422


# ---------------------------------------------------------------------------
# GET /rias - firm param (max_length=200)
# ---------------------------------------------------------------------------


class TestRiasFirmParam:
    def test_firm_200_chars_accepted(self, client):
        assert _rias(client, firm="f" * 200).status_code == 200

    def test_firm_201_chars_rejected(self, client):
        assert _rias(client, firm="f" * 201).status_code == 422

    def test_firm_omitted_accepted(self, client):
        assert _rias(client).status_code == 200

    def test_firm_normal_value_accepted(self, client):
        assert _rias(client, firm="Vanguard").status_code == 200


# ---------------------------------------------------------------------------
# GET /rias - verification_status param (max_length=50)
# ---------------------------------------------------------------------------


class TestRiasVerificationStatusParam:
    def test_status_50_chars_accepted(self, client):
        assert _rias(client, verification_status="s" * 50).status_code == 200

    def test_status_51_chars_rejected(self, client):
        assert _rias(client, verification_status="s" * 51).status_code == 422

    def test_status_omitted_accepted(self, client):
        assert _rias(client).status_code == 200

    def test_status_verified_accepted(self, client):
        assert _rias(client, verification_status="verified").status_code == 200

    def test_status_very_long_rejected(self, client):
        assert _rias(client, verification_status="x" * 200).status_code == 422


# ---------------------------------------------------------------------------
# GET /rias - combined params
# ---------------------------------------------------------------------------


class TestRiasCombined:
    def test_all_at_limit_accepted(self, client):
        resp = _rias(client, query="a" * 200, firm="f" * 200, verification_status="s" * 50)
        assert resp.status_code == 200

    def test_query_over_limit_rejected(self, client):
        assert (
            _rias(client, query="a" * 201, firm="ok", verification_status="ok").status_code == 422
        )

    def test_firm_over_limit_rejected(self, client):
        assert _rias(client, query="ok", firm="f" * 201).status_code == 422

    def test_status_over_limit_rejected(self, client):
        assert _rias(client, verification_status="s" * 51).status_code == 422


# ---------------------------------------------------------------------------
# GET /investors - query param (max_length=200)
# ---------------------------------------------------------------------------


class TestInvestorsQueryParam:
    def test_query_200_chars_accepted(self, client):
        assert _investors(client, query="a" * 200).status_code == 200

    def test_query_201_chars_rejected(self, client):
        assert _investors(client, query="a" * 201).status_code == 422

    def test_query_omitted_accepted(self, client):
        assert _investors(client).status_code == 200

    def test_query_normal_term_accepted(self, client):
        assert _investors(client, query="John Doe").status_code == 200

    def test_query_very_long_rejected(self, client):
        assert _investors(client, query="y" * 500).status_code == 422
