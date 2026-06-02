"""
Regression tests for CWE-209 fixes in api/routes/crd_scraper.py and
api/routes/pkm_routes_shared.py.

CWE-209 -- Information Exposure Through an Error Message:
  ValueError and CrdScrapeProxyError detail strings were forwarded verbatim
  to HTTP responses. This suite verifies that error responses now return
  opaque messages and do not expose internal exception text.

Endpoints under test:
  POST /api/ria/crd-scrape-jobs     (via _call_provider, ValueError path)
  POST /api/pkm/upgrade/runs/{run_id}/complete

Attach point: api/routes/crd_scraper.py, api/routes/pkm_routes_shared.py
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes import crd_scraper as crd_mod
from api.routes import pkm_routes_shared as pkm_mod
from hushh_mcp.services.crd_scrape_proxy_service import CrdScrapeProxyError

_INTERNAL_MSG = "internal:secret-uid-abc123-detail"
_UID = "test-uid-cwe209"
_VAULT_TOKEN = {"user_id": _UID, "token": "fake", "scope": "vault.owner"}  # noqa: S106


@pytest.fixture(scope="module")
def crd_client() -> TestClient:
    app = FastAPI()
    app.include_router(crd_mod.router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def pkm_client() -> TestClient:
    app = FastAPI()
    app.include_router(pkm_mod.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: _VAULT_TOKEN
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# CRD scraper -- ValueError must not leak internal detail
# ---------------------------------------------------------------------------


def test_crd_valueerror_detail_is_opaque(crd_client: TestClient) -> None:
    """ValueError in _call_provider must not be forwarded to the response body."""
    with patch(
        "api.routes.crd_scraper.CrdScrapeProxyService.create_job",
        side_effect=ValueError(_INTERNAL_MSG),
    ):
        resp = crd_client.post(
            "/api/ria/crd-scrape-jobs",
            json={"crdNumber": "1234567"},
        )

    assert resp.status_code == 422
    assert _INTERNAL_MSG not in resp.text, f"Internal detail leaked: {resp.text!r}"


def test_crd_proxy_error_5xx_detail_is_opaque(crd_client: TestClient) -> None:
    """CrdScrapeProxyError 5xx must return an opaque message, not str(exc)."""
    error = CrdScrapeProxyError(_INTERNAL_MSG, status_code=503)
    with patch(
        "api.routes.crd_scraper.CrdScrapeProxyService.create_job",
        side_effect=error,
    ):
        resp = crd_client.post(
            "/api/ria/crd-scrape-jobs",
            json={"crdNumber": "1234567"},
        )

    assert resp.status_code == 503
    assert _INTERNAL_MSG not in resp.text, f"Internal detail leaked: {resp.text!r}"


def test_crd_proxy_error_4xx_detail_is_opaque(crd_client: TestClient) -> None:
    """CrdScrapeProxyError 4xx must return an opaque message, not str(exc)."""
    error = CrdScrapeProxyError(_INTERNAL_MSG, status_code=404)
    with patch(
        "api.routes.crd_scraper.CrdScrapeProxyService.create_job",
        side_effect=error,
    ):
        resp = crd_client.post(
            "/api/ria/crd-scrape-jobs",
            json={"crdNumber": "1234567"},
        )

    assert resp.status_code == 404
    assert _INTERNAL_MSG not in resp.text, f"Internal detail leaked: {resp.text!r}"


# ---------------------------------------------------------------------------
# PKM upgrade complete -- ValueError must not leak
# ---------------------------------------------------------------------------


def test_pkm_upgrade_complete_valueerror_is_opaque(pkm_client: TestClient) -> None:
    """ValueError in complete_run must not be forwarded to the response."""
    with patch(
        "api.routes.pkm_routes_shared.get_pkm_upgrade_service",
    ) as mock_svc:
        mock_svc.return_value.complete_run = AsyncMock(
            side_effect=ValueError(_INTERNAL_MSG)
        )
        resp = pkm_client.post(
            "/api/pkm/upgrade/runs/run-001/complete",
            json={"user_id": _UID},
        )

    assert resp.status_code == 409
    assert _INTERNAL_MSG not in resp.text, f"Internal detail leaked: {resp.text!r}"
