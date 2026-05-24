"""
Tests that FinancialVerificationJobRequest rejects unknown extra fields.

Canonical attach point:
    api.routes.crd_scraper.create_financial_verification_job
    -> POST /api/ria/financial-verification-jobs
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes.crd_scraper as crd_module
from api.routes.crd_scraper import router
from hushh_mcp.services.crd_scrape_proxy_service import CrdScrapeProviderResponse


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


class TestCrdScraperRequestValidation:
    """Verifies that the typed model rejects unknown fields and accepts valid ones."""

    def test_unknown_extra_field_returns_422(self):
        client = TestClient(_build_app(), raise_server_exceptions=False)

        resp = client.post(
            "/api/ria/financial-verification-jobs",
            json={"crdNumber": "12345", "unknown_extra_key": "should_be_rejected"},
        )

        assert resp.status_code == 422

    def test_valid_request_is_forwarded(self, monkeypatch):
        mock_service = AsyncMock()
        mock_service.create_financial_verification_job = AsyncMock(
            return_value=CrdScrapeProviderResponse(
                status_code=202,
                payload={"jobId": "job_001", "status": "queued"},
            )
        )

        monkeypatch.setattr(
            crd_module, "get_crd_scrape_proxy_service", lambda: mock_service
        )

        client = TestClient(_build_app(), raise_server_exceptions=True)
        resp = client.post(
            "/api/ria/financial-verification-jobs",
            json={"crdNumber": "12345"},
        )

        assert resp.status_code != 422
        mock_service.create_financial_verification_job.assert_called_once()
        call_kwargs = mock_service.create_financial_verification_job.call_args.kwargs
        assert call_kwargs["payload"]["crdNumber"] == "12345"
        assert "unknown_extra_key" not in call_kwargs["payload"]

    def test_missing_crd_number_returns_422(self):
        client = TestClient(_build_app(), raise_server_exceptions=False)

        resp = client.post(
            "/api/ria/financial-verification-jobs",
            json={"userId": "user_abc"},
        )

        assert resp.status_code == 422
