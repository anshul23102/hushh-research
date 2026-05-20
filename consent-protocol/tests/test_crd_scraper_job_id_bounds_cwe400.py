"""Regression tests - CWE-400 in api/routes/crd_scraper.py job ID path params.

GET /api/ria/crd-scrape-jobs/{job_id} and
GET /api/ria/financial-verification-jobs/{job_id} previously accepted an
unbounded string path parameter. An attacker could send a megabyte-long job
ID forcing string materialisation and logging in every middleware layer.

These tests verify that:
  - a normally-sized job ID (UUID-like) is accepted (422 only from downstream)
  - a job ID exceeding max_length=128 is rejected with HTTP 422 before any
    service call is made

Attach point: api/routes/crd_scraper.py::get_crd_scrape_job,
              api/routes/crd_scraper.py::get_financial_verification_job
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False)

_VALID_JOB_ID = "a" * 36
_OVERLONG_JOB_ID = "x" * 129  # exceeds max_length=128


class TestCrdScrapeJobIdBounds:
    """GET /api/ria/crd-scrape-jobs/{job_id} path param bounds."""

    def test_valid_job_id_not_rejected_by_bounds(self) -> None:
        """A normally-sized job ID must not produce a 422 from path validation."""
        resp = client.get(f"/api/ria/crd-scrape-jobs/{_VALID_JOB_ID}")
        # 422 would mean validation failure; any other status means bounds passed
        assert resp.status_code != 422, (
            f"Valid job_id was rejected by path validation: {resp.text}"
        )

    def test_overlong_job_id_rejected_with_422(self) -> None:
        """A job ID exceeding 128 chars must be rejected with 422."""
        resp = client.get(f"/api/ria/crd-scrape-jobs/{_OVERLONG_JOB_ID}")
        assert resp.status_code == 422, (
            f"Overlong job_id was not rejected (got {resp.status_code})"
        )

    def test_empty_job_id_path_not_routed(self) -> None:
        """An empty job_id segment should not match the path (404 or 405)."""
        resp = client.get("/api/ria/crd-scrape-jobs/")
        assert resp.status_code in {404, 405, 307, 308}


class TestFinancialVerificationJobIdBounds:
    """GET /api/ria/financial-verification-jobs/{job_id} path param bounds."""

    def test_valid_job_id_not_rejected_by_bounds(self) -> None:
        """A normally-sized job ID must not produce a 422 from path validation."""
        resp = client.get(f"/api/ria/financial-verification-jobs/{_VALID_JOB_ID}")
        assert resp.status_code != 422, (
            f"Valid job_id was rejected by path validation: {resp.text}"
        )

    def test_overlong_job_id_rejected_with_422(self) -> None:
        """A job ID exceeding 128 chars must be rejected with 422."""
        resp = client.get(f"/api/ria/financial-verification-jobs/{_OVERLONG_JOB_ID}")
        assert resp.status_code == 422, (
            f"Overlong job_id was not rejected (got {resp.status_code})"
        )
