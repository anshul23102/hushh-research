# tests/test_kai_pagination_dos.py
"""
CWE-400: Unbounded offset/page parameters on Kai pagination endpoints.

Before this fix:
  GET /api/kai/decisions/{user_id}?offset=<N> had no upper bound.
  The route computed limit=limit+offset and passed it directly as the
  SQL LIMIT value, so offset=10_000_000 forced the DB to return 10M rows.

  GET /api/kai/gmail/{user_id}/receipts?page=<N> had no upper bound.
  A large page value computes a proportionally large SQL OFFSET.

After this fix:
  offset is capped at 10_000 (FastAPI returns 422 for larger values).
  page  is capped at 1_000.
  limit gets a lower bound of 1 so zero cannot be passed.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.middleware as mw


# ---------------------------------------------------------------------------
# Decisions route
# ---------------------------------------------------------------------------


def _make_decisions_client():
    from api.routes.kai.decisions import router

    app = FastAPI()
    app.include_router(router, prefix="/api/kai")
    app.dependency_overrides[mw.require_vault_owner_token] = lambda: {"user_id": "stub-uid"}
    return TestClient(app, raise_server_exceptions=False)


class TestDecisionsPaginationBounds:
    def test_offset_over_limit_rejected(self):
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid?offset=10001")
        assert resp.status_code == 422

    def test_offset_at_limit_accepted(self):
        """offset=10_000 is within bounds; validation must not reject it."""
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid?offset=10000")
        # 422 would mean the bound itself is wrong; any other code is fine.
        assert resp.status_code != 422

    def test_limit_zero_rejected(self):
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid?limit=0")
        assert resp.status_code == 422

    def test_limit_over_100_rejected(self):
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid?limit=101")
        assert resp.status_code == 422

    def test_defaults_accepted(self):
        """Default parameters must pass validation (422 would be a regression)."""
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid")
        assert resp.status_code != 422

    def test_valid_pagination_accepted(self):
        client = _make_decisions_client()
        resp = client.get("/api/kai/decisions/stub-uid?limit=20&offset=100")
        assert resp.status_code != 422


# ---------------------------------------------------------------------------
# Gmail receipts route
# ---------------------------------------------------------------------------


def _make_gmail_client():
    from api.routes.kai.gmail import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[mw.require_firebase_auth] = lambda: "stub-uid"
    app.dependency_overrides[mw.require_vault_owner_token] = lambda: {"user_id": "stub-uid"}
    return TestClient(app, raise_server_exceptions=False)


class TestGmailReceiptsPaginationBounds:
    def test_page_over_limit_rejected(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts/stub-uid?page=1001")
        assert resp.status_code == 422

    def test_page_at_limit_accepted(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts/stub-uid?page=1000")
        assert resp.status_code != 422

    def test_page_zero_rejected(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts/stub-uid?page=0")
        assert resp.status_code == 422

    def test_per_page_over_100_rejected(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts/stub-uid?per_page=101")
        assert resp.status_code == 422

    def test_defaults_accepted(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts/stub-uid")
        assert resp.status_code != 422
