"""
Regression tests for portfolio route path/query-parameter length enforcement.

Attach point: api/routes/kai/portfolio.py

Bug: Five route handlers accepted ``user_id`` or ``run_id`` as bare ``str``
parameters with no upper-bound check (CWE-400: Uncontrolled Resource
Consumption).  FastAPI forwarded arbitrarily large strings to log statements,
error detail dicts, and downstream service calls.

Affected routes:
  GET  /portfolio/summary/{user_id}
  GET  /dashboard/profile-picks/{user_id}
  GET  /portfolio/import/run/active          (user_id query param)
  GET  /portfolio/import/run/{run_id}/stream (run_id path + user_id query)
  POST /portfolio/import/run/{run_id}/cancel (run_id path + user_id query)

Fix: add ``_USER_ID_MAX_LEN = 128`` and ``_RUN_ID_MAX_LEN = 128`` module
constants.  Path params use ``Annotated[str, Path(max_length=...)]`` via the
``UserId`` / ``RunId`` type aliases; query params use ``Query(...,
max_length=...)``.  FastAPI returns HTTP 422 for any value that exceeds the
limit.

Tests cover:
- Constants exist and are within reasonable bounds
- HTTP 422 for oversized user_id on GET /portfolio/summary/{user_id}
- HTTP 422 for oversized user_id on GET /dashboard/profile-picks/{user_id}
- HTTP 422 for oversized run_id on GET /portfolio/import/run/{run_id}/stream
- HTTP 422 for oversized run_id on POST /portfolio/import/run/{run_id}/cancel
- HTTP 422 for oversized user_id query param on GET /portfolio/import/run/active
- Valid-length values are NOT rejected with 422 by the length check
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Constant-level checks (no network required)
# ---------------------------------------------------------------------------
import api.routes.kai.portfolio as _portfolio_mod


def test_user_id_max_len_constant_exists():
    assert hasattr(_portfolio_mod, "_USER_ID_MAX_LEN"), (
        "_USER_ID_MAX_LEN constant missing from api/routes/kai/portfolio.py"
    )


def test_run_id_max_len_constant_exists():
    assert hasattr(_portfolio_mod, "_RUN_ID_MAX_LEN"), (
        "_RUN_ID_MAX_LEN constant missing from api/routes/kai/portfolio.py"
    )


def test_user_id_max_len_above_firebase_uid():
    """Must accommodate Firebase UIDs (28 chars)."""
    assert _portfolio_mod._USER_ID_MAX_LEN >= 28


def test_user_id_max_len_not_absurdly_large():
    assert _portfolio_mod._USER_ID_MAX_LEN <= 1024


def test_run_id_max_len_above_uuid4():
    """Must accommodate UUID4 run IDs (36 chars)."""
    assert _portfolio_mod._RUN_ID_MAX_LEN >= 36


def test_run_id_max_len_not_absurdly_large():
    assert _portfolio_mod._RUN_ID_MAX_LEN <= 1024


# ---------------------------------------------------------------------------
# HTTP-layer tests (TestClient with stubbed vault-owner auth)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from api.middleware import require_vault_owner_token
    from server import app

    def _stub_token():
        return {"user_id": "user_stub_abc", "scope": "vault.owner", "token": "tok"}

    with patch.dict(app.dependency_overrides, {require_vault_owner_token: _stub_token}):
        yield TestClient(app, raise_server_exceptions=False)


_UID_MAX = _portfolio_mod._USER_ID_MAX_LEN
_RID_MAX = _portfolio_mod._RUN_ID_MAX_LEN


def test_portfolio_summary_oversized_user_id_returns_422(client):
    """GET /portfolio/summary/{user_id} must return 422 for oversized user_id."""
    oversized = "u" * (_UID_MAX + 1)
    resp = client.get(f"/portfolio/summary/{oversized}")
    assert resp.status_code == 422, (
        f"Expected 422 for oversized user_id on /portfolio/summary, got {resp.status_code}"
    )


def test_dashboard_picks_oversized_user_id_returns_422(client):
    """GET /dashboard/profile-picks/{user_id} must return 422 for oversized user_id."""
    oversized = "u" * (_UID_MAX + 1)
    resp = client.get(f"/dashboard/profile-picks/{oversized}")
    assert resp.status_code == 422, (
        f"Expected 422 for oversized user_id on /dashboard/profile-picks, got {resp.status_code}"
    )


def test_stream_run_oversized_run_id_returns_422(client):
    """GET /portfolio/import/run/{run_id}/stream must return 422 for oversized run_id."""
    oversized = "r" * (_RID_MAX + 1)
    resp = client.get(
        f"/portfolio/import/run/{oversized}/stream",
        params={"user_id": "user_stub_abc"},
    )
    assert resp.status_code == 422, (
        f"Expected 422 for oversized run_id on /stream, got {resp.status_code}"
    )


def test_cancel_run_oversized_run_id_returns_422(client):
    """POST /portfolio/import/run/{run_id}/cancel must return 422 for oversized run_id."""
    oversized = "r" * (_RID_MAX + 1)
    resp = client.post(
        f"/portfolio/import/run/{oversized}/cancel",
        params={"user_id": "user_stub_abc"},
    )
    assert resp.status_code == 422, (
        f"Expected 422 for oversized run_id on /cancel, got {resp.status_code}"
    )


def test_active_run_oversized_user_id_query_returns_422(client):
    """GET /portfolio/import/run/active must return 422 for oversized user_id query param."""
    oversized = "u" * (_UID_MAX + 1)
    resp = client.get("/portfolio/import/run/active", params={"user_id": oversized})
    assert resp.status_code == 422, (
        f"Expected 422 for oversized user_id on /run/active, got {resp.status_code}"
    )


def test_portfolio_summary_valid_user_id_not_rejected(client):
    """A Firebase-UID-length user_id must not be rejected by the length check."""
    valid_uid = "user_stub_abc"
    resp = client.get(f"/portfolio/summary/{valid_uid}")
    assert resp.status_code != 422, (
        f"Valid-length user_id was incorrectly rejected with 422: {resp.json()}"
    )
