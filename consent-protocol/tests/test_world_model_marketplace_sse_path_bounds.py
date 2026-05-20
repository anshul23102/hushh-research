# tests/test_world_model_marketplace_sse_path_bounds.py
"""
Regression tests for CWE-400 path/query-param bounds in:
  api/routes/world_model.py  (GET /api/world-model/domains|metadata|scopes|data|domain-data)
  api/routes/marketplace.py  (GET /api/marketplace/ria/{ria_id})
  api/routes/sse.py          (GET /api/consent/events/{user_id})

Each test drives the FastAPI app via TestClient so the Annotated Path() and Query()
constraints are validated by FastAPI/Pydantic before any service code runs.
Auth dependencies are stubbed via app.dependency_overrides.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

import api.routes.marketplace as mp_mod
import api.routes.sse as sse_mod
import api.routes.world_model as wm_mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_USER_ID = "firebase_uid_stub_28chars_abc"   # 30 chars, well within 128
_LONG_USER_ID = "u" * 129                          # exceeds _USER_ID_MAX_LEN=128
_LONG_DOMAIN = "d" * 129                           # exceeds _DOMAIN_KEY_MAX_LEN=128
_GOOD_DOMAIN = "financial"
_LONG_RIA_ID = "r" * 129                           # exceeds _RIA_ID_MAX_LEN=128
_GOOD_RIA_ID = "ria_12345678"


def _stub_vault_token():
    return {"user_id": _GOOD_USER_ID}


def _stub_firebase_bearer(_auth):
    return _GOOD_USER_ID


@contextmanager
def _world_model_client():
    from main import app

    from api.middleware import require_vault_owner_token
    with patch.dict(app.dependency_overrides, {require_vault_owner_token: _stub_vault_token}):
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client


@contextmanager
def _sse_client():
    from main import app

    import api.utils.firebase_auth as fb_mod
    with patch.object(fb_mod, "verify_firebase_bearer", side_effect=_stub_firebase_bearer):
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client


@contextmanager
def _mp_client():
    from main import app
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


# ---------------------------------------------------------------------------
# Constant sanity checks
# ---------------------------------------------------------------------------

def test_world_model_user_id_constant_is_reasonable():
    assert wm_mod._USER_ID_MAX_LEN == 128


def test_world_model_domain_key_constant_is_reasonable():
    assert wm_mod._DOMAIN_KEY_MAX_LEN == 128


def test_world_model_segment_ids_count_constant():
    assert wm_mod._SEGMENT_IDS_MAX_COUNT == 50


def test_marketplace_ria_id_constant_is_reasonable():
    assert mp_mod._RIA_ID_MAX_LEN == 128


def test_sse_user_id_constant_is_reasonable():
    assert sse_mod._USER_ID_MAX_LEN == 128


# ---------------------------------------------------------------------------
# world_model.py — oversized user_id path param (5 handlers)
# ---------------------------------------------------------------------------

def test_world_model_domains_rejects_oversized_user_id():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/domains/{_LONG_USER_ID}")
        assert r.status_code == 422, r.text


def test_world_model_metadata_rejects_oversized_user_id():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/metadata/{_LONG_USER_ID}")
        assert r.status_code == 422, r.text


def test_world_model_scopes_rejects_oversized_user_id():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/scopes/{_LONG_USER_ID}")
        assert r.status_code == 422, r.text


def test_world_model_data_rejects_oversized_user_id():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/data/{_LONG_USER_ID}")
        assert r.status_code == 422, r.text


def test_world_model_domain_data_rejects_oversized_user_id():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/domain-data/{_LONG_USER_ID}/{_GOOD_DOMAIN}")
        assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# world_model.py — oversized domain path param
# ---------------------------------------------------------------------------

def test_world_model_domain_data_rejects_oversized_domain():
    with _world_model_client() as client:
        r = client.get(f"/api/world-model/domain-data/{_GOOD_USER_ID}/{_LONG_DOMAIN}")
        assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# world_model.py — oversized segment_ids query list
# ---------------------------------------------------------------------------

def test_world_model_domain_data_rejects_too_many_segment_ids():
    with _world_model_client() as client:
        params = [("segment_ids", f"seg_{i}") for i in range(51)]  # > max_count=50
        r = client.get(
            f"/api/world-model/domain-data/{_GOOD_USER_ID}/{_GOOD_DOMAIN}",
            params=params,
        )
        assert r.status_code == 422, r.text


def test_world_model_domain_data_rejects_oversized_segment_id_item():
    with _world_model_client() as client:
        long_seg = "x" * 257  # > _SEGMENT_ID_MAX_LEN=256
        r = client.get(
            f"/api/world-model/domain-data/{_GOOD_USER_ID}/{_GOOD_DOMAIN}",
            params={"segment_ids": long_seg},
        )
        assert r.status_code == 422, r.text


def test_world_model_domain_data_accepts_valid_segment_ids():
    with _world_model_client() as client:
        params = [("segment_ids", f"seg_{i}") for i in range(5)]  # well within cap
        r = client.get(
            f"/api/world-model/domain-data/{_GOOD_USER_ID}/{_GOOD_DOMAIN}",
            params=params,
        )
        # 422 would mean our guard is too strict; 4xx/5xx from service is acceptable
        assert r.status_code != 422, r.text


# ---------------------------------------------------------------------------
# marketplace.py — ria_id path param (unauthenticated public endpoint)
# ---------------------------------------------------------------------------

def test_marketplace_ria_rejects_oversized_ria_id():
    with _mp_client() as client:
        r = client.get(f"/api/marketplace/ria/{_LONG_RIA_ID}")
        assert r.status_code == 422, r.text


def test_marketplace_ria_accepts_valid_ria_id():
    with _mp_client() as client:
        r = client.get(f"/api/marketplace/ria/{_GOOD_RIA_ID}")
        # Any non-422 response means the guard is not over-rejecting valid input
        assert r.status_code != 422, r.text


# ---------------------------------------------------------------------------
# sse.py — user_id path param
# ---------------------------------------------------------------------------

def test_sse_consent_events_rejects_oversized_user_id():
    with _sse_client() as client:
        r = client.get(
            f"/api/consent/events/{_LONG_USER_ID}",
            headers={"Authorization": f"Bearer token_{_GOOD_USER_ID}"},
        )
        assert r.status_code == 422, r.text


def test_sse_consent_events_accepts_valid_user_id():
    with _sse_client() as client:
        # SSE may return 410 (disabled in test env) or stream; 422 would be wrong
        r = client.get(
            f"/api/consent/events/{_GOOD_USER_ID}",
            headers={"Authorization": f"Bearer token_{_GOOD_USER_ID}"},
        )
        assert r.status_code != 422, r.text
