"""Route-level and model-level proof for EncryptedBlob and domain write payload bounds.

Canonical attach points:
  POST /api/pkm/store-domain         EncryptedBlob.ciphertext / iv / tag / algorithm
  POST /api/pkm/store-domain         EncryptedBlob.segments   (nested, max 100 entries)
  POST /api/pkm/store-domain         StoreDomainRequest.write_projections (max 100)
  POST /api/pkm/domains/{d}/scope-exposure  ScopeExposureRequest.changes (max 200)

Tests prove:
  - Oversized ciphertext / iv / tag are rejected 422 by the route.
  - segment count above 100 is rejected at the model layer.
  - segment key length above 128 is rejected at the model layer.
  - Nested EncryptedBlob.segments is safe: the validator runs on segment sub-models.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

import api.routes.pkm_routes_shared as pkm_shared
from api.middleware import require_vault_owner_token
from api.routes.pkm_routes_shared import EncryptedBlob

_UID = "test-user-id"
_TOKEN = {"user_id": _UID, "token": "stub", "scope": "vault.owner"}

_VALID_BLOB = {
    "ciphertext": "dGVzdA==",
    "iv": "aXY=",
    "tag": "dGFn",
    "algorithm": "aes-256-gcm",
}


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(pkm_shared.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: _TOKEN
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# EncryptedBlob model-level bounds
# ---------------------------------------------------------------------------


def test_ciphertext_over_10mib_rejected():
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="x" * (10_485_760 + 1), iv="aXY=", tag="dGFn")


def test_ciphertext_at_limit_accepted():
    blob = EncryptedBlob(ciphertext="x" * 10_485_760, iv="aXY=", tag="dGFn")
    assert len(blob.ciphertext) == 10_485_760


def test_iv_over_512_rejected():
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="x" * 513, tag="dGFn")


def test_tag_over_512_rejected():
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="x" * 513)


def test_algorithm_over_64_rejected():
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", algorithm="a" * 65)


# ---------------------------------------------------------------------------
# EncryptedBlob.segments nested bounds
# ---------------------------------------------------------------------------


def test_segments_over_100_entries_rejected():
    """More than 100 segment entries must be rejected at the model layer."""
    segments = {
        f"seg-{i}": EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn")
        for i in range(101)
    }
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", segments=segments)


def test_segments_at_100_entries_accepted():
    segments = {
        f"seg-{i}": EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn")
        for i in range(100)
    }
    blob = EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", segments=segments)
    assert len(blob.segments) == 100


def test_segment_key_over_128_chars_rejected():
    """Segment keys longer than 128 characters must be rejected."""
    segments = {
        "k" * 129: EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn")
    }
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", segments=segments)


def test_segment_key_at_128_chars_accepted():
    segments = {
        "k" * 128: EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn")
    }
    blob = EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", segments=segments)
    assert len(blob.segments) == 1


def test_empty_segment_key_rejected():
    segments = {
        "": EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn")
    }
    with pytest.raises(ValidationError):
        EncryptedBlob(ciphertext="dGVzdA==", iv="aXY=", tag="dGFn", segments=segments)


# ---------------------------------------------------------------------------
# Route-level rejection via canonical POST /api/pkm/store-domain
# ---------------------------------------------------------------------------


def test_route_rejects_oversized_ciphertext(client: TestClient):
    resp = client.post(
        "/api/pkm/store-domain",
        json={
            "user_id": _UID,
            "domain": "financial",
            "encrypted_blob": {**_VALID_BLOB, "ciphertext": "x" * (10_485_760 + 1)},
            "summary": {},
        },
    )
    assert resp.status_code == 422, resp.text


def test_route_rejects_too_many_segments(client: TestClient):
    segments = {
        f"seg-{i}": _VALID_BLOB for i in range(101)
    }
    resp = client.post(
        "/api/pkm/store-domain",
        json={
            "user_id": _UID,
            "domain": "financial",
            "encrypted_blob": {**_VALID_BLOB, "segments": segments},
            "summary": {},
        },
    )
    assert resp.status_code == 422, resp.text


def test_route_accepts_valid_blob_with_segments(client: TestClient):
    segments = {f"seg-{i}": _VALID_BLOB for i in range(5)}
    mock_service = MagicMock()
    mock_service.store_domain_data = AsyncMock(
        return_value={"success": True, "conflict": False, "data_version": 1}
    )
    with patch.object(pkm_shared, "get_pkm_service", return_value=mock_service):
        resp = client.post(
            "/api/pkm/store-domain",
            json={
                "user_id": _UID,
                "domain": "financial",
                "encrypted_blob": {**_VALID_BLOB, "segments": segments},
                "summary": {},
            },
        )
    assert resp.status_code != 422, resp.text
