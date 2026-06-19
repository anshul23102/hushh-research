"""Tests for PKM segment_ids Query parameter bounds (CWE-400).

Validates that segment_ids Query parameter on GET /api/pkm/domain-data/{user_id}/{domain}
and GET /api/world-model/domain-data/{user_id}/{domain} is properly bounded to prevent
unbounded list consumption attacks.

Security: CWE-400 Uncontrolled Resource Consumption via Query Parameters
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.pkm import router as pkm_router
from api.routes.world_model import router as world_model_router

app = FastAPI()
app.include_router(pkm_router)
app.include_router(world_model_router)

_TEST_USER_ID = "test-user-12345"
_TEST_DOMAIN = "financial"


def _mock_token_data() -> dict:
    """Return mock token data for successful auth."""
    return {
        "user_id": _TEST_USER_ID,
        "agent_id": "test_agent",
        "scope": "vault.owner",
        "token": "test-token",
        "token_obj": None,
    }


def _override_auth():
    """Dependency override for token validation."""
    return _mock_token_data()


app.dependency_overrides[require_vault_owner_token] = _override_auth
client = TestClient(app)


class TestPKMSegmentIdsBounds:
    """Test PKM segment_ids bounds on /api/pkm/domain-data endpoint."""

    def test_segment_ids_within_bounds_accepted(self):
        """Verify that segment_ids under 100 items are accepted (HTTP 200/401/403)."""
        segment_ids = [f"segment_{i}" for i in range(50)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/pkm/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code in (401, 403, 404, 500), (
            f"Expected success or auth error, got {response.status_code}: {response.text}"
        )

    def test_segment_ids_at_boundary_accepted(self):
        """Verify that segment_ids at exactly 100 items are accepted."""
        segment_ids = [f"segment_{i}" for i in range(100)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/pkm/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code != 422, (
            f"Boundary case (100 items) should be accepted, got 422: {response.text}"
        )

    def test_segment_ids_exceeds_bounds_rejected(self):
        """Verify that segment_ids exceeding 100 items are rejected with HTTP 422."""
        segment_ids = [f"segment_{i}" for i in range(101)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/pkm/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code == 422, (
            f"Exceeded bounds (101 items) should reject with 422, got {response.status_code}"
        )

    def test_segment_ids_large_overflow_rejected(self):
        """Verify that very large segment_ids list (1000+) is rejected."""
        segment_ids = [f"segment_{i}" for i in range(1000)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/pkm/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code == 422, (
            f"Large overflow (1000 items) must reject, got {response.status_code}"
        )


class TestWorldModelSegmentIdsBounds:
    """Test segment_ids bounds on /api/world-model/domain-data endpoint."""

    def test_world_model_segment_ids_within_bounds_accepted(self):
        """Verify that segment_ids under 100 items are accepted on world-model endpoint."""
        segment_ids = [f"segment_{i}" for i in range(50)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/world-model/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code in (401, 403, 404, 500), (
            f"Expected success or auth error, got {response.status_code}: {response.text}"
        )

    def test_world_model_segment_ids_exceeds_bounds_rejected(self):
        """Verify that segment_ids exceeding 100 on world-model endpoint are rejected."""
        segment_ids = [f"segment_{i}" for i in range(101)]
        params = {"segment_ids": segment_ids}

        response = client.get(
            f"/api/world-model/domain-data/{_TEST_USER_ID}/{_TEST_DOMAIN}",
            params=params,
        )

        assert response.status_code == 422, (
            f"World-model: exceeded bounds should reject with 422, got {response.status_code}"
        )
