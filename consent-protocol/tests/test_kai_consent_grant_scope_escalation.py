"""Test that Kai consent grant endpoint blocks privileged scope self-grant."""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from hushh_mcp.consent.token import issue_token
from hushh_mcp.constants import ConsentScope

client = TestClient(app)


@pytest.mark.parametrize("blocked_scope", [
    "vault.owner",
    "agent.nav.revoke",
    "pkm.write",
])
def test_blocked_scopes_rejected_on_grant(blocked_scope):
    """Verify that privileged scopes are rejected by /consent/grant endpoint."""
    # Attempt to request a blocked scope
    response = client.post(
        "/consent/grant",
        json={
            "user_id": "test_user_123",
            "scopes": [blocked_scope],
        },
    )

    # Should return 403 Forbidden, not 200 with a token
    assert response.status_code == 403
    detail = response.json().get("detail", "")
    assert "not available" in detail.lower()


def test_allowed_scopes_still_grant():
    """Verify that allowed scopes (attr.financial.*, agent.kai.analyze) still work."""
    # Request an allowed scope
    response = client.post(
        "/consent/grant",
        json={
            "user_id": "test_user_456",
            "scopes": ["attr.financial.*", "agent.kai.analyze"],
        },
    )

    # Should succeed and return tokens
    assert response.status_code == 200
    data = response.json()
    assert data.get("consent_id") is not None
    assert len(data.get("tokens", {})) > 0


def test_mixed_blocked_and_allowed_scopes():
    """Verify that even one blocked scope in a mixed list is rejected."""
    response = client.post(
        "/consent/grant",
        json={
            "user_id": "test_user_789",
            "scopes": ["attr.financial.*", "vault.owner"],  # One blocked
        },
    )

    # Should fail because vault.owner is in the list
    assert response.status_code == 403
