"""
Tests that ConsentApprovalPayload silently drops unknown extra fields.

Canonical attach point:
    api.routes.consent.ConsentApprovalPayload (consumed by approve_consent)
    -> POST /api/consent/pending/approve
"""

from __future__ import annotations

from api.routes.consent import ConsentApprovalPayload


class TestConsentApprovalExtraIgnored:
    """Verifies that extra fields are silently dropped instead of being stored."""

    def test_extra_fields_not_in_model_fields_set(self):
        payload = ConsentApprovalPayload(
            userId="user_abc",
            requestId="req_001",
            unknown_field="should_be_dropped",
            another_extra=12345,
        )

        assert "unknown_field" not in payload.model_fields_set
        assert "another_extra" not in payload.model_fields_set

    def test_valid_fields_are_preserved(self):
        payload = ConsentApprovalPayload(
            userId="user_abc",
            requestId="req_001",
            version=2,
        )

        assert payload.userId == "user_abc"
        assert payload.requestId == "req_001"
        assert payload.version == 2

    def test_extra_fields_absent_from_model_dump(self):
        payload = ConsentApprovalPayload(
            userId="user_abc",
            requestId="req_001",
            injected_key="injected_value",
        )

        dumped = payload.model_dump()
        assert "injected_key" not in dumped

    def test_model_accepts_minimal_valid_payload(self):
        payload = ConsentApprovalPayload(
            userId="user_abc",
            requestId="req_001",
        )

        assert payload.userId == "user_abc"
        assert payload.requestId == "req_001"
