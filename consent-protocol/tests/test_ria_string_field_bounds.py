# tests/test_ria_string_field_bounds.py
"""
Input bounds: unbounded string fields in RIA request models reject oversized input.

All required string fields in these models previously had only min_length,
allowing arbitrarily long payloads. Critical case: csv_content had no upper
limit, enabling memory-exhaustion DoS via enormous CSV uploads.

Models under test:
  RIAOnboardingSubmitRequest: display_name max 200
  RIAOnboardingVerifyNameRequest: query max 200, crd_number max 20
  RIAOnboardingVerifyLicenseRequest: license_number max 50
  RIAConsentRequestCreate: subject_user_id max 128, scope_template_id max 128
  RIAConsentBundleCreate: subject_user_id max 128, scope_template_id max 128
  RIAPicksParseRequest: csv_content max 5_000_000 (5 MB)
  RIAInviteCreateRequest: scope_template_id max 128
  RIAMarketplaceDiscoverabilityRequest: headline max 200, strategy_summary max 2000
  RIAInviteTarget: email max 320, display_name max 200
"""

import pytest
from pydantic import ValidationError

from api.routes.ria import (
    RIAConsentBundleCreate,
    RIAConsentRequestCreate,
    RIAInviteCreateRequest,
    RIAInviteTarget,
    RIAMarketplaceDiscoverabilityRequest,
    RIAOnboardingSubmitRequest,
    RIAOnboardingVerifyLicenseRequest,
    RIAOnboardingVerifyNameRequest,
    RIAPicksParseRequest,
    RIAPicksSyncRequest,
)

# RIAOnboardingSubmitRequest

class TestOnboardingSubmitBounds:
    def test_display_name_at_max_accepted(self):
        m = RIAOnboardingSubmitRequest(display_name="A" * 200)
        assert m.display_name == "A" * 200

    def test_display_name_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingSubmitRequest(display_name="A" * 201)

    def test_bio_at_max_accepted(self):
        m = RIAOnboardingSubmitRequest(display_name="X", bio="B" * 5000)
        assert len(m.bio) == 5000

    def test_bio_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingSubmitRequest(display_name="X", bio="B" * 5001)

    def test_currency_over_3_chars_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingSubmitRequest(display_name="X", min_engagement_currency="USDX")

    def test_individual_crd_over_20_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingSubmitRequest(display_name="X", individual_crd="1" * 21)


# RIAOnboardingVerifyNameRequest

class TestVerifyNameBounds:
    def test_query_at_max_accepted(self):
        m = RIAOnboardingVerifyNameRequest(query="A" * 200)
        assert len(m.query) == 200

    def test_query_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingVerifyNameRequest(query="A" * 201)

    def test_crd_number_over_20_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingVerifyNameRequest(query="Jane Smith", crd_number="1" * 21)


# RIAOnboardingVerifyLicenseRequest

class TestVerifyLicenseBounds:
    def test_license_number_at_max_accepted(self):
        m = RIAOnboardingVerifyLicenseRequest(license_number="A" * 50)
        assert len(m.license_number) == 50

    def test_license_number_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAOnboardingVerifyLicenseRequest(license_number="A" * 51)


# RIAConsentRequestCreate

class TestConsentRequestBounds:
    def test_subject_user_id_at_max_accepted(self):
        m = RIAConsentRequestCreate(subject_user_id="u" * 128, scope_template_id="scope")
        assert len(m.subject_user_id) == 128

    def test_subject_user_id_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAConsentRequestCreate(subject_user_id="u" * 129, scope_template_id="scope")

    def test_scope_template_id_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAConsentRequestCreate(subject_user_id="uid", scope_template_id="s" * 129)

    def test_reason_over_1000_rejected(self):
        with pytest.raises(ValidationError):
            RIAConsentRequestCreate(
                subject_user_id="uid",
                scope_template_id="scope",
                reason="R" * 1001,
            )


# RIAConsentBundleCreate

class TestConsentBundleBounds:
    def test_subject_user_id_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAConsentBundleCreate(subject_user_id="u" * 129, scope_template_id="scope")

    def test_scope_template_id_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAConsentBundleCreate(subject_user_id="uid", scope_template_id="s" * 129)


# RIAPicksParseRequest (critical, previously unbounded csv_content)

class TestPicksParseBounds:
    def test_csv_at_max_accepted(self):
        m = RIAPicksParseRequest(csv_content="x" * 5_000_000)
        assert len(m.csv_content) == 5_000_000

    def test_csv_over_5mb_rejected(self):
        with pytest.raises(ValidationError):
            RIAPicksParseRequest(csv_content="x" * 5_000_001)

    def test_source_filename_over_255_rejected(self):
        with pytest.raises(ValidationError):
            RIAPicksParseRequest(csv_content="a,b", source_filename="f" * 256)

    def test_package_note_over_1000_rejected(self):
        with pytest.raises(ValidationError):
            RIAPicksParseRequest(csv_content="a,b", package_note="n" * 1001)


# RIAPicksSyncRequest

class TestPicksSyncBounds:
    def test_label_over_200_rejected(self):
        with pytest.raises(ValidationError):
            RIAPicksSyncRequest(label="L" * 201)

    def test_package_note_over_1000_rejected(self):
        with pytest.raises(ValidationError):
            RIAPicksSyncRequest(package_note="N" * 1001)


# RIAInviteTarget

class TestInviteTargetBounds:
    def test_email_over_320_rejected(self):
        with pytest.raises(ValidationError):
            RIAInviteTarget(email="e" * 321)

    def test_display_name_over_200_rejected(self):
        with pytest.raises(ValidationError):
            RIAInviteTarget(display_name="N" * 201)

    def test_investor_user_id_over_128_rejected(self):
        with pytest.raises(ValidationError):
            RIAInviteTarget(investor_user_id="u" * 129)


# RIAInviteCreateRequest

class TestInviteCreateBounds:
    def test_scope_template_id_over_max_rejected(self):
        with pytest.raises(ValidationError):
            RIAInviteCreateRequest(scope_template_id="s" * 129)

    def test_reason_over_1000_rejected(self):
        with pytest.raises(ValidationError):
            RIAInviteCreateRequest(scope_template_id="scope", reason="R" * 1001)


# RIAMarketplaceDiscoverabilityRequest

class TestMarketplaceDiscoverabilityBounds:
    def test_headline_over_200_rejected(self):
        with pytest.raises(ValidationError):
            RIAMarketplaceDiscoverabilityRequest(enabled=True, headline="H" * 201)

    def test_strategy_summary_over_2000_rejected(self):
        with pytest.raises(ValidationError):
            RIAMarketplaceDiscoverabilityRequest(enabled=True, strategy_summary="S" * 2001)

    def test_valid_payload_accepted(self):
        m = RIAMarketplaceDiscoverabilityRequest(
            enabled=True,
            headline="My Strategy",
            strategy_summary="We focus on long-term value.",
        )
        assert m.enabled is True
