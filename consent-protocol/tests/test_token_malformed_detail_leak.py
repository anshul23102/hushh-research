# tests/test_token_malformed_detail_leak.py
"""
CWE-209: validate_token() returned f"Malformed token: {str(e)}" as the
reason string, embedding raw exception detail (padding errors, codec
names, binascii messages) that callers forwarded verbatim in HTTP responses.

After the fix the reason is always the static string "Malformed token",
with the actual exception logged at DEBUG level server-side.
"""

import base64
import binascii

import pytest

from hushh_mcp.consent.token import validate_token


_LEAK_TERMS = [
    "ValueError",
    "UnicodeDecodeError",
    "binascii",
    "padding",
    "codec",
    "Incorrect padding",
    "invalid base64",
    "utf-8",
    "decode",
]


# Tokens that exercise the (ValueError | UnicodeDecodeError | binascii.Error) branch
_BAD_TOKENS = [
    # Not even close to the expected format
    "not-a-token",
    # Correct prefix, but base64 with broken padding
    "hct:!!!.sig",
    # Correct prefix, valid prefix split, but base64 that decodes to non-UTF-8
    "hct:" + base64.urlsafe_b64encode(b"\xff\xfe\xfd").decode() + ".sig",
    # Correct prefix, valid base64 but payload missing fields
    "hct:" + base64.urlsafe_b64encode(b"only|two").decode() + ".sig",
    # Plain garbage after prefix separator
    "hct:$$$$$$$$.sig",
]


@pytest.mark.parametrize("bad_token", _BAD_TOKENS)
def test_malformed_token_reason_contains_no_exception_detail(bad_token):
    """The reason string must never embed raw exception text."""
    valid, reason, token_obj = validate_token(bad_token)
    assert not valid
    assert token_obj is None
    assert reason is not None
    for term in _LEAK_TERMS:
        assert term not in reason, (
            f"validate_token leaked exception term {term!r} in reason: {reason!r}"
        )


def test_malformed_token_reason_is_exact_static_string():
    """The reason must be exactly 'Malformed token' (no extra detail appended)."""
    import base64 as _b64

    # Correct prefix (HCT), valid split, but base64 that decodes to non-UTF-8 bytes
    # so the UnicodeDecodeError path fires and must return exactly "Malformed token".
    bad_payload = _b64.urlsafe_b64encode(b"\xff\xfe").decode()
    token = f"HCT:{bad_payload}.sig"
    valid, reason, _ = validate_token(token)
    assert not valid
    assert reason == "Malformed token"


def test_valid_token_returns_no_reason():
    """Sanity: a valid token returns reason=None."""
    from hushh_mcp.consent.token import issue_token
    from hushh_mcp.constants import ConsentScope

    tok = issue_token("user-1", "agent-1", ConsentScope.VAULT_OWNER)
    valid, reason, token_obj = validate_token(tok.token)
    assert valid
    assert reason is None
    assert token_obj is not None
