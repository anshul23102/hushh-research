"""
Regression tests for unbounded string-field DoS in Kai stream and voice request models.

Attach point: api/routes/kai/stream.py (StreamAnalyzeRequest, StartAnalyzeRunRequest)
             api/routes/kai/voice.py  (VoicePlanRequest, VoiceComposeRequest,
                                        VoiceTTSRequest, VoiceCapabilityRequest,
                                        VoiceRealtimeSessionRequest)

Each test asserts that Pydantic raises ValidationError when a string field exceeds its
declared max_length, preventing a caller from sending arbitrarily large payloads that
would exhaust server memory.
"""

import pytest
from pydantic import ValidationError

from api.routes.kai.stream import StartAnalyzeRunRequest, StreamAnalyzeRequest
from api.routes.kai.voice import (
    VoiceCapabilityRequest,
    VoiceComposeRequest,
    VoicePlanRequest,
    VoiceRealtimeSessionRequest,
    VoiceTTSRequest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_UID = "u" * 32
_LONG_UID = "u" * 129          # > 128
_LONG_TICKER = "A" * 11        # > 10
_LONG_RISK = "r" * 51          # > 50
_LONG_RUN_ID = "r" * 129       # > 128
_LONG_TEXT_10K = "x" * 10_001  # > 10_000
_LONG_TEXT_5K = "x" * 5_001    # > 5_000
_LONG_VOICE = "v" * 51         # > 50
_LONG_DEBATE = "d" * 129       # > 128
_LONG_PICK = "p" * 101         # > 100
_LONG_LABEL = "l" * 201        # > 200
_LONG_KIND = "k" * 51          # > 50


# ===========================================================================
# StreamAnalyzeRequest
# ===========================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"ticker": _LONG_TICKER},
        {"ticker": ""},
        {"risk_profile": _LONG_RISK},
        {"run_id": _LONG_RUN_ID},
    ],
)
def test_stream_analyze_request_rejects_oversized_fields(overrides):
    base = {"user_id": _GOOD_UID, "ticker": "AAPL"}
    with pytest.raises(ValidationError):
        StreamAnalyzeRequest(**{**base, **overrides})


# ===========================================================================
# StartAnalyzeRunRequest
# ===========================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"debate_session_id": _LONG_DEBATE},
        {"debate_session_id": ""},
        {"ticker": _LONG_TICKER},
        {"ticker": ""},
        {"risk_profile": _LONG_RISK},
        {"pick_source": _LONG_PICK},
        {"pick_source_label": _LONG_LABEL},
        {"pick_source_kind": _LONG_KIND},
    ],
)
def test_start_analyze_run_request_rejects_oversized_fields(overrides):
    base = {"user_id": _GOOD_UID, "debate_session_id": "sess-01", "ticker": "AAPL"}
    with pytest.raises(ValidationError):
        StartAnalyzeRunRequest(**{**base, **overrides})


# ===========================================================================
# VoicePlanRequest
# ===========================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"transcript": _LONG_TEXT_10K},
        {"transcript": ""},
        {"turn_id": _LONG_RUN_ID},
        {"transcript_final": _LONG_TEXT_10K},
    ],
)
def test_voice_plan_request_rejects_oversized_fields(overrides):
    base = {"user_id": _GOOD_UID, "transcript": "buy everything"}
    with pytest.raises(ValidationError):
        VoicePlanRequest(**{**base, **overrides})


# ===========================================================================
# VoiceComposeRequest  (requires a valid VoiceResponsePayload)
# ===========================================================================


def _compose_base():
    from api.routes.kai.voice import VoiceResponsePayload

    return {
        "user_id": _GOOD_UID,
        "transcript": "ok",
        "response": VoiceResponsePayload(
            type="speak",
            text="hello",
            tts_text="hello",
            tts_voice="alloy",
            tts_format="mp3",
        ),
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"transcript": _LONG_TEXT_10K},
        {"transcript": ""},
        {"turn_id": _LONG_RUN_ID},
        {"response_id": _LONG_RUN_ID},
        {"mode": _LONG_RISK},
        {"action_id": _LONG_RUN_ID},
        {"reply_strategy": _LONG_RISK},
        {"action_completion": "a" * 201},
    ],
)
def test_voice_compose_request_rejects_oversized_fields(overrides):
    with pytest.raises(ValidationError):
        VoiceComposeRequest(**{**_compose_base(), **overrides})


# ===========================================================================
# VoiceTTSRequest
# ===========================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"text": _LONG_TEXT_5K},
        {"text": ""},
        {"voice": _LONG_VOICE},
    ],
)
def test_voice_tts_request_rejects_oversized_fields(overrides):
    base = {"user_id": _GOOD_UID, "text": "hello"}
    with pytest.raises(ValidationError):
        VoiceTTSRequest(**{**base, **overrides})


# ===========================================================================
# VoiceCapabilityRequest
# ===========================================================================


@pytest.mark.parametrize(
    "user_id",
    [_LONG_UID, ""],
)
def test_voice_capability_request_rejects_oversized_user_id(user_id):
    with pytest.raises(ValidationError):
        VoiceCapabilityRequest(user_id=user_id)


# ===========================================================================
# VoiceRealtimeSessionRequest
# ===========================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": _LONG_UID},
        {"user_id": ""},
        {"voice": _LONG_VOICE},
    ],
)
def test_voice_realtime_session_request_rejects_oversized_fields(overrides):
    base = {"user_id": _GOOD_UID}
    with pytest.raises(ValidationError):
        VoiceRealtimeSessionRequest(**{**base, **overrides})


# ===========================================================================
# Happy-path smoke tests (valid payloads must not raise)
# ===========================================================================


def test_stream_analyze_request_accepts_valid_payload():
    req = StreamAnalyzeRequest(user_id=_GOOD_UID, ticker="AAPL", risk_profile="aggressive")
    assert req.ticker == "AAPL"


def test_start_analyze_run_accepts_valid_payload():
    req = StartAnalyzeRunRequest(
        user_id=_GOOD_UID, debate_session_id="sess-01", ticker="MSFT"
    )
    assert req.ticker == "MSFT"


def test_voice_plan_accepts_valid_payload():
    req = VoicePlanRequest(user_id=_GOOD_UID, transcript="what should I buy?")
    assert req.user_id == _GOOD_UID


def test_voice_tts_accepts_valid_payload():
    req = VoiceTTSRequest(user_id=_GOOD_UID, text="good morning")
    assert req.voice == "alloy"


def test_voice_realtime_session_accepts_valid_payload():
    req = VoiceRealtimeSessionRequest(user_id=_GOOD_UID, voice="echo")
    assert req.voice == "echo"
