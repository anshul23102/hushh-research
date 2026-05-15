"""
Tests for input bounds on voice and support request models.

Covers:
- VoicePlanRequest: user_id, transcript, turn_id, transcript_final,
  memory_short, memory_retrieved
- VoiceComposeRequest: user_id, transcript, turn_id, response_id, mode,
  action_id, guards, reply_strategy, action_completion, memory lists
- VoiceTTSRequest: user_id, text, voice
- VoiceCapabilityRequest: user_id
- VoiceRealtimeSessionRequest: user_id, voice
- SupportMessageRequest: user_id
"""

import pytest
from pydantic import ValidationError

from api.routes.kai.support import SupportMessageRequest
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

_RESPONSE_PAYLOAD = {
    "kind": "reply",
    "message": "Hello",
}


# ---------------------------------------------------------------------------
# VoicePlanRequest
# ---------------------------------------------------------------------------


class TestVoicePlanRequest:
    def test_valid_passes(self):
        r = VoicePlanRequest(user_id="u1", transcript="Buy Apple")
        assert r.user_id == "u1"

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="", transcript="Buy Apple")

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u" * 129, transcript="Buy Apple")

    def test_transcript_empty_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="")

    def test_transcript_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="t" * 32_001)

    def test_transcript_at_max_passes(self):
        r = VoicePlanRequest(user_id="u1", transcript="t" * 32_000)
        assert len(r.transcript) == 32_000

    def test_turn_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="t", turn_id="x" * 129)

    def test_transcript_final_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="t", transcript_final="f" * 32_001)

    def test_memory_short_over_100_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="t", memory_short=[{}] * 101)

    def test_memory_retrieved_over_100_raises(self):
        with pytest.raises(ValidationError):
            VoicePlanRequest(user_id="u1", transcript="t", memory_retrieved=[{}] * 101)

    def test_memory_short_at_max_passes(self):
        r = VoicePlanRequest(user_id="u1", transcript="t", memory_short=[{}] * 100)
        assert len(r.memory_short) == 100


# ---------------------------------------------------------------------------
# VoiceComposeRequest
# ---------------------------------------------------------------------------


class TestVoiceComposeRequest:
    def _valid(self, **kw) -> dict:
        base = dict(user_id="u1", transcript="Hello", response=_RESPONSE_PAYLOAD)
        return {**base, **kw}

    def test_valid_passes(self):
        r = VoiceComposeRequest(**self._valid())
        assert r.user_id == "u1"

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(user_id=""))

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(user_id="u" * 129))

    def test_transcript_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(transcript="t" * 32_001))

    def test_turn_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(turn_id="x" * 129))

    def test_response_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(response_id="r" * 129))

    def test_mode_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(mode="m" * 65))

    def test_action_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(action_id="a" * 129))

    def test_guards_over_50_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(guards=["g"] * 51))

    def test_reply_strategy_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(reply_strategy="r" * 65))

    def test_action_completion_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(action_completion="a" * 257))

    def test_memory_short_over_100_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(memory_short=[{}] * 101))

    def test_memory_retrieved_over_100_raises(self):
        with pytest.raises(ValidationError):
            VoiceComposeRequest(**self._valid(memory_retrieved=[{}] * 101))


# ---------------------------------------------------------------------------
# VoiceTTSRequest
# ---------------------------------------------------------------------------


class TestVoiceTTSRequest:
    def test_valid_passes(self):
        r = VoiceTTSRequest(user_id="u1", text="Hello there")
        assert r.voice == "alloy"

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            VoiceTTSRequest(user_id="", text="Hello")

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceTTSRequest(user_id="u" * 129, text="Hello")

    def test_text_empty_raises(self):
        with pytest.raises(ValidationError):
            VoiceTTSRequest(user_id="u1", text="")

    def test_text_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceTTSRequest(user_id="u1", text="t" * 4097)

    def test_text_at_max_passes(self):
        r = VoiceTTSRequest(user_id="u1", text="t" * 4096)
        assert len(r.text) == 4096

    def test_voice_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceTTSRequest(user_id="u1", text="Hello", voice="v" * 65)


# ---------------------------------------------------------------------------
# VoiceCapabilityRequest
# ---------------------------------------------------------------------------


class TestVoiceCapabilityRequest:
    def test_valid_passes(self):
        r = VoiceCapabilityRequest(user_id="u1")
        assert r.user_id == "u1"

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            VoiceCapabilityRequest(user_id="")

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceCapabilityRequest(user_id="u" * 129)


# ---------------------------------------------------------------------------
# VoiceRealtimeSessionRequest
# ---------------------------------------------------------------------------


class TestVoiceRealtimeSessionRequest:
    def test_valid_passes(self):
        r = VoiceRealtimeSessionRequest(user_id="u1")
        assert r.voice is None

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            VoiceRealtimeSessionRequest(user_id="")

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceRealtimeSessionRequest(user_id="u" * 129)

    def test_voice_too_long_raises(self):
        with pytest.raises(ValidationError):
            VoiceRealtimeSessionRequest(user_id="u1", voice="v" * 65)


# ---------------------------------------------------------------------------
# SupportMessageRequest
# ---------------------------------------------------------------------------


class TestSupportMessageRequest:
    def _valid(self, **kw) -> dict:
        base = dict(
            user_id="u1",
            kind="support_request",
            subject="App crashes on login",
            message="When I tap login the app crashes immediately.",
        )
        return {**base, **kw}

    def test_valid_passes(self):
        r = SupportMessageRequest(**self._valid())
        assert r.user_id == "u1"

    def test_user_id_empty_raises(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(**self._valid(user_id=""))

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(**self._valid(user_id="u" * 129))

    def test_user_id_at_max_passes(self):
        r = SupportMessageRequest(**self._valid(user_id="u" * 128))
        assert len(r.user_id) == 128

    def test_invalid_kind_raises(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(**self._valid(kind="spam"))

    def test_subject_too_long_raises(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(**self._valid(subject="s" * 141))

    def test_message_too_long_raises(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(**self._valid(message="m" * 8001))
