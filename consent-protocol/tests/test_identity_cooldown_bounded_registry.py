"""
Canonical caller proof: _CooldownRegistry is reachable through the
shipped ActorIdentityService.schedule_sync_from_firebase path.

Canonical attach point:
  hushh_mcp.services.actor_identity_service.ActorIdentityService
  .schedule_sync_from_firebase
  -> uses module-level _IDENTITY_SYNC_COOLDOWN_UNTIL (_CooldownRegistry)
  -> called by api.routes.consent (via _hydrate_pending_requester_labels
     -> ActorIdentityService().ensure_many -> schedule_sync_from_firebase)

Strategy
--------
- Import ActorIdentityService and _IDENTITY_SYNC_COOLDOWN_UNTIL directly.
- Drive schedule_sync_from_firebase with a mocked event loop so no real
  asyncio, DB, or Firebase infra is needed.
- Verify that _IDENTITY_SYNC_COOLDOWN_UNTIL is a _CooldownRegistry instance
  (not the old unbounded dict).
- Verify that schedule_sync_from_firebase writes into it on first call and
  that a second immediate call is blocked by the TTL entry.
- Verify the registry stays bounded under repeated calls (size cap).
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from hushh_mcp.services.actor_identity_service import (
    _IDENTITY_SYNC_COOLDOWN_UNTIL,
    ActorIdentityService,
    _CooldownRegistry,
)

# A 28-char string that satisfies the Firebase UID length heuristic.
_FAKE_UID = "testuid1234567890abcdefghij"
_FAKE_UID_2 = "testuid1234567890abcdefghij2"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _past(seconds: float = 60) -> datetime:
    return _now() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_loop_and_task() -> tuple[MagicMock, MagicMock]:
    mock_loop = MagicMock()
    mock_task = MagicMock()
    mock_task.done.return_value = True  # no prior task running
    mock_loop.create_task.return_value = mock_task
    return mock_loop, mock_task


# ---------------------------------------------------------------------------
# Proof: module-level registry is a _CooldownRegistry (not a plain dict)
# ---------------------------------------------------------------------------


class TestIdentityCooldownBoundedRegistryCallProof:
    """
    Canonical caller proof: ActorIdentityService.schedule_sync_from_firebase
    writes to and reads from a _CooldownRegistry, not an unbounded plain dict.

    Canonical attach point:
      hushh_mcp.services.actor_identity_service.ActorIdentityService
      .schedule_sync_from_firebase -> _IDENTITY_SYNC_COOLDOWN_UNTIL
    """

    def setup_method(self):
        _IDENTITY_SYNC_COOLDOWN_UNTIL.clear()

    def teardown_method(self):
        _IDENTITY_SYNC_COOLDOWN_UNTIL.clear()

    # ------------------------------------------------------------------
    # Static: module exports _CooldownRegistry, not a plain dict
    # ------------------------------------------------------------------

    def test_cooldown_registry_is_bounded_instance(self):
        """_IDENTITY_SYNC_COOLDOWN_UNTIL must be a _CooldownRegistry."""
        assert isinstance(_IDENTITY_SYNC_COOLDOWN_UNTIL, _CooldownRegistry), (
            "_IDENTITY_SYNC_COOLDOWN_UNTIL must be a _CooldownRegistry, "
            f"got {type(_IDENTITY_SYNC_COOLDOWN_UNTIL)}"
        )

    def test_cooldown_registry_is_not_plain_dict(self):
        """The module-level registry must not be a bare dict."""
        assert not isinstance(_IDENTITY_SYNC_COOLDOWN_UNTIL, dict), (
            "Registry reverted to unbounded plain dict - memory leak risk"
        )

    def test_registry_has_size_cap(self):
        """_CooldownRegistry must expose MAX_ENTRIES to confirm bounded design."""
        assert hasattr(_IDENTITY_SYNC_COOLDOWN_UNTIL, "MAX_ENTRIES")
        assert _IDENTITY_SYNC_COOLDOWN_UNTIL.MAX_ENTRIES >= 1

    def test_registry_has_thread_lock(self):
        """_CooldownRegistry must carry a threading.Lock for thread safety."""
        import threading

        assert hasattr(_IDENTITY_SYNC_COOLDOWN_UNTIL, "_lock")
        assert isinstance(_IDENTITY_SYNC_COOLDOWN_UNTIL._lock, type(threading.Lock()))

    # ------------------------------------------------------------------
    # Reachability: schedule_sync_from_firebase writes to _CooldownRegistry
    # ------------------------------------------------------------------

    def test_schedule_sync_writes_cooldown_entry(self):
        """
        After a successful schedule_sync_from_firebase call the
        _CooldownRegistry must contain a future deadline for the UID.
        """
        svc = ActorIdentityService()
        mock_loop, mock_task = _make_mock_loop_and_task()

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            result = svc.schedule_sync_from_firebase(_FAKE_UID)

        assert result is True
        deadline = _IDENTITY_SYNC_COOLDOWN_UNTIL.get(_FAKE_UID)
        assert deadline is not None, "schedule_sync must write a cooldown deadline"
        assert deadline > _now(), "Cooldown deadline must be in the future"

    def test_second_immediate_schedule_is_blocked_by_cooldown(self):
        """
        A second immediate call to schedule_sync_from_firebase for the
        same UID must return False because the cooldown entry is live.
        """
        svc = ActorIdentityService()
        mock_loop, mock_task = _make_mock_loop_and_task()

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            first = svc.schedule_sync_from_firebase(_FAKE_UID)
            # Simulate task finished so the task-running guard does not block
            mock_task.done.return_value = True
            second = svc.schedule_sync_from_firebase(_FAKE_UID)

        assert first is True
        assert second is False, (
            "Cooldown registry must block immediate re-schedule for same UID"
        )

    def test_expired_cooldown_allows_reschedule(self):
        """
        After the cooldown deadline has passed the registry allows a
        new schedule call for the same UID.
        """
        svc = ActorIdentityService()
        # Pre-plant an expired entry
        _IDENTITY_SYNC_COOLDOWN_UNTIL._data[_FAKE_UID] = _past(300)

        mock_loop, mock_task = _make_mock_loop_and_task()

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            result = svc.schedule_sync_from_firebase(_FAKE_UID)

        assert result is True, "Expired cooldown must not block a new schedule"

    def test_force_flag_bypasses_cooldown(self):
        """
        schedule_sync_from_firebase(..., force=True) must succeed even
        when a live cooldown entry exists for the UID.
        """
        svc = ActorIdentityService()
        # Plant an active cooldown
        _IDENTITY_SYNC_COOLDOWN_UNTIL[_FAKE_UID] = _now() + timedelta(minutes=5)

        mock_loop, mock_task = _make_mock_loop_and_task()

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            result = svc.schedule_sync_from_firebase(_FAKE_UID, force=True)

        assert result is True, "force=True must bypass the cooldown check"

    # ------------------------------------------------------------------
    # Boundedness: repeated calls from many UIDs stay within cap
    # ------------------------------------------------------------------

    def test_registry_stays_bounded_under_load(self):
        """
        Repeated calls for many UIDs must not grow the registry beyond
        its configured MAX_ENTRIES cap.
        """
        svc = ActorIdentityService()
        mock_loop, _ = _make_mock_loop_and_task()

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            for i in range(200):
                uid = f"testuid123456789abcdefghij{i:04d}"
                svc.schedule_sync_from_firebase(uid)

        assert len(_IDENTITY_SYNC_COOLDOWN_UNTIL) <= _IDENTITY_SYNC_COOLDOWN_UNTIL.MAX_ENTRIES

    # ------------------------------------------------------------------
    # Source-level proof: service file uses _CooldownRegistry, not dict
    # ------------------------------------------------------------------

    def test_service_source_uses_cooldown_registry_class(self):
        """The actor_identity_service module must reference _CooldownRegistry."""
        import hushh_mcp.services.actor_identity_service as svc_mod

        src = inspect.getsource(svc_mod)
        assert "_CooldownRegistry" in src
        assert "_CooldownRegistry()" in src, (
            "Module must instantiate _CooldownRegistry as the cooldown store"
        )

    def test_service_source_does_not_use_bare_dict_for_cooldown(self):
        """Confirm the module removed the old unbounded dict for cooldowns."""
        import hushh_mcp.services.actor_identity_service as svc_mod

        src = inspect.getsource(svc_mod)
        # The old pattern was: _IDENTITY_SYNC_COOLDOWN_UNTIL: dict[str, datetime] = {}
        assert "dict[str, datetime] = {}" not in src, (
            "Old unbounded dict pattern found - fix not applied"
        )
