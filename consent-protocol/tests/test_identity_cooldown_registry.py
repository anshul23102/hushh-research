"""Hermetic unit tests for _CooldownRegistry in actor_identity_service.py.

_CooldownRegistry is the drop-in replacement for the bare dict[str, datetime]
that used to accumulate every unique Firebase UID that ever triggered a
background sync -- with no eviction, growing unboundedly for the lifetime of
the Cloud Run instance.

All tests run without DB, network, or Firebase.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from hushh_mcp.services.actor_identity_service import _CooldownRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COOLDOWN = timedelta(minutes=5)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _future(seconds: float = 300) -> datetime:
    return _now() + timedelta(seconds=seconds)


def _past(seconds: float = 1) -> datetime:
    return _now() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Basic membership semantics
# ---------------------------------------------------------------------------


class TestBasicSemantics:
    def test_get_unknown_key_returns_none(self):
        reg = _CooldownRegistry()
        assert reg.get("no_such_user") is None

    def test_set_then_get_returns_deadline(self):
        reg = _CooldownRegistry()
        deadline = _future()
        reg["user_a"] = deadline
        result = reg.get("user_a")
        assert result is not None
        assert abs((result - deadline).total_seconds()) < 0.001

    def test_len_empty_is_zero(self):
        reg = _CooldownRegistry()
        assert len(reg) == 0

    def test_len_after_one_set(self):
        reg = _CooldownRegistry()
        reg["user_x"] = _future()
        assert len(reg) == 1

    def test_len_after_multiple_sets(self):
        reg = _CooldownRegistry()
        for i in range(5):
            reg[f"user_{i}"] = _future()
        assert len(reg) == 5

    def test_duplicate_set_is_idempotent(self):
        reg = _CooldownRegistry()
        first = _future(100)
        reg["u"] = first
        second = _future(200)
        reg["u"] = second
        # Only one entry; value updated to second
        assert len(reg) == 1
        result = reg.get("u")
        assert result is not None
        assert abs((result - second).total_seconds()) < 0.001

    def test_clear_empties_registry(self):
        reg = _CooldownRegistry()
        for i in range(10):
            reg[f"u{i}"] = _future()
        reg.clear()
        assert len(reg) == 0
        assert reg.get("u0") is None


# ---------------------------------------------------------------------------
# TTL eviction via get()
# ---------------------------------------------------------------------------


class TestTTLEviction:
    def test_expired_entry_returns_none(self):
        reg = _CooldownRegistry()
        # Back-date the entry so it is already expired
        reg._data["u_expired"] = _past(10)
        assert reg.get("u_expired") is None

    def test_expired_entry_is_removed_from_data(self):
        reg = _CooldownRegistry()
        reg._data["u_stale"] = _past(5)
        reg.get("u_stale")  # trigger lazy eviction
        assert "u_stale" not in reg._data

    def test_non_expired_entry_survives_get(self):
        reg = _CooldownRegistry()
        reg["u_fresh"] = _future(300)
        reg.get("u_fresh")
        assert len(reg) == 1

    def test_exactly_expired_deadline_is_evicted(self):
        # An entry at exactly now (not strictly future) is considered expired
        reg = _CooldownRegistry()
        # Slight past to avoid race between assignment and check
        reg._data["u_boundary"] = _now() - timedelta(milliseconds=1)
        assert reg.get("u_boundary") is None


# ---------------------------------------------------------------------------
# Size cap enforcement
# ---------------------------------------------------------------------------


class TestSizeCap:
    def test_size_cap_not_exceeded(self):
        cap = 5
        reg = _CooldownRegistry(max_entries=cap)
        for i in range(cap + 3):
            reg[f"u{i}"] = _future()
        assert len(reg) <= cap

    def test_expired_entries_evicted_before_oldest(self):
        """When over capacity, expired entries go first."""
        reg = _CooldownRegistry(max_entries=3)
        # Fill with two expired
        reg._data["expired_1"] = _past(10)
        reg._data["expired_2"] = _past(5)
        reg["fresh_1"] = _future()
        # Trigger overflow with a 4th entry
        reg["fresh_2"] = _future()
        # expired_1 and expired_2 should be gone; both fresh entries remain
        assert reg.get("fresh_1") is not None
        assert reg.get("fresh_2") is not None
        assert reg.get("expired_1") is None
        assert reg.get("expired_2") is None

    def test_oldest_entry_evicted_when_no_expired(self):
        """With no expired entries and cap=2, inserting a 3rd drops the oldest."""
        reg = _CooldownRegistry(max_entries=2)
        reg["first"] = _future(500)
        time.sleep(0.01)  # ensure insertion-order difference
        reg["second"] = _future(500)
        # Insert a third - "first" should be evicted (oldest inserted)
        reg["third"] = _future(500)
        assert len(reg) <= 2
        # "third" must survive as it was just inserted
        assert reg.get("third") is not None

    def test_max_entries_zero_raises(self):
        with pytest.raises(ValueError, match="max_entries must be >= 1"):
            _CooldownRegistry(max_entries=0)

    def test_max_entries_negative_raises(self):
        with pytest.raises(ValueError, match="max_entries must be >= 1"):
            _CooldownRegistry(max_entries=-5)

    def test_max_entries_one_works(self):
        reg = _CooldownRegistry(max_entries=1)
        reg["only"] = _future()
        assert len(reg) == 1
        reg["another"] = _future()
        assert len(reg) == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_set_from_many_threads(self):
        """8 threads each inserting 50 entries - no corruption or exception."""
        reg = _CooldownRegistry(max_entries=10_000)
        errors: list[Exception] = []

        def worker(prefix: str) -> None:
            try:
                for i in range(50):
                    reg[f"{prefix}_{i}"] = _future()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(reg) <= reg._max

    def test_concurrent_get_and_set(self):
        """Readers and writers run simultaneously - no race or exception."""
        reg = _CooldownRegistry(max_entries=500)
        for i in range(100):
            reg[f"seed_{i}"] = _future()

        errors: list[Exception] = []

        def writer() -> None:
            try:
                for i in range(200):
                    reg[f"w_{i}"] = _future()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def reader() -> None:
            try:
                for i in range(200):
                    reg.get(f"seed_{i % 100}")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(4)] + [
            threading.Thread(target=reader) for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"

    def test_concurrent_clear_and_set(self):
        """clear() racing against set() must not raise."""
        reg = _CooldownRegistry(max_entries=1_000)
        errors: list[Exception] = []

        def setter() -> None:
            try:
                for i in range(300):
                    reg[f"s_{i}"] = _future()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def clearer() -> None:
            try:
                for _ in range(10):
                    reg.clear()
                    time.sleep(0.002)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=setter) for _ in range(4)] + [
            threading.Thread(target=clearer)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"


# ---------------------------------------------------------------------------
# Integration: schedule_sync_from_firebase uses _IDENTITY_SYNC_COOLDOWN_UNTIL
# ---------------------------------------------------------------------------


class TestScheduleSyncIntegration:
    def test_cooldown_blocks_second_schedule(self):
        """After a successful schedule the cooldown prevents immediate re-schedule."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from hushh_mcp.services.actor_identity_service import (
            _IDENTITY_SYNC_COOLDOWN_UNTIL,
            ActorIdentityService,
        )

        _IDENTITY_SYNC_COOLDOWN_UNTIL.clear()

        svc = ActorIdentityService()
        uid = "uid_abcdefghijklmnopqrstuvwxyz1"  # 28+ chars, looks like Firebase UID

        mock_loop = MagicMock()
        mock_task = MagicMock()
        mock_task.done.return_value = False
        mock_loop.create_task.return_value = mock_task

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            first = svc.schedule_sync_from_firebase(uid)
            second = svc.schedule_sync_from_firebase(uid)

        assert first is True
        # Second call should be blocked by either the active task OR the cooldown
        assert second is False

    def test_expired_cooldown_allows_reschedule(self):
        """An expired cooldown entry does not block a new schedule."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from hushh_mcp.services.actor_identity_service import (
            _IDENTITY_SYNC_COOLDOWN_UNTIL,
            ActorIdentityService,
        )

        _IDENTITY_SYNC_COOLDOWN_UNTIL.clear()
        uid = "uid_bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        # Pre-set an already-expired cooldown
        _IDENTITY_SYNC_COOLDOWN_UNTIL._data[uid] = _past(10)

        svc = ActorIdentityService()
        mock_loop = MagicMock()
        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_loop.create_task.return_value = mock_task

        with (
            patch("asyncio.get_running_loop", return_value=mock_loop),
            patch.object(svc, "sync_from_firebase", new=AsyncMock()),
        ):
            result = svc.schedule_sync_from_firebase(uid)

        # Expired cooldown should not block; the schedule should succeed
        assert result is True
