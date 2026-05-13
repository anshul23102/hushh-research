"""Hermetic unit tests for _get_market_data_lock eviction logic in fetchers.py.

_MARKET_DATA_LOCKS previously grew without bound: a new asyncio.Lock was
created for every unique cache key (format: "{symbol}|fh:{0|1}|pmp:{0|1}")
and never removed, even after the corresponding cache entry expired.

With 10 000+ unique symbols queried over an instance lifetime, this becomes
a permanent ~3 MB memory leak (10 000 x ~300 B) with no relief valve.

The fix adds a capacity cap with a two-step eviction strategy:
  1. Remove locks for keys no longer present in _MARKET_DATA_CACHE (stale).
  2. If still at capacity, drop the oldest-inserted lock.

All tests run without DB, network, or LLM.
"""

from __future__ import annotations

import asyncio
import threading

import hushh_mcp.operons.kai.fetchers as fetchers_module
from hushh_mcp.operons.kai.fetchers import _get_market_data_lock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset(max_entries: int = 10_000) -> None:
    """Clear both module-level dicts and set the cap for this test."""
    fetchers_module._MARKET_DATA_LOCKS.clear()
    fetchers_module._MARKET_DATA_CACHE.clear()
    fetchers_module._MARKET_DATA_LOCKS_MAX = max_entries


# ---------------------------------------------------------------------------
# Basic creation semantics
# ---------------------------------------------------------------------------


class TestLockCreation:
    def setup_method(self):
        _reset()

    def test_returns_asyncio_lock(self):
        lock = _get_market_data_lock("AAPL|fh:1|pmp:0")
        assert isinstance(lock, asyncio.Lock)

    def test_same_key_returns_same_object(self):
        k = "MSFT|fh:1|pmp:0"
        lock_a = _get_market_data_lock(k)
        lock_b = _get_market_data_lock(k)
        assert lock_a is lock_b

    def test_different_keys_return_different_objects(self):
        lock_a = _get_market_data_lock("AAPL|fh:1|pmp:0")
        lock_b = _get_market_data_lock("GOOG|fh:1|pmp:0")
        assert lock_a is not lock_b

    def test_lock_stored_in_registry(self):
        _get_market_data_lock("TSLA|fh:0|pmp:0")
        assert "TSLA|fh:0|pmp:0" in fetchers_module._MARKET_DATA_LOCKS

    def test_lock_count_grows_with_unique_keys(self):
        for sym in ("AAPL", "GOOG", "MSFT"):
            _get_market_data_lock(f"{sym}|fh:1|pmp:0")
        assert len(fetchers_module._MARKET_DATA_LOCKS) == 3


# ---------------------------------------------------------------------------
# Capacity cap: stale-key eviction (step 1)
# ---------------------------------------------------------------------------


class TestStaleKeyEviction:
    def setup_method(self):
        _reset(max_entries=3)

    def test_stale_locks_evicted_on_overflow(self):
        # Fill to capacity with keys that have NO cache entries (stale)
        for sym in ("AAA", "BBB", "CCC"):
            _get_market_data_lock(f"{sym}|fh:1|pmp:0")
        assert len(fetchers_module._MARKET_DATA_LOCKS) == 3

        # Adding a 4th key should trigger stale eviction
        _get_market_data_lock("DDD|fh:1|pmp:0")
        assert len(fetchers_module._MARKET_DATA_LOCKS) <= 3

    def test_cache_backed_locks_survive_eviction(self):
        # Key with a live cache entry must NOT be evicted
        live_key = "LIVE|fh:1|pmp:0"
        fetchers_module._MARKET_DATA_CACHE[live_key] = (9_999_999_999, {"price": 100})
        _get_market_data_lock(live_key)

        # Fill with two more stale keys to reach cap=3
        _get_market_data_lock("STALE1|fh:1|pmp:0")
        _get_market_data_lock("STALE2|fh:1|pmp:0")

        # Overflow: adding a 4th should evict stale keys, not the live one
        _get_market_data_lock("NEW|fh:1|pmp:0")
        assert live_key in fetchers_module._MARKET_DATA_LOCKS

    def test_new_key_present_after_stale_eviction(self):
        for sym in ("X1", "X2", "X3"):
            _get_market_data_lock(f"{sym}|fh:0|pmp:0")
        new_key = "NEWKEY|fh:0|pmp:0"
        _get_market_data_lock(new_key)
        assert new_key in fetchers_module._MARKET_DATA_LOCKS


# ---------------------------------------------------------------------------
# Capacity cap: oldest-entry eviction (step 2)
# ---------------------------------------------------------------------------


class TestOldestEntryEviction:
    def setup_method(self):
        _reset(max_entries=2)

    def _fill_cache_for(self, *keys: str) -> None:
        for k in keys:
            fetchers_module._MARKET_DATA_CACHE[k] = (9_999_999_999, {"price": 1})

    def test_oldest_lock_evicted_when_all_live(self):
        k1, k2 = "SYM1|fh:1|pmp:0", "SYM2|fh:1|pmp:0"
        self._fill_cache_for(k1, k2)
        _get_market_data_lock(k1)
        _get_market_data_lock(k2)

        k3 = "SYM3|fh:1|pmp:0"
        self._fill_cache_for(k3)
        _get_market_data_lock(k3)

        assert len(fetchers_module._MARKET_DATA_LOCKS) <= 2
        # The most recently inserted key must survive
        assert k3 in fetchers_module._MARKET_DATA_LOCKS

    def test_cap_never_exceeded(self):
        _reset(max_entries=5)
        for i in range(20):
            _get_market_data_lock(f"SYM{i}|fh:1|pmp:0")
        assert len(fetchers_module._MARKET_DATA_LOCKS) <= 5


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def setup_method(self):
        _reset()

    def test_max_one_works(self):
        _reset(max_entries=1)
        _get_market_data_lock("A|fh:0|pmp:0")
        _get_market_data_lock("B|fh:0|pmp:0")
        assert len(fetchers_module._MARKET_DATA_LOCKS) <= 1

    def test_repeated_same_key_no_growth(self):
        k = "REPEAT|fh:1|pmp:0"
        for _ in range(100):
            _get_market_data_lock(k)
        assert len(fetchers_module._MARKET_DATA_LOCKS) == 1

    def test_empty_string_key_accepted(self):
        lock = _get_market_data_lock("")
        assert isinstance(lock, asyncio.Lock)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def setup_method(self):
        _reset(max_entries=10_000)

    def test_concurrent_creates_no_corruption(self):
        errors: list[Exception] = []

        def worker(prefix: str) -> None:
            try:
                for i in range(50):
                    _get_market_data_lock(f"{prefix}_{i}|fh:1|pmp:0")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"T{n}",)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(fetchers_module._MARKET_DATA_LOCKS) <= fetchers_module._MARKET_DATA_LOCKS_MAX

    def test_concurrent_same_key_returns_consistent_object(self):
        """Multiple threads requesting the same key must get the same lock."""
        results: list[asyncio.Lock] = []
        lock = threading.Lock()

        def worker() -> None:
            obj = _get_market_data_lock("SHARED|fh:1|pmp:1")
            with lock:
                results.append(obj)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should have received the same Lock object
        assert len({id(r) for r in results}) == 1
