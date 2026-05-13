"""Hermetic tests for the bounded _MARKET_DATA_CACHE in fetchers.py.

No DB, no network, no LLM.  All tests manipulate the module-level
_MARKET_DATA_CACHE / _MARKET_DATA_CACHE_MAX directly via the public
helpers _get_cached_market_data and _set_cached_market_data.
"""

from __future__ import annotations

import threading
import time

import pytest

from hushh_mcp.operons.kai import fetchers
from hushh_mcp.operons.kai.fetchers import (
    _get_cached_market_data,
    _set_cached_market_data,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_cache():
    """Isolate every test: clear the cache and restore the original cap."""
    original_max = fetchers._MARKET_DATA_CACHE_MAX
    fetchers._MARKET_DATA_CACHE.clear()
    yield
    fetchers._MARKET_DATA_CACHE.clear()
    fetchers._MARKET_DATA_CACHE_MAX = original_max


# ---------------------------------------------------------------------------
# Basic get / set
# ---------------------------------------------------------------------------


class TestBasicGetSet:
    def test_miss_returns_none(self):
        assert _get_cached_market_data("AAPL|fh:0|pmp:0") is None

    def test_set_then_get_returns_payload(self):
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 150.0}, ttl_seconds=60)
        result = _get_cached_market_data("AAPL|fh:0|pmp:0")
        assert result is not None
        assert result["price"] == 150.0

    def test_get_returns_independent_copy(self):
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 150.0}, ttl_seconds=60)
        r1 = _get_cached_market_data("AAPL|fh:0|pmp:0")
        r1["mutated"] = True
        r2 = _get_cached_market_data("AAPL|fh:0|pmp:0")
        assert "mutated" not in r2

    def test_update_existing_key(self):
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 100.0}, ttl_seconds=60)
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 200.0}, ttl_seconds=60)
        result = _get_cached_market_data("AAPL|fh:0|pmp:0")
        assert result["price"] == 200.0

    def test_multiple_symbols_stored_independently(self):
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 150.0}, ttl_seconds=60)
        _set_cached_market_data("GOOG|fh:0|pmp:0", {"price": 2800.0}, ttl_seconds=60)
        assert _get_cached_market_data("AAPL|fh:0|pmp:0")["price"] == 150.0
        assert _get_cached_market_data("GOOG|fh:0|pmp:0")["price"] == 2800.0


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------


class TestTTLExpiry:
    def test_expired_entry_returns_none(self):
        # minimum TTL is clamped to 60s, so we patch the cache directly
        # with a past expiry to simulate expiration
        key = "AAPL|fh:0|pmp:0"
        fetchers._MARKET_DATA_CACHE[key] = (time.time() - 1.0, {"price": 50.0})
        assert _get_cached_market_data(key) is None

    def test_expired_entry_removed_from_cache(self):
        key = "AAPL|fh:0|pmp:0"
        fetchers._MARKET_DATA_CACHE[key] = (time.time() - 1.0, {"price": 50.0})
        _get_cached_market_data(key)
        assert key not in fetchers._MARKET_DATA_CACHE

    def test_live_entry_not_evicted(self):
        key = "TSLA|fh:0|pmp:0"
        _set_cached_market_data(key, {"price": 700.0}, ttl_seconds=300)
        assert _get_cached_market_data(key) is not None


# ---------------------------------------------------------------------------
# Size cap - stale eviction first
# ---------------------------------------------------------------------------


class TestSizeCapStaleFirst:
    def test_stale_entries_evicted_before_live(self):
        """When cap is reached, expired entries are pruned before live ones."""
        fetchers._MARKET_DATA_CACHE_MAX = 3
        # Insert two entries with already-expired TTLs
        fetchers._MARKET_DATA_CACHE["stale1|fh:0|pmp:0"] = (time.time() - 10, {"v": 1})
        fetchers._MARKET_DATA_CACHE["stale2|fh:0|pmp:0"] = (time.time() - 10, {"v": 2})
        fetchers._MARKET_DATA_CACHE["live1|fh:0|pmp:0"] = (time.time() + 600, {"v": 3})
        # At cap=3, adding a fourth entry should first evict stale entries
        _set_cached_market_data("live2|fh:0|pmp:0", {"v": 4}, ttl_seconds=300)
        # live1 must survive (it was not stale)
        assert _get_cached_market_data("live1|fh:0|pmp:0") is not None
        assert _get_cached_market_data("live2|fh:0|pmp:0") is not None
        assert len(fetchers._MARKET_DATA_CACHE) <= 3

    def test_cap_never_exceeded(self):
        fetchers._MARKET_DATA_CACHE_MAX = 5
        for i in range(20):
            _set_cached_market_data(f"SYM{i}|fh:0|pmp:0", {"i": i}, ttl_seconds=300)
        assert len(fetchers._MARKET_DATA_CACHE) <= 5


# ---------------------------------------------------------------------------
# Size cap - oldest eviction fallback
# ---------------------------------------------------------------------------


class TestSizeCapOldestFallback:
    def test_oldest_evicted_when_all_live(self):
        fetchers._MARKET_DATA_CACHE_MAX = 3
        _set_cached_market_data("first|fh:0|pmp:0", {"v": 1}, ttl_seconds=300)
        _set_cached_market_data("second|fh:0|pmp:0", {"v": 2}, ttl_seconds=300)
        _set_cached_market_data("third|fh:0|pmp:0", {"v": 3}, ttl_seconds=300)
        # fourth write should evict "first" (oldest-inserted)
        _set_cached_market_data("fourth|fh:0|pmp:0", {"v": 4}, ttl_seconds=300)
        assert _get_cached_market_data("first|fh:0|pmp:0") is None
        assert _get_cached_market_data("fourth|fh:0|pmp:0") is not None

    def test_update_in_place_does_not_evict(self):
        """Updating an existing key must not trigger any eviction."""
        fetchers._MARKET_DATA_CACHE_MAX = 2
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 100.0}, ttl_seconds=300)
        _set_cached_market_data("GOOG|fh:0|pmp:0", {"price": 200.0}, ttl_seconds=300)
        # Both slots filled; update AAPL - no eviction should happen
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 110.0}, ttl_seconds=300)
        assert len(fetchers._MARKET_DATA_CACHE) == 2
        assert _get_cached_market_data("GOOG|fh:0|pmp:0") is not None

    def test_max_1_keeps_only_latest(self):
        fetchers._MARKET_DATA_CACHE_MAX = 1
        _set_cached_market_data("AAPL|fh:0|pmp:0", {"price": 100.0}, ttl_seconds=300)
        _set_cached_market_data("GOOG|fh:0|pmp:0", {"price": 200.0}, ttl_seconds=300)
        assert len(fetchers._MARKET_DATA_CACHE) == 1
        assert _get_cached_market_data("GOOG|fh:0|pmp:0") is not None
        assert _get_cached_market_data("AAPL|fh:0|pmp:0") is None


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_writes_stay_within_cap(self):
        cap = 50
        fetchers._MARKET_DATA_CACHE_MAX = cap
        errors: list[Exception] = []

        def _worker(start: int) -> None:
            try:
                for i in range(start, start + 30):
                    _set_cached_market_data(f"SYM{i}|fh:0|pmp:0", {"i": i}, ttl_seconds=300)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i * 30,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(fetchers._MARKET_DATA_CACHE) <= cap

    def test_concurrent_reads_and_writes_no_exception(self):
        fetchers._MARKET_DATA_CACHE_MAX = 20
        errors: list[Exception] = []

        def _writer() -> None:
            try:
                for i in range(50):
                    _set_cached_market_data(f"SYM{i % 25}|fh:0|pmp:0", {"i": i}, ttl_seconds=300)
            except Exception as exc:
                errors.append(exc)

        def _reader() -> None:
            try:
                for i in range(50):
                    _get_cached_market_data(f"SYM{i % 25}|fh:0|pmp:0")
            except Exception as exc:
                errors.append(exc)

        threads = [
            *(threading.Thread(target=_writer) for _ in range(4)),
            *(threading.Thread(target=_reader) for _ in range(4)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
