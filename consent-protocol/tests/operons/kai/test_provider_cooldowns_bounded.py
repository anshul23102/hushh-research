"""Hermetic unit tests for _ProviderCooldownStore in fetchers.py.

No DB, no network, no LLM.

Covered:
    construction (default and custom capacity)
    in_cooldown — active, expired, missing
    set — basic, overwrites, TTL in future
    size cap — stale-first eviction, then FIFO oldest
    __len__ and clear
    concurrency — concurrent writers, concurrent reader+writer
    integration — _provider_in_cooldown, _mark_provider_cooldown,
                  _mark_provider_cooldown_for_duration
"""

from __future__ import annotations

import threading
import time

import pytest

from hushh_mcp.operons.kai.fetchers import (
    _PROVIDER_COOLDOWNS,
    _PROVIDER_COOLDOWNS_MAX,
    _mark_provider_cooldown,
    _mark_provider_cooldown_for_duration,
    _provider_in_cooldown,
    _ProviderCooldownStore,
)

# ---------------------------------------------------------------------------
# fixture: reset module-level store between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    _PROVIDER_COOLDOWNS.clear()
    original_max = _PROVIDER_COOLDOWNS._max
    yield
    _PROVIDER_COOLDOWNS.clear()
    _PROVIDER_COOLDOWNS._max = original_max


# ===========================================================================
# Construction
# ===========================================================================


class TestConstruction:
    def test_default_capacity_matches_env_var(self):
        store = _ProviderCooldownStore()
        assert store._max == _PROVIDER_COOLDOWNS_MAX

    def test_custom_capacity(self):
        store = _ProviderCooldownStore(max_entries=5)
        assert store._max == 5

    def test_initial_length_is_zero(self):
        assert len(_ProviderCooldownStore()) == 0


# ===========================================================================
# in_cooldown
# ===========================================================================


class TestInCooldown:
    def test_missing_key_returns_false(self):
        store = _ProviderCooldownStore()
        assert store.in_cooldown("finnhub:global") is False

    def test_active_cooldown_returns_true(self):
        store = _ProviderCooldownStore()
        store.set("finnhub:global", time.time() + 300)
        assert store.in_cooldown("finnhub:global") is True

    def test_expired_cooldown_returns_false(self):
        store = _ProviderCooldownStore()
        store._store["k"] = time.time() - 1
        assert store.in_cooldown("k") is False

    def test_expired_entry_removed_from_store(self):
        store = _ProviderCooldownStore()
        store._store["k"] = time.time() - 1
        store.in_cooldown("k")
        assert "k" not in store._store

    def test_exactly_at_expiry_is_not_in_cooldown(self):
        store = _ProviderCooldownStore()
        store._store["k"] = time.time() - 0.001
        assert store.in_cooldown("k") is False


# ===========================================================================
# set
# ===========================================================================


class TestSet:
    def test_set_adds_entry(self):
        store = _ProviderCooldownStore()
        store.set("yfinance:AAPL", time.time() + 60)
        assert len(store) == 1

    def test_set_overwrites_existing_key(self):
        store = _ProviderCooldownStore()
        store.set("k", time.time() + 60)
        later = time.time() + 120
        store.set("k", later)
        assert store._store["k"] == later
        assert len(store) == 1

    def test_set_stores_future_expiry(self):
        store = _ProviderCooldownStore()
        before = time.time()
        store.set("k", before + 300)
        assert store._store["k"] > before + 299


# ===========================================================================
# size cap — eviction
# ===========================================================================


class TestSizeCap:
    def test_stale_entries_evicted_first(self):
        store = _ProviderCooldownStore(max_entries=3)
        for i in range(3):
            store._store[f"stale_{i}"] = time.time() - 1
        store.set("fresh", time.time() + 60)
        assert store.in_cooldown("fresh") is True
        assert len(store) == 1

    def test_oldest_evicted_when_no_stale(self):
        store = _ProviderCooldownStore(max_entries=3)
        store.set("first", time.time() + 60)
        store.set("second", time.time() + 60)
        store.set("third", time.time() + 60)
        store.set("fourth", time.time() + 60)
        assert len(store) == 3
        assert store.in_cooldown("first") is False
        assert store.in_cooldown("fourth") is True

    def test_overwriting_existing_key_does_not_evict(self):
        store = _ProviderCooldownStore(max_entries=2)
        store.set("a", time.time() + 60)
        store.set("b", time.time() + 60)
        store.set("a", time.time() + 120)
        assert len(store) == 2
        assert store.in_cooldown("b") is True

    def test_capacity_one_always_holds_latest(self):
        store = _ProviderCooldownStore(max_entries=1)
        for i in range(5):
            store.set(f"k{i}", time.time() + 60)
        assert len(store) == 1
        assert store.in_cooldown("k4") is True


# ===========================================================================
# __len__ and clear
# ===========================================================================


class TestLenAndClear:
    def test_len_reflects_count(self):
        store = _ProviderCooldownStore()
        assert len(store) == 0
        store.set("a", time.time() + 60)
        assert len(store) == 1
        store.set("b", time.time() + 60)
        assert len(store) == 2

    def test_clear_empties_store(self):
        store = _ProviderCooldownStore()
        for i in range(5):
            store.set(f"k{i}", time.time() + 60)
        store.clear()
        assert len(store) == 0

    def test_in_cooldown_after_clear_returns_false(self):
        store = _ProviderCooldownStore()
        store.set("k", time.time() + 60)
        store.clear()
        assert store.in_cooldown("k") is False


# ===========================================================================
# Concurrency
# ===========================================================================


class TestConcurrency:
    def test_concurrent_writers_no_error(self):
        store = _ProviderCooldownStore(max_entries=200)
        errors: list[Exception] = []

        def _writer(prefix: str) -> None:
            try:
                for i in range(60):
                    store.set(f"{prefix}:{i}", time.time() + 60)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(f"t{t}",)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(store) <= 200

    def test_concurrent_reads_and_writes(self):
        store = _ProviderCooldownStore(max_entries=100)
        store.set("shared", time.time() + 60)
        errors: list[Exception] = []

        def _reader() -> None:
            try:
                for _ in range(100):
                    store.in_cooldown("shared")
            except Exception as exc:
                errors.append(exc)

        def _writer() -> None:
            try:
                for i in range(100):
                    store.set("shared", time.time() + 60 + i)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_reader) for _ in range(3)]
        threads += [threading.Thread(target=_writer) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ===========================================================================
# Integration — module-level helper functions
# ===========================================================================


class TestIntegration:
    def test_provider_in_cooldown_false_for_unknown_key(self):
        assert _provider_in_cooldown("yfinance:TSLA") is False

    def test_mark_provider_cooldown_sets_active_cooldown(self):
        _mark_provider_cooldown("finnhub:global", 429)
        assert _provider_in_cooldown("finnhub:global") is True

    def test_mark_provider_cooldown_unknown_status_no_effect(self):
        _mark_provider_cooldown("pmp:global", 200)
        assert _provider_in_cooldown("pmp:global") is False

    def test_mark_provider_cooldown_none_status_no_effect(self):
        _mark_provider_cooldown("finnhub:global", None)
        assert _provider_in_cooldown("finnhub:global") is False

    def test_mark_provider_cooldown_for_duration_sets_cooldown(self):
        _mark_provider_cooldown_for_duration("yfinance:AAPL", 300)
        assert _provider_in_cooldown("yfinance:AAPL") is True

    def test_mark_provider_cooldown_for_duration_zero_no_effect(self):
        _mark_provider_cooldown_for_duration("yfinance:AAPL", 0)
        assert _provider_in_cooldown("yfinance:AAPL") is False

    def test_mark_provider_cooldown_for_duration_negative_no_effect(self):
        _mark_provider_cooldown_for_duration("yfinance:AAPL", -5)
        assert _provider_in_cooldown("yfinance:AAPL") is False

    def test_module_store_bounded_at_configured_max(self):
        _PROVIDER_COOLDOWNS._max = 5
        for i in range(10):
            _mark_provider_cooldown_for_duration(f"yfinance:SYM{i}", 60)
        assert len(_PROVIDER_COOLDOWNS) <= 5

    def test_known_status_codes_all_set_cooldown(self):
        for code in (401, 402, 403, 404, 429):
            _PROVIDER_COOLDOWNS.clear()
            _mark_provider_cooldown(f"provider:{code}", code)
            assert _provider_in_cooldown(f"provider:{code}") is True
