"""Tests for the stealth controller."""

import asyncio
import pytest

from nexus.stealth.controller import (
    PROFILES,
    StealthController,
    get_active_stealth,
    set_active_stealth,
)


def test_default_profile():
    sc = StealthController()
    assert sc.level == "normal"
    assert sc.profile.max_concurrent == 25


def test_ghost_profile():
    sc = StealthController("ghost")
    assert sc.level == "ghost"
    assert sc.profile.max_concurrent == 3
    assert sc.profile.jitter is True
    assert sc.profile.rotate_user_agent is True
    assert sc.profile.randomize_order is True


def test_loud_profile():
    sc = StealthController("loud")
    assert sc.level == "loud"
    assert sc.profile.jitter is False
    assert sc.profile.delay_max_s == 0.0


def test_set_level():
    sc = StealthController("normal")
    sc.set_level("ghost")
    assert sc.level == "ghost"


def test_get_user_agent():
    sc = StealthController("normal")
    ua = sc.get_user_agent()
    assert "Mozilla" in ua


def test_get_delay_loud():
    sc = StealthController("loud")
    assert sc.get_delay() == 0.0


def test_get_delay_ghost_nonzero():
    sc = StealthController("ghost")
    delay = sc.get_delay()
    assert delay >= 2.0


def test_shuffle_targets_ghost():
    sc = StealthController("ghost")
    targets = list(range(100))
    shuffled = sc.shuffle_targets(targets)
    # Should be a different order (with overwhelming probability)
    assert len(shuffled) == 100
    # Loud mode should NOT shuffle
    sc2 = StealthController("loud")
    not_shuffled = sc2.shuffle_targets(targets)
    assert not_shuffled == targets


def test_tool_args():
    sc = StealthController("quiet")
    args = sc.tool_args("nmap")
    assert args["stealth"] == "quiet"
    assert args["max_concurrent"] == 10
    assert "user_agent" in args


def test_stats():
    sc = StealthController()
    stats = sc.stats()
    assert stats["level"] == "normal"
    assert stats["requests_sent"] == 0


@pytest.mark.asyncio
async def test_throttle():
    sc = StealthController("loud")
    await sc.throttle()
    assert sc.request_count == 1


def test_all_profiles_exist():
    for level in ("loud", "normal", "quiet", "ghost"):
        assert level in PROFILES


def test_unknown_level_warns_and_falls_back(caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="nexus.stealth.controller"):
        sc = StealthController("nonexistent")
    assert sc.level == "normal"
    assert any("Unknown stealth level" in r.message for r in caplog.records)


def test_active_stealth_registry():
    prev = get_active_stealth()
    try:
        sc = StealthController("quiet")
        set_active_stealth(sc)
        assert get_active_stealth() is sc
        set_active_stealth(None)
        assert get_active_stealth() is None
    finally:
        set_active_stealth(prev)


@pytest.mark.asyncio
async def test_concurrent_throttle_reserves_slots_atomically():
    sc = StealthController("ghost")  # 2 rps -> 0.5s interval, test fast with custom profile
    sc._profile.requests_per_second = 100.0
    sc._profile.jitter = False

    await asyncio.gather(*(sc.throttle() for _ in range(5)))
    assert sc.request_count == 5


@pytest.mark.asyncio
async def test_set_level_preserves_inflight_permits():
    sc = StealthController("ghost")  # max_concurrent = 3
    await sc.acquire()
    await sc.acquire()
    assert sc._active_concurrent == 2

    # Changing level mid-flight must not lose/corrupt in-flight permits
    sc.set_level("loud")  # max_concurrent = 50
    await sc.acquire()
    assert sc._active_concurrent == 3
    sc.release()
    sc.release()
    sc.release()
    assert sc._active_concurrent == 0
