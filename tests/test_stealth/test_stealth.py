"""Tests for the stealth controller."""

import asyncio
import pytest

from nexus.stealth.controller import StealthController, PROFILES


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
