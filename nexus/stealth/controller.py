"""Stealth controller — rate limiting, timing jitter, and evasion profiles.

Controls how aggressively NEXUS interacts with targets based on the
configured stealth level.  Every tool wrapper consults this controller
before sending requests.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("nexus.stealth.controller")

# User-agent pool for rotation
_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


@dataclass
class StealthProfile:
    """Per-level tuning knobs."""

    name: str
    max_concurrent: int
    requests_per_second: float
    delay_min_s: float
    delay_max_s: float
    jitter: bool
    rotate_user_agent: bool
    randomize_order: bool
    tcp_connect_timeout: float
    max_retries: int


# Predefined profiles matching the 4 stealth levels
PROFILES: dict[str, StealthProfile] = {
    "loud": StealthProfile(
        name="loud",
        max_concurrent=50,
        requests_per_second=200.0,
        delay_min_s=0.0,
        delay_max_s=0.0,
        jitter=False,
        rotate_user_agent=False,
        randomize_order=False,
        tcp_connect_timeout=5.0,
        max_retries=3,
    ),
    "normal": StealthProfile(
        name="normal",
        max_concurrent=25,
        requests_per_second=50.0,
        delay_min_s=0.05,
        delay_max_s=0.2,
        jitter=True,
        rotate_user_agent=True,
        randomize_order=False,
        tcp_connect_timeout=10.0,
        max_retries=2,
    ),
    "quiet": StealthProfile(
        name="quiet",
        max_concurrent=10,
        requests_per_second=10.0,
        delay_min_s=0.5,
        delay_max_s=2.0,
        jitter=True,
        rotate_user_agent=True,
        randomize_order=True,
        tcp_connect_timeout=15.0,
        max_retries=1,
    ),
    "ghost": StealthProfile(
        name="ghost",
        max_concurrent=3,
        requests_per_second=2.0,
        delay_min_s=2.0,
        delay_max_s=8.0,
        jitter=True,
        rotate_user_agent=True,
        randomize_order=True,
        tcp_connect_timeout=30.0,
        max_retries=1,
    ),
}


class StealthController:
    """Central stealth manager — throttles, jitters, and randomizes tool activity."""

    def __init__(self, level: str = "normal") -> None:
        self._profile = PROFILES.get(level, PROFILES["normal"])
        self._semaphore = asyncio.Semaphore(self._profile.max_concurrent)
        self._last_request_time: float = 0.0
        self._request_count: int = 0

    @property
    def profile(self) -> StealthProfile:
        return self._profile

    @property
    def level(self) -> str:
        return self._profile.name

    @property
    def request_count(self) -> int:
        return self._request_count

    def set_level(self, level: str) -> None:
        """Change stealth level at runtime."""
        self._profile = PROFILES.get(level, PROFILES["normal"])
        self._semaphore = asyncio.Semaphore(self._profile.max_concurrent)
        log.info("Stealth level changed to: %s", level)

    def get_user_agent(self) -> str:
        """Return a user-agent string — rotated if the profile says so."""
        if self._profile.rotate_user_agent:
            return random.choice(_USER_AGENTS)
        return _USER_AGENTS[0]

    def get_delay(self) -> float:
        """Return the delay in seconds to wait before the next request."""
        if self._profile.delay_max_s <= 0:
            return 0.0
        if self._profile.jitter:
            return random.uniform(self._profile.delay_min_s, self._profile.delay_max_s)
        return self._profile.delay_min_s

    def shuffle_targets(self, targets: list[Any]) -> list[Any]:
        """Optionally randomize target order to avoid sequential patterns."""
        if self._profile.randomize_order:
            shuffled = list(targets)
            random.shuffle(shuffled)
            return shuffled
        return targets

    async def throttle(self) -> None:
        """Wait for rate-limit compliance before sending a request."""
        if self._profile.requests_per_second <= 0:
            return

        min_interval = 1.0 / self._profile.requests_per_second
        now = time.monotonic()
        elapsed = now - self._last_request_time

        if elapsed < min_interval:
            wait = min_interval - elapsed
            if self._profile.jitter:
                wait += random.uniform(0, wait * 0.3)
            await asyncio.sleep(wait)

        self._last_request_time = time.monotonic()
        self._request_count += 1

    async def acquire(self) -> None:
        """Acquire the concurrency semaphore."""
        await self._semaphore.acquire()

    def release(self) -> None:
        """Release the concurrency semaphore."""
        self._semaphore.release()

    def tool_args(self, tool: str) -> dict[str, Any]:
        """Return stealth-aware arguments for a specific tool.

        Tools can use this to adjust their own concurrency, timing,
        and user-agent settings.
        """
        return {
            "stealth": self._profile.name,
            "delay_s": self.get_delay(),
            "timeout": self._profile.tcp_connect_timeout,
            "max_retries": self._profile.max_retries,
            "user_agent": self.get_user_agent(),
            "max_concurrent": self._profile.max_concurrent,
        }

    def stats(self) -> dict[str, Any]:
        return {
            "level": self._profile.name,
            "requests_sent": self._request_count,
            "max_concurrent": self._profile.max_concurrent,
            "rps_limit": self._profile.requests_per_second,
        }
