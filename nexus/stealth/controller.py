"""Stealth controller — rate limiting, timing jitter, and evasion profiles.

Controls how aggressively NEXUS interacts with targets based on the
configured stealth level.  Every tool wrapper consults this controller
before sending requests.
"""

from __future__ import annotations

import asyncio
from collections import deque
import logging
import random
import time
from dataclasses import dataclass
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
        self._profile = self._resolve_profile(level)
        self._throttle_lock = asyncio.Lock()
        self._active_concurrent: int = 0
        self._waiters: deque[asyncio.Future[None]] = deque()
        self._last_request_time: float = 0.0
        self._request_count: int = 0

    @staticmethod
    def _resolve_profile(level: str) -> StealthProfile:
        if level not in PROFILES:
            log.warning("Unknown stealth level %r; falling back to 'normal'", level)
            return PROFILES["normal"]
        return PROFILES[level]

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
        """Change stealth level at runtime without breaking in-flight permits."""
        self._profile = self._resolve_profile(level)
        self._wake_waiters()
        log.info("Stealth level changed to: %s", self._profile.name)

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
        rps = self._profile.requests_per_second
        if rps <= 0:
            return

        min_interval = 1.0 / rps
        jitter_enabled = self._profile.jitter
        async with self._throttle_lock:
            now = time.monotonic()
            next_slot = self._last_request_time + min_interval
            if now < next_slot:
                wait = next_slot - now
                if jitter_enabled:
                    wait += random.uniform(0, min_interval * 0.3)
                reserved = now + wait
            else:
                wait = 0.0
                reserved = now
            self._last_request_time = reserved
            self._request_count += 1

        if wait > 0:
            await asyncio.sleep(wait)

    def _wake_waiters(self) -> None:
        """Wake the next queued waiter if concurrency capacity is available."""
        if self._active_concurrent >= self._profile.max_concurrent:
            return
        while self._waiters:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)
                break

    async def acquire(self) -> None:
        """Acquire a concurrency slot, safe across runtime level changes."""
        while self._active_concurrent >= self._profile.max_concurrent:
            fut = asyncio.get_running_loop().create_future()
            self._waiters.append(fut)
            try:
                await fut
            except BaseException:
                try:
                    self._waiters.remove(fut)
                except ValueError:
                    pass
                if fut.done() and not fut.cancelled():
                    self._wake_waiters()
                raise
        self._active_concurrent += 1
        self._wake_waiters()

    def release(self) -> None:
        """Release a concurrency slot."""
        if self._active_concurrent > 0:
            self._active_concurrent -= 1
        self._wake_waiters()

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


_active_stealth: StealthController | None = None


def get_active_stealth() -> StealthController | None:
    """Return the active process-wide StealthController, if registered."""
    return _active_stealth


def set_active_stealth(ctrl: StealthController | None) -> None:
    """Register or clear the active StealthController."""
    global _active_stealth
    _active_stealth = ctrl
