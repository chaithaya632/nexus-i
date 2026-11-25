"""Async parallel task scheduler for NEXUS tool orchestration."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    name: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    duration_s: float = 0.0


@dataclass
class TaskScheduler:
    """Manages concurrent and sequential async task execution."""

    max_concurrent: int = 5
    _results: list[TaskResult] = field(default_factory=list, init=False)
    _running: int = 0
    _completed: int = 0
    _failed: int = 0

    @property
    def stats(self) -> dict[str, int]:
        return {
            "running": self._running,
            "completed": self._completed,
            "failed": self._failed,
            "total": len(self._results),
        }

    async def _run_one(
        self, name: str, coro: Awaitable[Any], semaphore: asyncio.Semaphore
    ) -> TaskResult:
        async with semaphore:
            self._running += 1
            start = time.monotonic()
            try:
                result = await coro
                duration = time.monotonic() - start
                self._running -= 1
                self._completed += 1
                tr = TaskResult(
                    name=name,
                    status=TaskStatus.COMPLETED,
                    result=result,
                    duration_s=round(duration, 2),
                )
            except Exception as exc:
                duration = time.monotonic() - start
                self._running -= 1
                self._failed += 1
                tr = TaskResult(
                    name=name,
                    status=TaskStatus.FAILED,
                    error=str(exc),
                    duration_s=round(duration, 2),
                )
            self._results.append(tr)
            return tr

    async def run_parallel(
        self, tasks: list[tuple[str, Awaitable[Any]]]
    ) -> list[TaskResult]:
        """Run tasks concurrently up to max_concurrent."""
        sem = asyncio.Semaphore(self.max_concurrent)
        coros = [self._run_one(name, coro, sem) for name, coro in tasks]
        return await asyncio.gather(*coros)

    async def run_sequential(
        self, tasks: list[tuple[str, Awaitable[Any]]]
    ) -> list[TaskResult]:
        """Run tasks one after another, stopping on first failure."""
        sem = asyncio.Semaphore(1)
        results: list[TaskResult] = []
        for name, coro in tasks:
            tr = await self._run_one(name, coro, sem)
            results.append(tr)
            if tr.status == TaskStatus.FAILED:
                break
        return results

    def reset(self) -> None:
        self._results.clear()
        self._running = 0
        self._completed = 0
        self._failed = 0
