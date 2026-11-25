"""Async parallel task scheduler for NEXUS tool orchestration."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TaskStatus(StrEnum):
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


def _close_unawaited(awaitable: Awaitable[Any]) -> None:
    """Close an unstarted coroutine so skipped/cancelled tasks don't emit warnings."""
    if (
        inspect.iscoroutine(awaitable)
        and inspect.getcoroutinestate(awaitable) == inspect.CORO_CREATED
    ):
        awaitable.close()


@dataclass
class TaskScheduler:
    """Manages concurrent and sequential async task execution."""

    max_concurrent: int = 5
    _results: list[TaskResult] = field(default_factory=list, init=False)
    _running: int = 0
    _completed: int = 0
    _failed: int = 0

    def __post_init__(self) -> None:
        if self.max_concurrent < 1:
            raise ValueError(f"max_concurrent must be >= 1, got {self.max_concurrent}")

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
        try:
            async with semaphore:
                self._running += 1
                start = time.monotonic()
                try:
                    result = await coro
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    duration = time.monotonic() - start
                    self._failed += 1
                    tr = TaskResult(
                        name=name,
                        status=TaskStatus.FAILED,
                        error=str(exc),
                        duration_s=round(duration, 2),
                    )
                else:
                    duration = time.monotonic() - start
                    self._completed += 1
                    tr = TaskResult(
                        name=name,
                        status=TaskStatus.COMPLETED,
                        result=result,
                        duration_s=round(duration, 2),
                    )
                finally:
                    self._running -= 1
                self._results.append(tr)
                return tr
        except asyncio.CancelledError:
            _close_unawaited(coro)
            raise

    async def run_parallel(self, tasks: list[tuple[str, Awaitable[Any]]]) -> list[TaskResult]:
        """Run tasks concurrently up to max_concurrent."""
        sem = asyncio.Semaphore(self.max_concurrent)
        coros = [self._run_one(name, coro, sem) for name, coro in tasks]
        return await asyncio.gather(*coros)

    async def run_sequential(self, tasks: list[tuple[str, Awaitable[Any]]]) -> list[TaskResult]:
        """Run tasks one after another, stopping on first failure."""
        sem = asyncio.Semaphore(1)
        results: list[TaskResult] = []
        failed = False
        for idx, (name, coro) in enumerate(tasks):
            if failed:
                _close_unawaited(coro)
                continue
            try:
                tr = await self._run_one(name, coro, sem)
            except BaseException:
                for _, rem_coro in tasks[idx + 1 :]:
                    _close_unawaited(rem_coro)
                raise
            results.append(tr)
            if tr.status == TaskStatus.FAILED:
                failed = True
        return results

    def reset(self) -> None:
        self._results.clear()
        self._running = 0
        self._completed = 0
        self._failed = 0
