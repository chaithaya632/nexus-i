"""Tests for nexus.core.audit."""

import asyncio
import json
import threading
import warnings
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.core.audit import AuditLogger
from nexus.core.scheduler import TaskScheduler, TaskStatus


class TestAuditLogger:
    def test_log_and_verify(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("test_action", target="10.0.0.1", tool="nmap", result="success")
        audit.log_action("second_action", target="10.0.0.2", tool="nuclei")

        valid, count = audit.verify_chain()
        assert valid
        assert count == 2

    def test_chain_integrity(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("action_1")
        audit.log_action("action_2")
        audit.log_action("action_3")

        valid, count = audit.verify_chain()
        assert valid
        assert count == 3

    def test_tampered_log_detected(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("real_action")
        audit.log_action("real_action_2")

        # Tamper with the first line
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["action"] = "tampered"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, count = audit.verify_chain()
        assert not valid

    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        valid, count = audit.verify_chain()
        assert valid
        assert count == 0

    def test_extra_data(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        audit.log_action("test", extra={"key": "value", "count": 42})

        line = log_path.read_text(encoding="utf-8").strip()
        entry = json.loads(line)
        assert entry["extra"]["key"] == "value"
        assert entry["extra"]["count"] == 42

        valid, count = audit.verify_chain()
        assert valid
        assert count == 1

    def test_cross_instance_chain_continuity(self, tmp_path):
        """Simulates separate CLI processes writing to the same audit log.

        Each new AuditLogger instance must pick up the last hash from disk,
        not start a fresh genesis chain.
        """
        log_path = tmp_path / "audit.jsonl"

        # Instance 1 writes two entries
        audit1 = AuditLogger(log_path)
        audit1.log_action("boot", tool="nexus")
        audit1.log_action("recon_start", target="10.0.0.1")

        # Instance 2 (new process) must continue the chain
        audit2 = AuditLogger(log_path)
        audit2.log_action("scan_start", target="10.0.0.1")
        audit2.log_action("shutdown", tool="nexus")

        # Instance 3 for good measure
        audit3 = AuditLogger(log_path)
        audit3.log_action("boot", tool="nexus")

        # The entire 5-entry chain must verify cleanly
        verifier = AuditLogger(log_path)
        valid, count = verifier.verify_chain()
        assert valid, "Cross-instance chain is broken"
        assert count == 5

    def test_single_entry_file(self, tmp_path):
        """Edge case: file has exactly one entry — new instance must chain from it."""
        log_path = tmp_path / "audit.jsonl"

        audit1 = AuditLogger(log_path)
        audit1.log_action("only_entry")

        audit2 = AuditLogger(log_path)
        audit2.log_action("second_entry")

        valid, count = audit2.verify_chain()
        assert valid
        assert count == 2

    def test_concurrent_log_action_thread_safety(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                for i in range(25):
                    audit.log_action("thread_event", target=f"10.0.0.{tid}", extra={"i": i})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        valid, count = audit.verify_chain()
        assert valid
        assert count == 150

    def test_non_json_extra_types(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        audit.log_action(
            "non_json",
            extra={
                "path": Path("/tmp/report.pdf"),
                "ts": datetime(2026, 1, 1, tzinfo=UTC),
                "tags": {"sqli"},
            },
        )
        valid, count = audit.verify_chain()
        assert valid
        assert count == 1

    def test_corrupted_tail_flagged_not_reset(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit1 = AuditLogger(log_path)
        audit1.log_action("good_entry")

        with open(log_path, "a", encoding="utf-8") as f:
            f.write("{corrupted_json_tail\n")

        audit2 = AuditLogger(log_path)
        assert audit2.corrupted is True
        assert audit2._prev_hash != "0" * 64
        valid, count = audit2.verify_chain()
        assert not valid
        assert count == 1

        # Missing hash field in tail should also flag corruption
        missing_hash_path = tmp_path / "missing_hash.jsonl"
        missing_hash_path.write_text('{"action":"no_hash"}\n', encoding="utf-8")
        audit3 = AuditLogger(missing_hash_path)
        assert audit3.corrupted is True
        assert audit3._prev_hash != "0" * 64
        assert audit3.verify_chain()[0] is False


class TestTaskScheduler:
    def test_invalid_max_concurrent_raises(self):
        with pytest.raises(ValueError):
            TaskScheduler(max_concurrent=0)
        with pytest.raises(ValueError):
            TaskScheduler(max_concurrent=-3)

    @pytest.mark.asyncio
    async def test_parallel_execution_and_stats(self):
        scheduler = TaskScheduler(max_concurrent=2)
        active = 0
        peak = 0

        async def ok(val):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1
            return val

        async def fail():
            raise RuntimeError("boom")

        results = await scheduler.run_parallel(
            [
                ("t1", ok(1)),
                ("t2", ok(2)),
                ("t3", fail()),
                ("t4", ok(4)),
            ]
        )
        assert peak <= 2
        assert [r.status for r in results] == [
            TaskStatus.COMPLETED,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.COMPLETED,
        ]
        assert scheduler.stats == {"running": 0, "completed": 3, "failed": 1, "total": 4}

    @pytest.mark.asyncio
    async def test_cancellation_resets_running_counter(self):
        scheduler = TaskScheduler(max_concurrent=2)
        started = asyncio.Event()

        async def hang():
            started.set()
            await asyncio.sleep(10)

        task = asyncio.create_task(scheduler.run_parallel([("hang", hang())]))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert scheduler.stats["running"] == 0

    @pytest.mark.asyncio
    async def test_sequential_closes_unawaited_coroutines_on_failure(self):
        scheduler = TaskScheduler()

        async def fail():
            raise RuntimeError("stop")

        async def never_runs():
            return "unused"

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("error", RuntimeWarning)
            results = await scheduler.run_sequential(
                [
                    ("first", fail()),
                    ("second", never_runs()),
                    ("third", never_runs()),
                ]
            )

        assert len(results) == 1
        assert results[0].status == TaskStatus.FAILED
        assert not caught
