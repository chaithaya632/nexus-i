"""Base async subprocess runner for external Kali tool wrappers.

Every recon/scan/exploit wrapper uses `ToolRunner.run()` to invoke a CLI tool
and capture stdout/stderr.  Stealth-aware rate limiting is applied via the
optional `delay_s` parameter.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("nexus.recon.runner")


class ToolNotFoundError(Exception):
    """Raised when a required CLI tool is missing from $PATH."""


@dataclass
class ToolOutput:
    """Result of a single CLI invocation."""

    tool: str
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float = 0.0
    output_file: str | None = None  # path to any temp output file (-oX, -oJ, etc.)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def lines(self) -> list[str]:
        return [l for l in self.stdout.splitlines() if l.strip()]


class ToolRunner:
    """Async wrapper for subprocess calls to external tools."""

    @staticmethod
    def require(tool_name: str) -> str:
        """Return the full path of *tool_name* or raise ToolNotFoundError."""
        path = shutil.which(tool_name)
        if not path:
            raise ToolNotFoundError(
                f"'{tool_name}' not found in $PATH.  Install it with: "
                f"sudo apt install {tool_name}"
            )
        return path

    @staticmethod
    def is_available(tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    @staticmethod
    async def run(
        tool: str,
        args: list[str],
        *,
        timeout: int = 300,
        delay_s: float = 0.0,
        cwd: str | Path | None = None,
        stdin_data: str | None = None,
    ) -> ToolOutput:
        """Execute *tool* with *args* asynchronously and return captured output."""
        import time

        if delay_s > 0:
            await asyncio.sleep(delay_s)

        cmd = [tool, *args]
        log.debug("Running: %s", " ".join(cmd))

        start = time.monotonic()
        proc: asyncio.subprocess.Process | None = None
        use_pg = os.name == "posix"
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                start_new_session=use_pg,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            await _terminate_process_tree(proc, use_pg=use_pg)
            if isinstance(exc, asyncio.CancelledError):
                raise
            duration = time.monotonic() - start
            log.warning("Tool timed out after %ds: %s", timeout, " ".join(cmd))
            return ToolOutput(
                tool=tool,
                args=args,
                returncode=-1,
                stdout="",
                stderr=f"TIMEOUT after {timeout}s",
                duration_s=round(duration, 2),
            )
        except FileNotFoundError:
            raise ToolNotFoundError(
                f"'{tool}' not found in $PATH.  Install it first."
            )

        duration = time.monotonic() - start
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        log.debug(
            "Finished %s (rc=%d, %.1fs, stdout=%d bytes)",
            tool,
            proc.returncode or 0,
            duration,
            len(stdout),
        )
        return ToolOutput(
            tool=tool,
            args=args,
            returncode=proc.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            duration_s=round(duration, 2),
        )

    @staticmethod
    def make_temp_path(suffix: str = ".xml") -> str:
        """Return a unique temp file path for tool output."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="nexus_")
        os.close(fd)
        return path


async def _terminate_process_tree(
    proc: asyncio.subprocess.Process | None,
    *,
    use_pg: bool = False,
) -> None:
    """Terminate a timed-out/cancelled process and its POSIX process group."""
    if proc is None or proc.returncode is not None:
        return
    try:
        if use_pg:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
        else:
            proc.kill()
        await asyncio.wait_for(proc.wait(), timeout=5)
    except (ProcessLookupError, asyncio.TimeoutError, OSError):
        pass
