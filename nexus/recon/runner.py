"""Base async subprocess runner for external Kali tool wrappers.

Every recon/scan/exploit wrapper uses `ToolRunner.run()` to invoke a CLI tool
and capture stdout/stderr.  Stealth-aware rate limiting is applied via the
optional `delay_s` parameter.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import xml.etree.ElementTree as _StdlibET
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import defusedxml.ElementTree as _DefusedET
except ImportError:  # pragma: no cover - fallback when defusedxml is absent
    _DefusedET = None  # type: ignore[assignment]

log = logging.getLogger("nexus.recon.runner")

_UNSAFE_XML_RE = re.compile(
    r"<!(?:ENTITY|ATTLIST|NOTATION)\b|SYSTEM\s+['\"]|PUBLIC\s+['\"]",
    re.IGNORECASE,
)

_DEFAULT_DENIED_EXTRA_FLAGS = frozenset({
    "-o",
    "-ox",
    "-on",
    "-og",
    "-oa",
    "-oj",
    "-il",
    "-x",
    "--output",
    "--output-dir",
    "--list",
    "--datadir",
    "--stylesheet",
    "--webxml",
    "--resume",
    "--interactive",
    "--shell",
    "--exec",
    "--command",
    "--eval",
    "--os-shell",
    "--os-cmd",
    "--os-pwn",
    "--os-smbrelay",
    "--os-bof",
    "--sql-shell",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--reg-read",
    "--reg-add",
    "--reg-del",
})


def safe_parse_xml(xml_text: str) -> _StdlibET.Element:
    """Parse XML safely using defusedxml when installed, or a strict XXE/entity guard."""
    if _DefusedET is not None:
        try:
            return _DefusedET.fromstring(xml_text)
        except Exception as exc:
            if isinstance(exc, _StdlibET.ParseError):
                raise
            raise _StdlibET.ParseError(str(exc)) from exc
    if _UNSAFE_XML_RE.search(xml_text):
        raise _StdlibET.ParseError("Unsafe XML construct (ENTITY/external DTD) rejected")
    return _StdlibET.fromstring(xml_text)


def validate_cli_target(
    target: str,
    *,
    label: str = "target",
    allow_spaces: bool = False,
) -> str:
    """Validate a CLI target/argument against empty strings, leading '-', and control chars."""
    if not isinstance(target, str):
        raise ValueError(f"Invalid {label}: expected string")
    cleaned = target.strip()
    if not cleaned:
        raise ValueError(f"Invalid {label}: must not be empty")
    if "\x00" in cleaned or "\r" in cleaned or "\n" in cleaned:
        raise ValueError(f"Invalid {label}: contains NUL or CR/LF characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
        raise ValueError(f"Invalid {label}: contains control characters")
    if not allow_spaces and any(c.isspace() for c in cleaned):
        raise ValueError(f"Invalid {label}: must not contain whitespace")
    if cleaned.startswith("-"):
        raise ValueError(f"Invalid {label}: must not start with '-'")
    return cleaned


def sanitize_header_value(value: str, *, name: str = "") -> str:
    """Validate an HTTP header value (and optional name) against CRLF/NUL injection."""
    if not isinstance(value, str):
        raise ValueError("Invalid header value: expected string")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("Invalid header value: contains NUL or CR/LF characters")
    if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
        raise ValueError("Invalid header value: contains control characters")
    if name:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Invalid header name: must not be empty")
        if "\x00" in name or "\r" in name or "\n" in name or ":" in name:
            raise ValueError("Invalid header name: contains illegal characters")
        if any(ord(c) <= 32 or ord(c) == 127 for c in name.strip()):
            raise ValueError("Invalid header name: contains whitespace or control characters")
        if name.strip().startswith("-"):
            raise ValueError("Invalid header name: must not start with '-'")
    return value.strip()


def validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Validate a mapping of HTTP headers against CRLF/NUL/option injection."""
    if not headers:
        return {}
    clean: dict[str, str] = {}
    for k, v in headers.items():
        val = sanitize_header_value(v, name=k)
        clean[k.strip()] = val
    return clean


def validate_extra_args(
    extra_args: list[str] | None,
    *,
    allowed_flags: frozenset[str] | None = None,
    denied_flags: frozenset[str] | None = None,
) -> list[str]:
    """Validate extra CLI args against NUL/CRLF, empty items, and disallowed flags."""
    if not extra_args:
        return []
    denied = denied_flags if denied_flags is not None else _DEFAULT_DENIED_EXTRA_FLAGS
    out: list[str] = []
    for raw in extra_args:
        if not isinstance(raw, str):
            raise ValueError("Invalid extra argument: expected string")
        arg = raw.strip()
        if not arg:
            raise ValueError("Invalid extra argument: empty argument")
        if "\x00" in arg or "\r" in arg or "\n" in arg:
            raise ValueError("Invalid extra argument: contains NUL or CR/LF characters")
        if any(ord(c) < 32 or ord(c) == 127 for c in arg):
            raise ValueError("Invalid extra argument: contains control characters")
        if arg.startswith("-"):
            flag = arg.split("=", 1)[0].lower()
            if allowed_flags is not None and flag not in allowed_flags:
                raise ValueError(f"Disallowed extra CLI flag: {flag}")
            if flag in denied:
                raise ValueError(f"Disallowed extra CLI flag: {flag}")
        out.append(arg)
    return out


def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number is in 1..65535."""
    if isinstance(port, bool):
        raise ValueError(f"Invalid port: {port!r}")
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid port: {port!r}") from exc
    if not (1 <= p <= 65535):
        raise ValueError(f"Port out of range (1-65535): {p}")
    return p


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


_SECRET_NEXT_FLAGS = frozenset({
    "--api-token",
    "--enterprise-db-token",
    "--cookie-string",
    "--cookie",
    "--wp-auth",
    "-p",
    "--data",
    "--password",
    "--passwd",
})
_HEADER_NEXT_FLAGS = frozenset({"--header", "-add-header", "--add-header"})


def _mask_header_value(raw: str) -> str:
    if ":" in raw:
        hdr_name, _ = raw.split(":", 1)
        return f"{hdr_name}: ***"
    return "***"


def _redact_args(args: list[str]) -> list[str]:
    """Return a copy of CLI *args* with credential/token values masked for logs and ToolOutput."""
    out: list[str] = []
    redact_next = False
    redact_header = False
    for arg in args:
        if redact_next:
            out.append("***")
            redact_next = False
            continue
        if redact_header:
            out.append(_mask_header_value(arg))
            redact_header = False
            continue

        low = arg.lower()
        if low in _SECRET_NEXT_FLAGS:
            out.append(arg)
            redact_next = True
        elif any(low.startswith(f + "=") for f in _SECRET_NEXT_FLAGS):
            flag_name = arg.split("=", 1)[0]
            out.append(f"{flag_name}=***")
        elif arg == "-H" or low in _HEADER_NEXT_FLAGS:
            out.append(arg)
            redact_header = True
        elif arg.startswith("-H=") or any(low.startswith(f + "=") for f in _HEADER_NEXT_FLAGS):
            flag_name, val = arg.split("=", 1)
            out.append(f"{flag_name}={_mask_header_value(val)}")
        else:
            out.append(arg)
    return out


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
        safe_args = _redact_args(args)
        safe_cmd = [tool, *safe_args]
        log.debug("Running: %s", " ".join(safe_cmd))

        start = time.monotonic()
        proc: asyncio.subprocess.Process | None = None
        use_pg = os.name == "posix"
        spawn_kwargs: dict[str, Any] = {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "cwd": str(cwd) if cwd else None,
            "stdin": asyncio.subprocess.PIPE if stdin_data else None,
            "start_new_session": use_pg,
        }
        if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            spawn_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                **spawn_kwargs,
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
            log.warning("Tool timed out after %ds: %s", timeout, " ".join(safe_cmd))
            return ToolOutput(
                tool=tool,
                args=safe_args,
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
            args=safe_args,
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
    """Terminate a timed-out/cancelled process and its process group/tree."""
    if proc is None or proc.returncode is not None:
        return
    try:
        if use_pg:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
        elif os.name == "nt":
            killed_tree = False
            try:
                tk = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/T",
                    "/F",
                    "/PID",
                    str(proc.pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(tk.wait(), timeout=5)
                killed_tree = tk.returncode == 0
            except (OSError, asyncio.TimeoutError):
                killed_tree = False
            if not killed_tree and proc.returncode is None:
                proc.kill()
        else:
            proc.kill()
        await asyncio.wait_for(proc.wait(), timeout=5)
    except (ProcessLookupError, asyncio.TimeoutError, OSError):
        pass
