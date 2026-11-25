"""Hardware detection and automatic tier selection for NEXUS."""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from nexus.core.config import Tier

log = logging.getLogger("nexus.core.hardware")


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


@dataclass(frozen=True)
class HardwareInfo:
    ram_total_mb: int
    ram_free_mb: int
    cpu_cores: int
    gpu_detected: bool
    gpu_name: str


def _read_windows_memory() -> tuple[int, int] | None:
    """Read total and available RAM in MB on Windows via GlobalMemoryStatusEx."""
    if sys.platform != "win32":
        return None
    try:
        kernel32 = getattr(getattr(ctypes, "windll", None), "kernel32", None)
        if kernel32 is None:
            return None
        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) and status.ullTotalPhys > 0:
            return (
                int(status.ullTotalPhys // (1024 * 1024)),
                int(status.ullAvailPhys // (1024 * 1024)),
            )
    except Exception as exc:
        log.debug("GlobalMemoryStatusEx failed: %s", exc)
    return None


def _read_meminfo() -> tuple[int, int]:
    """Read total and available RAM in MB across Linux, Windows, and macOS/BSD."""
    total_kb = 0
    free_kb = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            mem_free_fallback = 0
            for line in f:
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    free_kb = int(line.split()[1])
                elif line.startswith("MemFree:"):
                    mem_free_fallback = int(line.split()[1])
            if total_kb > 0 and free_kb == 0:
                free_kb = mem_free_fallback
    except (FileNotFoundError, PermissionError, ValueError):
        total_kb = 0
        free_kb = 0

    if total_kb > 0:
        return total_kb // 1024, free_kb // 1024

    # Windows native Win32 API
    win_mem = _read_windows_memory()
    if win_mem is not None:
        return win_mem

    # POSIX sysconf — only accept if BOTH SC_PHYS_PAGES and SC_AVPHYS_PAGES succeed
    if hasattr(os, "sysconf"):
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            phys_pages = int(os.sysconf("SC_PHYS_PAGES"))
            avail_pages = int(os.sysconf("SC_AVPHYS_PAGES"))
            if page_size > 0 and phys_pages > 0 and avail_pages >= 0:
                return (phys_pages * page_size) // (1024 * 1024), (avail_pages * page_size) // (1024 * 1024)
        except (ValueError, OSError):
            pass

    # Cross-platform fallback via psutil (macOS/BSD/containers)
    try:
        import psutil

        mem = psutil.virtual_memory()
        if mem.total > 0:
            return int(mem.total // (1024 * 1024)), int(mem.available // (1024 * 1024))
    except ImportError:
        pass

    log.warning("Could not detect host RAM; assuming 4096MB total / 2048MB free.")
    return 4096, 2048


def _count_cpus() -> int:
    count = os.cpu_count()
    return count if count else 2


def _detect_gpu() -> tuple[bool, str]:
    if not shutil.which("nvidia-smi"):
        return False, "None"
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        name = out.strip().split("\n")[0].strip()
        return bool(name), name or "Unknown NVIDIA"
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False, "None"


def detect_hardware() -> HardwareInfo:
    """Detect current hardware capabilities."""
    ram_total, ram_free = _read_meminfo()
    cpu_cores = _count_cpus()
    gpu_detected, gpu_name = _detect_gpu()
    return HardwareInfo(
        ram_total_mb=ram_total,
        ram_free_mb=ram_free,
        cpu_cores=cpu_cores,
        gpu_detected=gpu_detected,
        gpu_name=gpu_name,
    )


def auto_select_tier(hw: HardwareInfo) -> Tier:
    """Select the best resource tier based on available RAM.

    Thresholds (free RAM):
        FULL:     >=12000 MB
        STANDARD: >=6000 MB
        LIGHT:    >=2500 MB
        MINIMAL:  anything below
    """
    free = hw.ram_free_mb
    if free >= 12_000:
        return Tier.FULL
    if free >= 6_000:
        return Tier.STANDARD
    if free >= 2_500:
        return Tier.LIGHT
    return Tier.MINIMAL


def tier_description(tier: Tier) -> str:
    descs = {
        Tier.MINIMAL: "Expert System only (no AI) — ~550MB",
        Tier.LIGHT: "Expert System + Qwen 2.5 0.5B — ~950MB",
        Tier.STANDARD: "Expert System + dolphin-mistral 7B — ~5GB",
        Tier.FULL: "Expert System + WhiteRabbitNeo 13B — ~8.5GB",
    }
    return descs.get(tier, "Unknown tier")
