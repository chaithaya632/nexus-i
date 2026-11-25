"""Hardware detection and automatic tier selection for NEXUS."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from nexus.core.config import Tier


@dataclass(frozen=True)
class HardwareInfo:
    ram_total_mb: int
    ram_free_mb: int
    cpu_cores: int
    gpu_detected: bool
    gpu_name: str


def _read_meminfo() -> tuple[int, int]:
    """Read total and free RAM from /proc/meminfo (Linux only)."""
    total_kb = 0
    free_kb = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    free_kb = int(line.split()[1])
    except (FileNotFoundError, PermissionError, ValueError):
        # Fallback 1: os.sysconf (Linux without /proc)
        if hasattr(os, "sysconf"):
            try:
                page_size = os.sysconf("SC_PAGE_SIZE")
                total_kb = (os.sysconf("SC_PHYS_PAGES") * page_size) // 1024
                free_kb = (os.sysconf("SC_AVPHYS_PAGES") * page_size) // 1024
            except (ValueError, OSError):
                pass
        # Fallback 2: psutil or Windows WMI (dev/testing on non-Linux)
        if total_kb == 0:
            try:
                import psutil
                mem = psutil.virtual_memory()
                total_kb = mem.total // 1024
                free_kb = mem.available // 1024
            except ImportError:
                # Last resort: assume 4GB (safe default for VM detection)
                total_kb = 4 * 1024 * 1024
                free_kb = 2 * 1024 * 1024
    return total_kb // 1024, free_kb // 1024


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
