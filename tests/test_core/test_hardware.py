"""Tests for cross-platform hardware detection and tier selection."""

from __future__ import annotations

import builtins
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

from nexus.core.config import Tier
from nexus.core.hardware import (
    HardwareInfo,
    _read_meminfo,
    auto_select_tier,
    detect_hardware,
    tier_description,
)


class TestHardwareDetection:
    def test_auto_select_tier_thresholds(self):
        assert auto_select_tier(HardwareInfo(16384, 12000, 8, False, "None")) == Tier.FULL
        assert auto_select_tier(HardwareInfo(8192, 6000, 4, False, "None")) == Tier.STANDARD
        assert auto_select_tier(HardwareInfo(4096, 2500, 2, False, "None")) == Tier.LIGHT
        assert auto_select_tier(HardwareInfo(2048, 2499, 2, False, "None")) == Tier.MINIMAL

    def test_tier_description_all_tiers(self):
        for tier in Tier:
            desc = tier_description(tier)
            assert isinstance(desc, str) and len(desc) > 5

    def test_detect_hardware_returns_valid_info(self):
        hw = detect_hardware()
        assert hw.ram_total_mb > 0
        assert hw.ram_free_mb >= 0
        assert hw.cpu_cores >= 1

    def test_windows_memory_detection(self):
        with (
            patch.object(builtins, "open", side_effect=FileNotFoundError),
            patch("nexus.core.hardware._read_windows_memory", return_value=(16384, 8192)),
        ):
            total, free = _read_meminfo()
        assert (total, free) == (16384, 8192)

    def test_macos_bsd_sysconf_partial_failure_falls_through_to_psutil(self):
        def fake_sysconf(name: str) -> int:
            if name == "SC_PAGE_SIZE":
                return 4096
            if name == "SC_PHYS_PAGES":
                return 2 * 1024 * 1024  # 8 GB
            raise ValueError("SC_AVPHYS_PAGES unsupported on macOS")

        fake_psutil = SimpleNamespace(
            virtual_memory=lambda: SimpleNamespace(
                total=8 * 1024 * 1024 * 1024,
                available=5 * 1024 * 1024 * 1024,
            )
        )
        with (
            patch.object(builtins, "open", side_effect=FileNotFoundError),
            patch("nexus.core.hardware._read_windows_memory", return_value=None),
            patch.object(os, "sysconf", fake_sysconf, create=True),
            patch.dict(sys.modules, {"psutil": fake_psutil}),
        ):
            total, free = _read_meminfo()
        assert total == 8192
        assert free == 5120
