"""Tests for nexus.core.config."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from nexus.core.config import (
    NexusConfig,
    SCAN_PROFILE_SETTINGS,
    ScanProfile,
    Tier,
    StealthLevel,
    get_config,
    set_config,
)


class TestNexusConfig:
    def test_default_config(self, tmp_path):
        cfg = NexusConfig(data_dir=tmp_path, db_path=tmp_path / "test.db",
                          output_dir=tmp_path / "output")
        assert cfg.tier == Tier.MINIMAL
        assert cfg.stealth == StealthLevel.MEDIUM
        assert cfg.max_threads == 5
        assert cfg.ollama_host == "http://127.0.0.1:11434"

    def test_save_and_load(self, tmp_path):
        cfg = NexusConfig(
            data_dir=tmp_path,
            db_path=tmp_path / "test.db",
            output_dir=tmp_path / "output",
            tier=Tier.LIGHT,
            stealth=StealthLevel.HIGH,
            max_threads=10,
        )
        saved_path = cfg.save(tmp_path / "config.yaml")
        assert saved_path.is_file()

        loaded = NexusConfig.load(saved_path)
        assert loaded.tier == Tier.LIGHT
        assert loaded.stealth == StealthLevel.HIGH
        assert loaded.max_threads == 10

    def test_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NEXUS_TIER", "full")
        monkeypatch.setenv("NEXUS_MAX_THREADS", "20")
        # Load from non-existent file so only env vars apply
        cfg = NexusConfig.load(tmp_path / "nonexistent.yaml")
        assert cfg.tier == Tier.FULL
        assert cfg.max_threads == 20

    def test_singleton(self, tmp_path):
        cfg = NexusConfig(data_dir=tmp_path, db_path=tmp_path / "test.db",
                          output_dir=tmp_path / "output", tier=Tier.STANDARD)
        set_config(cfg)
        retrieved = get_config()
        assert retrieved.tier == Tier.STANDARD
        # Reset singleton
        set_config(None)

    def test_tiers(self):
        assert Tier.MINIMAL.value == "minimal"
        assert Tier.FULL.value == "full"

    def test_stealth_levels(self):
        assert StealthLevel.PARANOID.value == "paranoid"
        assert StealthLevel.OFF.value == "off"

    def test_scan_profiles(self):
        assert set(SCAN_PROFILE_SETTINGS.keys()) == {p.value for p in ScanProfile}
        assert SCAN_PROFILE_SETTINGS[ScanProfile.NETWORK.value]["run_nuclei"] is False
        assert SCAN_PROFILE_SETTINGS[ScanProfile.NETWORK.value]["run_tls"] is True
        assert SCAN_PROFILE_SETTINGS[ScanProfile.NETWORK.value]["run_crawl"] is False
        assert SCAN_PROFILE_SETTINGS[ScanProfile.API.value]["ffuf_wordlist"] == "api"
        assert SCAN_PROFILE_SETTINGS[ScanProfile.WEB.value]["run_crawl"] is True

    def test_auth_headers_excluded_from_saved_config(self, tmp_path):
        cfg = NexusConfig(
            data_dir=tmp_path,
            db_path=tmp_path / "test.db",
            output_dir=tmp_path / "output",
            auth_headers={"Authorization": "Bearer sensitive_token"},
            wpscan_api_token="wp_secret_token_val",
            dashboard_token="dash_secret_tok_val",
            api_keys={"wpscan": "wp_map_secret"},
            openapi_spec=tmp_path / "spec.yaml",
        )
        saved_path = cfg.save(tmp_path / "cfg.yaml")
        raw = saved_path.read_text(encoding="utf-8")
        loaded_dict = yaml.safe_load(raw)
        assert "sensitive_token" not in raw
        assert "wp_secret_token_val" not in raw
        assert "dash_secret_tok_val" not in raw
        assert "wp_map_secret" not in raw
        assert "dash_secret_tok_val" not in repr(cfg)
        assert "auth_headers" not in loaded_dict
        assert "wpscan_api_token" not in loaded_dict
        assert "dashboard_token" not in loaded_dict
        assert "api_keys" not in loaded_dict
        assert "openapi_spec" in loaded_dict
