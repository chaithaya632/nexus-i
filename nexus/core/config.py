"""NEXUS configuration system — YAML + env vars + Pydantic."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class Tier(str, Enum):
    MINIMAL = "minimal"
    LIGHT = "light"
    STANDARD = "standard"
    FULL = "full"


class StealthLevel(str, Enum):
    OFF = "off"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class ScanProfile(str, Enum):
    QUICK = "quick"
    WEB = "web"
    NETWORK = "network"
    API = "api"
    FULL = "full"


# Behavior flags per ScanProfile (kept lightweight & explicit)
SCAN_PROFILE_SETTINGS: dict[str, dict[str, Any]] = {
    "quick": {
        "use_amass": False, "run_osint": False, "run_waf": False,
        "run_crawl": False, "run_headers": True,
        "run_nuclei": True, "targeted_nuclei": True,
        "run_ffuf": False, "run_nikto": False,
        "run_tls": True, "run_ssh": True,
    },
    "web": {
        "use_amass": True, "run_osint": False, "run_waf": True,
        "run_crawl": True, "run_headers": True,
        "run_nuclei": True, "targeted_nuclei": True,
        "run_ffuf": True, "ffuf_wordlist": "common", "run_nikto": True,
        "run_tls": True, "run_ssh": False,
    },
    "network": {
        "use_amass": False, "run_osint": True, "run_waf": False,
        "run_crawl": False, "run_headers": False,
        "run_nuclei": False, "targeted_nuclei": False,
        "run_ffuf": False, "run_nikto": False,
        "run_tls": True, "run_ssh": True,
    },
    "api": {
        "use_amass": False, "run_osint": False, "run_waf": True,
        "run_crawl": True, "run_headers": True,
        "run_nuclei": True, "targeted_nuclei": True,
        "run_ffuf": True, "ffuf_wordlist": "api", "run_nikto": False,
        "run_tls": True, "run_ssh": False,
    },
    "full": {
        "use_amass": True, "run_osint": True, "run_waf": True,
        "run_crawl": True, "run_headers": True,
        "run_nuclei": True, "targeted_nuclei": False,
        "run_ffuf": True, "ffuf_wordlist": "common", "run_nikto": True,
        "run_tls": True, "run_ssh": True,
    },
}


class NexusConfig(BaseModel):
    """Central configuration for NEXUS."""

    data_dir: Path = Field(default_factory=lambda: Path.home() / ".nexus")
    db_path: Path = Field(default_factory=lambda: Path.home() / ".nexus" / "nexus.db")
    scope_file: Path | None = None
    stealth: StealthLevel = StealthLevel.MEDIUM
    tier: Tier = Tier.MINIMAL
    profile: ScanProfile = ScanProfile.FULL
    auth_headers: dict[str, str] = Field(default_factory=dict, exclude=True)
    openapi_spec: Path | None = None
    ignore_file: Path | None = None
    ollama_host: str = "http://127.0.0.1:11434"
    model_name: str = "dolphin-mistral"
    max_threads: int = 5
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "nexus_output")
    api_keys: dict[str, str] = Field(default_factory=dict)
    knowledge_dir: Path | None = None

    def model_post_init(self, __context: Any) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.knowledge_dir is None:
            # Default: bundled knowledge inside the package
            self.knowledge_dir = Path(__file__).resolve().parent.parent / "brain" / "knowledge"

    def save(self, path: Path | None = None) -> Path:
        dest = path or (self.data_dir / "config.yaml")
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        # Convert Path objects to strings for YAML
        for key in ("data_dir", "db_path", "scope_file", "openapi_spec", "ignore_file", "output_dir", "knowledge_dir"):
            if data.get(key) is not None:
                data[key] = str(data[key])
        dest.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
        return dest

    @classmethod
    def load(cls, path: Path | None = None) -> "NexusConfig":
        """Load config from YAML file, then overlay environment variables."""
        default_path = Path.home() / ".nexus" / "config.yaml"
        cfg_path = path or default_path

        data: dict[str, Any] = {}
        if cfg_path.is_file():
            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data = raw

        # Environment variable overrides (NEXUS_ prefix)
        env_map = {
            "NEXUS_DATA_DIR": "data_dir",
            "NEXUS_DB_PATH": "db_path",
            "NEXUS_STEALTH": "stealth",
            "NEXUS_TIER": "tier",
            "NEXUS_OLLAMA_HOST": "ollama_host",
            "NEXUS_MODEL": "model_name",
            "NEXUS_MAX_THREADS": "max_threads",
            "NEXUS_OUTPUT_DIR": "output_dir",
        }
        for env_key, cfg_key in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                data[cfg_key] = val

        return cls(**data)


# Singleton access
_config: NexusConfig | None = None


def get_config() -> NexusConfig:
    global _config
    if _config is None:
        _config = NexusConfig.load()
    return _config


def set_config(config: NexusConfig) -> None:
    global _config
    _config = config
