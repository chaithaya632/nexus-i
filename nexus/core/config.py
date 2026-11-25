"""NEXUS configuration system — YAML + env vars + Pydantic."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class Tier(StrEnum):
    MINIMAL = "minimal"
    LIGHT = "light"
    STANDARD = "standard"
    FULL = "full"


class StealthLevel(StrEnum):
    OFF = "off"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class ScanProfile(StrEnum):
    QUICK = "quick"
    WEB = "web"
    NETWORK = "network"
    API = "api"
    FULL = "full"


# Behavior flags per ScanProfile (kept lightweight & explicit)
SCAN_PROFILE_SETTINGS: dict[str, dict[str, Any]] = {
    "quick": {
        "use_amass": False,
        "run_osint": False,
        "run_waf": False,
        "run_crawl": False,
        "run_headers": True,
        "run_exposure": True,
        "run_graphql": False,
        "run_auth_diff": False,
        "run_nuclei": True,
        "targeted_nuclei": True,
        "run_ffuf": False,
        "run_nikto": False,
        "run_tls": True,
        "run_ssh": True,
        "run_network_audits": True,
    },
    "web": {
        "use_amass": True,
        "run_osint": False,
        "run_waf": True,
        "run_crawl": True,
        "run_headers": True,
        "run_exposure": True,
        "run_graphql": True,
        "run_auth_diff": True,
        "run_nuclei": True,
        "targeted_nuclei": True,
        "run_ffuf": True,
        "ffuf_wordlist": "common",
        "run_nikto": True,
        "run_tls": True,
        "run_ssh": False,
        "run_network_audits": False,
    },
    "network": {
        "use_amass": False,
        "run_osint": True,
        "run_waf": False,
        "run_crawl": False,
        "run_headers": False,
        "run_exposure": False,
        "run_graphql": False,
        "run_auth_diff": False,
        "run_nuclei": False,
        "targeted_nuclei": False,
        "run_ffuf": False,
        "run_nikto": False,
        "run_tls": True,
        "run_ssh": True,
        "run_network_audits": True,
    },
    "api": {
        "use_amass": False,
        "run_osint": False,
        "run_waf": True,
        "run_crawl": True,
        "run_headers": True,
        "run_exposure": True,
        "run_graphql": True,
        "run_auth_diff": True,
        "run_nuclei": True,
        "targeted_nuclei": True,
        "run_ffuf": True,
        "ffuf_wordlist": "api",
        "run_nikto": False,
        "run_tls": True,
        "run_ssh": False,
        "run_network_audits": False,
    },
    "full": {
        "use_amass": True,
        "run_osint": True,
        "run_waf": True,
        "run_crawl": True,
        "run_headers": True,
        "run_exposure": True,
        "run_graphql": True,
        "run_auth_diff": True,
        "run_nuclei": True,
        "targeted_nuclei": False,
        "run_ffuf": True,
        "ffuf_wordlist": "common",
        "run_nikto": True,
        "run_tls": True,
        "run_ssh": True,
        "run_network_audits": True,
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
    auth_headers: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    wpscan_api_token: str | None = Field(default=None, exclude=True, repr=False)
    dashboard_token: str | None = Field(default=None, exclude=True, repr=False)
    ssh_user: str | None = Field(default=None, exclude=True, repr=False)
    ssh_key_path: Path | None = Field(default=None, exclude=True, repr=False)
    local_pkg_audit: bool = False
    openapi_spec: Path | None = None
    ignore_file: Path | None = None
    ollama_host: str = "http://127.0.0.1:11434"
    model_name: str = "dolphin-mistral"
    max_threads: int = Field(default=5, ge=1)
    auto_confirm_exploits: bool = False
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "nexus_output")
    api_keys: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    knowledge_dir: Path | None = None

    def model_post_init(self, __context: Any) -> None:
        if "db_path" not in self.model_fields_set:
            self.db_path = self.data_dir / "nexus.db"
        if self.knowledge_dir is None:
            # Default: bundled knowledge inside the package
            self.knowledge_dir = Path(__file__).resolve().parent.parent / "brain" / "knowledge"

    def ensure_dirs(self) -> None:
        """Create configured data and output directories on disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, path: Path | None = None) -> Path:
        dest = path or (self.data_dir / "config.yaml")
        if path is None:
            self.ensure_dirs()
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        # Convert Path objects to strings for YAML
        for key in (
            "data_dir",
            "db_path",
            "scope_file",
            "openapi_spec",
            "ignore_file",
            "output_dir",
            "knowledge_dir",
        ):
            if data.get(key) is not None:
                data[key] = str(data[key])
        dest.write_text(
            yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest

    @classmethod
    def load(cls, path: Path | None = None) -> NexusConfig:
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
            "NEXUS_SCOPE_FILE": "scope_file",
            "NEXUS_STEALTH": "stealth",
            "NEXUS_TIER": "tier",
            "NEXUS_PROFILE": "profile",
            "NEXUS_KNOWLEDGE_DIR": "knowledge_dir",
            "NEXUS_IGNORE_FILE": "ignore_file",
            "NEXUS_LOCAL_PKG_AUDIT": "local_pkg_audit",
            "NEXUS_AUTO_CONFIRM_EXPLOITS": "auto_confirm_exploits",
            "NEXUS_OLLAMA_HOST": "ollama_host",
            "NEXUS_MODEL": "model_name",
            "NEXUS_MAX_THREADS": "max_threads",
            "NEXUS_OUTPUT_DIR": "output_dir",
            "NEXUS_WPSCAN_API_TOKEN": "wpscan_api_token",
            "NEXUS_DASHBOARD_TOKEN": "dashboard_token",
        }
        optional_fields = {
            "scope_file",
            "knowledge_dir",
            "ignore_file",
            "wpscan_api_token",
            "dashboard_token",
        }
        for env_key, cfg_key in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                if cfg_key in optional_fields and not val.strip():
                    continue
                data[cfg_key] = val
        if not data.get("wpscan_api_token"):
            wp_tok = os.environ.get("WPSCAN_API_TOKEN")
            if wp_tok:
                data["wpscan_api_token"] = wp_tok

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
