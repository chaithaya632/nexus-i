"""NEXUS Plugin System — load community and custom scanner/recon extensions.

Plugins are Python modules placed in `nexus/plugins/community/` or a custom
directory.  Each plugin must expose a `register(registry)` function that
receives a PluginRegistry and registers hooks.

Plugin types:
  - scanner: custom vulnerability scanners
  - recon: custom recon modules
  - reporter: custom report formats
  - post: post-processing hooks (run after correlate)

Example plugin (save as nexus/plugins/community/my_scanner.py):

    PLUGIN_NAME = "my-scanner"
    PLUGIN_VERSION = "0.1.0"
    PLUGIN_TYPE = "scanner"

    def register(registry):
        registry.add_scanner("my-scanner", run_my_scanner)

    async def run_my_scanner(target, **kwargs):
        # Return list of Finding-like dicts
        return []
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable

log = logging.getLogger("nexus.plugins")

# Type aliases for plugin callables
ScannerFunc = Callable[..., Awaitable[list[Any]]]
ReconFunc = Callable[..., Awaitable[list[Any]]]
ReporterFunc = Callable[..., Any]
PostHookFunc = Callable[..., Any]


@dataclass
class PluginInfo:
    """Metadata about a loaded plugin."""
    name: str
    version: str
    plugin_type: str
    module_path: str
    enabled: bool = True


class PluginRegistry:
    """Central registry for all plugin hooks."""

    def __init__(self) -> None:
        self._scanners: dict[str, ScannerFunc] = {}
        self._recon: dict[str, ReconFunc] = {}
        self._reporters: dict[str, ReporterFunc] = {}
        self._post_hooks: list[PostHookFunc] = []
        self._plugins: dict[str, PluginInfo] = {}

    # ── Registration API (called by plugins) ─────────────────────

    def add_scanner(self, name: str, func: ScannerFunc) -> None:
        """Register a custom scanner."""
        self._scanners[name] = func
        log.debug("Registered scanner plugin: %s", name)

    def add_recon(self, name: str, func: ReconFunc) -> None:
        """Register a custom recon module."""
        self._recon[name] = func
        log.debug("Registered recon plugin: %s", name)

    def add_reporter(self, name: str, func: ReporterFunc) -> None:
        """Register a custom report format."""
        self._reporters[name] = func
        log.debug("Registered reporter plugin: %s", name)

    def add_post_hook(self, func: PostHookFunc) -> None:
        """Register a post-processing hook."""
        self._post_hooks.append(func)
        log.debug("Registered post-processing hook")

    # ── Query API ─────────────────────────────────────────────────

    @property
    def scanners(self) -> dict[str, ScannerFunc]:
        return dict(self._scanners)

    @property
    def recon_modules(self) -> dict[str, ReconFunc]:
        return dict(self._recon)

    @property
    def reporters(self) -> dict[str, ReporterFunc]:
        return dict(self._reporters)

    @property
    def post_hooks(self) -> list[PostHookFunc]:
        return list(self._post_hooks)

    @property
    def plugins(self) -> dict[str, PluginInfo]:
        return dict(self._plugins)

    @property
    def count(self) -> int:
        return len(self._plugins)

    def stats(self) -> dict[str, int]:
        """Return counts by type."""
        return {
            "total": self.count,
            "scanners": len(self._scanners),
            "recon": len(self._recon),
            "reporters": len(self._reporters),
            "post_hooks": len(self._post_hooks),
        }


class PluginLoader:
    """Discovers and loads plugins from directories."""

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        self.registry = registry or PluginRegistry()
        self._errors: list[tuple[str, str]] = []

    @property
    def errors(self) -> list[tuple[str, str]]:
        """Return list of (plugin_path, error_message) for failed loads."""
        return list(self._errors)

    def load_directory(self, plugin_dir: Path) -> int:
        """Load all .py plugins from a directory. Returns count loaded."""
        if not plugin_dir.is_dir():
            log.debug("Plugin directory not found: %s", plugin_dir)
            return 0

        loaded = 0
        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            if self._load_plugin(py_file):
                loaded += 1

        if loaded:
            log.info("Loaded %d plugin(s) from %s", loaded, plugin_dir)
        return loaded

    def load_builtin(self) -> int:
        """Load plugins from the built-in community directory."""
        community_dir = Path(__file__).parent / "community"
        return self.load_directory(community_dir)

    def _load_plugin(self, path: Path) -> bool:
        """Load a single plugin file. Returns True on success."""
        module_name = f"nexus.plugins._{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                self._errors.append((str(path), "Invalid module spec"))
                return False

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Validate required attributes
            name = getattr(module, "PLUGIN_NAME", path.stem)
            version = getattr(module, "PLUGIN_VERSION", "0.0.0")
            ptype = getattr(module, "PLUGIN_TYPE", "unknown")

            # Call register() if it exists
            register_fn = getattr(module, "register", None)
            if register_fn is None:
                self._errors.append((str(path), "No register() function"))
                return False

            register_fn(self.registry)

            info = PluginInfo(
                name=name,
                version=version,
                plugin_type=ptype,
                module_path=str(path),
            )
            self.registry._plugins[name] = info
            log.info("Loaded plugin: %s v%s (%s)", name, version, ptype)
            return True

        except Exception as exc:
            self._errors.append((str(path), str(exc)))
            log.warning("Failed to load plugin %s: %s", path.name, exc)
            return False
