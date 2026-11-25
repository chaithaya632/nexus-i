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

import hashlib
import importlib.metadata
import importlib.util
import inspect
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

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
    """Central registry for all plugin hooks.

    Scanner and recon plugins may return either `Finding` instances or
    `Finding`-compatible dictionaries (with keys like `title`, `host`,
    `port`, `severity`, `description`, `evidence`, `cve_ids`, `cwe_id`).
    Post-hooks may be synchronous functions or `async def` coroutines.
    """

    def __init__(self) -> None:
        self._scanners: dict[str, ScannerFunc] = {}
        self._recon: dict[str, ReconFunc] = {}
        self._reporters: dict[str, ReporterFunc] = {}
        self._post_hooks: list[PostHookFunc] = []
        self._plugins: dict[str, PluginInfo] = {}
        self._hook_owners: dict[tuple[str, str], str] = {}
        self._post_hook_owners: list[tuple[str | None, PostHookFunc]] = []
        self._current_owner: str | None = None

    # ── Registration API (called by plugins) ─────────────────────

    def add_scanner(self, name: str, func: ScannerFunc) -> None:
        """Register a custom scanner."""
        self._scanners[name] = func
        if self._current_owner:
            self._hook_owners[("scanner", name)] = self._current_owner
        log.debug("Registered scanner plugin: %s", name)

    def add_recon(self, name: str, func: ReconFunc) -> None:
        """Register a custom recon module."""
        self._recon[name] = func
        if self._current_owner:
            self._hook_owners[("recon", name)] = self._current_owner
        log.debug("Registered recon plugin: %s", name)

    def add_reporter(self, name: str, func: ReporterFunc) -> None:
        """Register a custom report format."""
        self._reporters[name] = func
        if self._current_owner:
            self._hook_owners[("reporter", name)] = self._current_owner
        log.debug("Registered reporter plugin: %s", name)

    def add_post_hook(self, func: PostHookFunc) -> None:
        """Register a post-processing hook."""
        self._post_hooks.append(func)
        self._post_hook_owners.append((self._current_owner, func))
        log.debug("Registered post-processing hook")

    def is_plugin_enabled(self, plugin_name: str | None) -> bool:
        """Return True if a plugin is enabled (or has no owning plugin metadata)."""
        if not plugin_name or plugin_name not in self._plugins:
            return True
        return self._plugins[plugin_name].enabled

    def set_enabled(self, plugin_name: str, enabled: bool) -> bool:
        """Enable or disable a loaded plugin by name. Returns True if found."""
        info = self._plugins.get(plugin_name)
        if info is None:
            return False
        info.enabled = enabled
        return True

    # ── Query API ─────────────────────────────────────────────────

    @property
    def scanners(self) -> dict[str, ScannerFunc]:
        return {
            name: fn
            for name, fn in self._scanners.items()
            if self.is_plugin_enabled(self._hook_owners.get(("scanner", name)))
        }

    @property
    def recon_modules(self) -> dict[str, ReconFunc]:
        return {
            name: fn
            for name, fn in self._recon.items()
            if self.is_plugin_enabled(self._hook_owners.get(("recon", name)))
        }

    @property
    def reporters(self) -> dict[str, ReporterFunc]:
        return {
            name: fn
            for name, fn in self._reporters.items()
            if self.is_plugin_enabled(self._hook_owners.get(("reporter", name)))
        }

    @property
    def post_hooks(self) -> list[PostHookFunc]:
        if not self._post_hook_owners:
            return list(self._post_hooks)
        return [
            fn for owner, fn in self._post_hook_owners
            if self.is_plugin_enabled(owner)
        ]

    async def run_post_hooks(self, **kwargs: Any) -> list[Exception]:
        """Invoke all enabled post-hooks, awaiting async hooks cleanly."""
        errors: list[Exception] = []
        for hook in self.post_hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    await hook(**kwargs)
                else:
                    res = hook(**kwargs)
                    if inspect.isawaitable(res):
                        await res
            except Exception as exc:
                errors.append(exc)
                log.warning("Plugin post-hook failed: %s", exc)
        return errors

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
            "scanners": len(self.scanners),
            "recon": len(self.recon_modules),
            "reporters": len(self.reporters),
            "post_hooks": len(self.post_hooks),
        }


class PluginLoader:
    """Discovers and loads plugins from directories and Python entry points."""

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

    def load_entry_points(self, group: str = "nexus.plugins") -> int:
        """Load installed plugins declared via Python package entry points."""
        loaded = 0
        try:
            eps = importlib.metadata.entry_points(group=group)
        except Exception as exc:
            self._errors.append((f"entry_points:{group}", str(exc)))
            return 0

        for ep in eps:
            try:
                obj = ep.load()
                if inspect.ismodule(obj):
                    name = getattr(obj, "PLUGIN_NAME", ep.name)
                    version = getattr(obj, "PLUGIN_VERSION", "0.0.0")
                    ptype = getattr(obj, "PLUGIN_TYPE", "entry_point")
                    enabled = bool(getattr(obj, "PLUGIN_ENABLED", True))
                    register_fn = getattr(obj, "register", None)
                    if register_fn is None:
                        self._errors.append((ep.value, "No register() function"))
                        continue
                elif callable(obj):
                    name = getattr(obj, "PLUGIN_NAME", ep.name)
                    version = getattr(obj, "PLUGIN_VERSION", "0.0.0")
                    ptype = getattr(obj, "PLUGIN_TYPE", "entry_point")
                    enabled = bool(getattr(obj, "PLUGIN_ENABLED", True))
                    register_fn = obj
                else:
                    self._errors.append((ep.value, "Entry point is neither module nor callable"))
                    continue

                info = PluginInfo(
                    name=name,
                    version=version,
                    plugin_type=ptype,
                    module_path=f"entry_point:{ep.value}",
                    enabled=enabled,
                )
                self.registry._plugins[name] = info
                if enabled:
                    prev_owner = self.registry._current_owner
                    self.registry._current_owner = name
                    try:
                        register_fn(self.registry)
                    finally:
                        self.registry._current_owner = prev_owner
                loaded += 1
                log.info("Loaded entry-point plugin: %s v%s (%s)", name, version, ptype)
            except Exception as exc:
                self._errors.append((f"entry_point:{ep.name}", str(exc)))
                log.warning("Failed to load entry-point plugin %s: %s", ep.name, exc)
        return loaded

    def load_builtin(self) -> int:
        """Load plugins from the built-in community directory and package entry points."""
        community_dir = Path(__file__).parent / "community"
        return self.load_directory(community_dir) + self.load_entry_points()

    def _load_plugin(self, path: Path) -> bool:
        """Load a single plugin file. Returns True on success."""
        path_hash = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:12]
        module_name = f"nexus.plugins._ext_{path.stem}_{path_hash}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                self._errors.append((str(path), "Invalid module spec"))
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Validate required attributes
            name = getattr(module, "PLUGIN_NAME", path.stem)
            version = getattr(module, "PLUGIN_VERSION", "0.0.0")
            ptype = getattr(module, "PLUGIN_TYPE", "unknown")
            enabled = bool(getattr(module, "PLUGIN_ENABLED", True))

            # Call register() if it exists
            register_fn = getattr(module, "register", None)
            if register_fn is None:
                sys.modules.pop(module_name, None)
                self._errors.append((str(path), "No register() function"))
                return False

            info = PluginInfo(
                name=name,
                version=version,
                plugin_type=ptype,
                module_path=str(path),
                enabled=enabled,
            )
            self.registry._plugins[name] = info
            if enabled:
                prev_owner = self.registry._current_owner
                self.registry._current_owner = name
                try:
                    register_fn(self.registry)
                finally:
                    self.registry._current_owner = prev_owner

            log.info("Loaded plugin: %s v%s (%s, enabled=%s)", name, version, ptype, enabled)
            return True

        except Exception as exc:
            sys.modules.pop(module_name, None)
            self._errors.append((str(path), str(exc)))
            log.warning("Failed to load plugin %s: %s", path.name, exc)
            return False
