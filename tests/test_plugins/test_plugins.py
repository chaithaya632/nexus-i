"""Plugin system tests — registry, loader, and sample plugin."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from nexus.plugins import PluginRegistry, PluginLoader, PluginInfo


class TestPluginRegistry:
    """PluginRegistry registration and query tests."""

    def test_empty_registry(self) -> None:
        reg = PluginRegistry()
        assert reg.count == 0
        assert reg.scanners == {}
        assert reg.recon_modules == {}
        assert reg.reporters == {}
        assert reg.post_hooks == []

    def test_add_scanner(self) -> None:
        reg = PluginRegistry()
        async def dummy(target: str) -> list:
            return []
        reg.add_scanner("test-scan", dummy)
        assert "test-scan" in reg.scanners
        assert reg.scanners["test-scan"] is dummy

    def test_add_recon(self) -> None:
        reg = PluginRegistry()
        async def dummy(target: str) -> list:
            return []
        reg.add_recon("test-recon", dummy)
        assert "test-recon" in reg.recon_modules

    def test_add_reporter(self) -> None:
        reg = PluginRegistry()
        def dummy(data):
            return "report"
        reg.add_reporter("test-fmt", dummy)
        assert "test-fmt" in reg.reporters

    def test_add_post_hook(self) -> None:
        reg = PluginRegistry()
        def hook(findings):
            return findings
        reg.add_post_hook(hook)
        assert len(reg.post_hooks) == 1

    def test_stats(self) -> None:
        reg = PluginRegistry()
        async def s(t): return []
        async def r(t): return []
        reg.add_scanner("s1", s)
        reg.add_recon("r1", r)
        stats = reg.stats()
        assert stats["scanners"] == 1
        assert stats["recon"] == 1
        assert stats["total"] == 0  # no plugins registered via loader


class TestPluginLoader:
    """PluginLoader file discovery and loading."""

    def test_load_empty_directory(self, tmp_path: Path) -> None:
        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 0

    def test_load_nonexistent_directory(self, tmp_path: Path) -> None:
        loader = PluginLoader()
        count = loader.load_directory(tmp_path / "nope")
        assert count == 0

    def test_load_valid_plugin(self, tmp_path: Path) -> None:
        plugin_code = textwrap.dedent("""\
            PLUGIN_NAME = "test-scanner"
            PLUGIN_VERSION = "1.0.0"
            PLUGIN_TYPE = "scanner"

            async def _scan(target, **kwargs):
                return [{"title": "Test Finding", "host": target}]

            def register(registry):
                registry.add_scanner("test-scanner", _scan)
        """)
        (tmp_path / "test_scanner.py").write_text(plugin_code)

        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 1
        assert "test-scanner" in loader.registry.scanners
        assert loader.registry.count == 1
        assert loader.registry.plugins["test-scanner"].version == "1.0.0"

    def test_load_plugin_without_register(self, tmp_path: Path) -> None:
        (tmp_path / "bad_plugin.py").write_text("PLUGIN_NAME = 'bad'\n")

        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 0
        assert len(loader.errors) == 1
        assert "No register()" in loader.errors[0][1]

    def test_load_plugin_with_syntax_error(self, tmp_path: Path) -> None:
        (tmp_path / "broken.py").write_text("def register(x\n")

        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 0
        assert len(loader.errors) == 1

    def test_skip_underscore_files(self, tmp_path: Path) -> None:
        (tmp_path / "__init__.py").write_text("")
        (tmp_path / "_internal.py").write_text("")

        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 0
        assert len(loader.errors) == 0

    def test_multiple_plugins(self, tmp_path: Path) -> None:
        for i in range(3):
            code = textwrap.dedent(f"""\
                PLUGIN_NAME = "plug-{i}"
                PLUGIN_VERSION = "0.{i}.0"
                PLUGIN_TYPE = "scanner"
                async def _run(t): return []
                def register(reg): reg.add_scanner("plug-{i}", _run)
            """)
            (tmp_path / f"plugin_{i}.py").write_text(code)

        loader = PluginLoader()
        count = loader.load_directory(tmp_path)
        assert count == 3
        assert loader.registry.count == 3

    def test_load_builtin_no_crash(self) -> None:
        """load_builtin() should not crash even with empty community dir."""
        loader = PluginLoader()
        count = loader.load_builtin()
        assert count >= 0  # 0 is fine — no community plugins shipped yet

    def test_shared_registry(self, tmp_path: Path) -> None:
        """Multiple loaders can share a registry."""
        reg = PluginRegistry()
        code = textwrap.dedent("""\
            PLUGIN_NAME = "shared"
            PLUGIN_VERSION = "1.0.0"
            PLUGIN_TYPE = "recon"
            async def _run(t): return []
            def register(reg): reg.add_recon("shared", _run)
        """)
        (tmp_path / "shared.py").write_text(code)

        loader = PluginLoader(registry=reg)
        loader.load_directory(tmp_path)
        assert "shared" in reg.recon_modules
