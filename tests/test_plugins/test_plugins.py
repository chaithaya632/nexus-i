"""Plugin system tests — registry, loader, and sample plugin."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from nexus.plugins import PluginLoader, PluginRegistry


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

        async def s(t):
            return []

        async def r(t):
            return []

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

    def test_same_filename_across_dirs_no_sys_modules_collision(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "scanner.py").write_text(
            textwrap.dedent("""\
            from dataclasses import dataclass
            PLUGIN_NAME = "plug-a"
            PLUGIN_VERSION = "1.0.0"
            PLUGIN_TYPE = "scanner"

            @dataclass
            class Item:
                x: int = 1

            async def _run(t, **kw): return []
            def register(reg): reg.add_scanner("plug-a", _run)
        """)
        )
        (dir_b / "scanner.py").write_text(
            textwrap.dedent("""\
            PLUGIN_NAME = "plug-b"
            PLUGIN_VERSION = "2.0.0"
            PLUGIN_TYPE = "scanner"
            async def _run(t, **kw): return []
            def register(reg): reg.add_scanner("plug-b", _run)
        """)
        )

        loader = PluginLoader()
        assert loader.load_directory(dir_a) == 1
        assert loader.load_directory(dir_b) == 1
        assert "plug-a" in loader.registry.scanners
        assert "plug-b" in loader.registry.scanners

    def test_disabled_plugin_not_returned_in_active_hooks(self, tmp_path: Path) -> None:
        (tmp_path / "en.py").write_text(
            textwrap.dedent("""\
            PLUGIN_NAME = "toggle-plug"
            PLUGIN_VERSION = "1.0.0"
            PLUGIN_TYPE = "scanner"
            async def _run(t, **kw): return []
            def register(reg): reg.add_scanner("toggle-plug", _run)
        """)
        )
        (tmp_path / "dis.py").write_text(
            textwrap.dedent("""\
            PLUGIN_NAME = "off-plug"
            PLUGIN_VERSION = "1.0.0"
            PLUGIN_TYPE = "scanner"
            PLUGIN_ENABLED = False
            async def _run(t, **kw): return []
            def register(reg): reg.add_scanner("off-plug", _run)
        """)
        )

        loader = PluginLoader()
        assert loader.load_directory(tmp_path) == 2
        assert "toggle-plug" in loader.registry.scanners
        assert "off-plug" not in loader.registry.scanners

        assert loader.registry.set_enabled("toggle-plug", False) is True
        assert "toggle-plug" not in loader.registry.scanners

    @pytest.mark.asyncio
    async def test_async_and_sync_post_hooks(self) -> None:
        reg = PluginRegistry()
        called = []

        def sync_hook(eng_id: str, **_):
            called.append(("sync", eng_id))

        async def async_hook(eng_id: str, **_):
            called.append(("async", eng_id))

        reg.add_post_hook(sync_hook)
        reg.add_post_hook(async_hook)
        errors = await reg.run_post_hooks(eng_id="eng1")
        assert errors == []
        assert called == [("sync", "eng1"), ("async", "eng1")]

    def test_entry_points_loading(self) -> None:
        from types import ModuleType, SimpleNamespace
        from unittest.mock import patch

        mod = ModuleType("fake_ep_mod")
        mod.PLUGIN_NAME = "ep-plug"  # type: ignore[attr-defined]
        mod.PLUGIN_VERSION = "1.2.3"  # type: ignore[attr-defined]
        mod.PLUGIN_TYPE = "scanner"  # type: ignore[attr-defined]
        mod.register = lambda reg: reg.add_scanner("ep-scan", lambda t, **kw: [])  # type: ignore[attr-defined]
        fake_ep = SimpleNamespace(name="ep-plug", value="pkg:mod", load=lambda: mod)
        loader = PluginLoader()
        with patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            count = loader.load_entry_points()
        assert count == 1
        assert "ep-scan" in loader.registry.scanners
