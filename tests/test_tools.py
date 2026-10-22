"""Unit tests for tool registry."""

import tempfile
from pathlib import Path
from arjuna.memory import MemoryStore
from arjuna.tools import ToolRegistry


def test_calculate():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(Path(tmpdir) / "test.db")
        tools = ToolRegistry(store)

        assert "15" in tools.calculate("10 + 5")
        assert "64" in tools.calculate("2 ** 6")
        assert "3.14" in tools.calculate("round(math.pi, 2)")
        assert "Error" in tools.calculate("__import__('os').system('ls')")


def test_remember_and_recall():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(Path(tmpdir) / "test.db")
        tools = ToolRegistry(store)

        tools.remember("city", "Bangalore")
        assert "Bangalore" in tools.recall("city")
        assert "No record found" in tools.recall("country")


def test_read_local_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "sample.txt"
        test_file.write_text("Hello from Arjuna test suite!", encoding="utf-8")

        store = MemoryStore(Path(tmpdir) / "test.db")
        tools = ToolRegistry(store)

        content = tools.read_local_file(str(test_file))
        assert "Hello from Arjuna test suite!" in content
