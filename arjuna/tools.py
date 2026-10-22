"""Zero-cost local tool registry for Arjuna."""

from __future__ import annotations

import math
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from arjuna.memory import MemoryStore


class ToolRegistry:
    """Provides local utility tools for Arjuna to use."""

    def __init__(self, memory: MemoryStore) -> None:
        self.memory = memory

    def get_system_status(self) -> dict[str, Any]:
        """Inspect current machine state (CPU, RAM, GPU, OS)."""
        status: dict[str, Any] = {
            "os": f"{platform.system()} {platform.release()}",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        # Windows RAM check via PowerShell
        try:
            cmd = "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemorySize"
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True)
            status["ram_info"] = out.strip()
        except Exception:
            status["ram_info"] = "Unavailable"

        # GPU check
        try:
            cmd = "nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader"
            out = subprocess.check_output(cmd, shell=True, text=True)
            status["gpu_info"] = out.strip()
        except Exception:
            status["gpu_info"] = "No discrete GPU detected or nvidia-smi unavailable"

        return status

    def remember(self, key: str, value: str) -> str:
        """Store a persistent piece of knowledge into SQLite."""
        self.memory.set_fact(key, value)
        return f"Successfully saved fact '{key}': '{value}'"

    def recall(self, key: str) -> str:
        """Retrieve a stored fact from SQLite."""
        val = self.memory.get_fact(key)
        if val is not None:
            return f"Fact '{key}': {val}"
        return f"No record found for key '{key}'"

    def calculate(self, expression: str) -> str:
        """Evaluate a safe mathematical expression."""
        allowed_names: dict[str, Any] = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}
        allowed_names.update({
            "math": math,
            "abs": abs,
            "round": round,
            "max": max,
            "min": min,
            "pow": pow,
        })
        try:
            code = compile(expression, "<string>", "eval")
            for name in code.co_names:
                if name not in allowed_names:
                    return f"Error: Function or variable '{name}' is not allowed."
            result = eval(code, {"__builtins__": {}}, allowed_names)
            return f"{expression} = {result}"
        except Exception as e:
            return f"Error evaluating expression: {e}"

    def read_local_file(self, file_path: str, max_chars: int = 2000) -> str:
        """Read text from a local workspace file safely."""
        p = Path(file_path)
        if not p.is_file():
            return f"Error: File '{file_path}' does not exist or is not a file."
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            if len(content) > max_chars:
                return content[:max_chars] + f"\n... [Truncated after {max_chars} chars]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"
