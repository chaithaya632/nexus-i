"""Ollama HTTP API client — connects to a local Ollama instance.

100% optional.  If Ollama isn't running, every public method returns
a sensible fallback (False, [], empty string) so the rest of NEXUS
keeps working.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("nexus.ai.ollama")

# Models we recommend for uncensored security analysis
RECOMMENDED_MODELS: list[dict[str, str]] = [
    {"name": "dolphin-mistral",   "size": "4.1GB", "vram": "~5GB",  "tier": "light",    "description": "Uncensored Mistral 7B — best all-around for security analysis"},
    {"name": "whiterabbitneo",    "size": "4.1GB", "vram": "~5GB",  "tier": "light",    "description": "Security-focused uncensored model, trained on cybersecurity data"},
    {"name": "dolphin-llama3",    "size": "4.7GB", "vram": "~6GB",  "tier": "standard", "description": "Uncensored Llama-3 8B — better reasoning, more VRAM"},
    {"name": "qwen2.5:0.5b",     "size": "0.4GB", "vram": "~1GB",  "tier": "minimal",  "description": "Tiny model for minimal-tier systems — limited accuracy"},
    {"name": "qwen2.5:1.5b",     "size": "1.0GB", "vram": "~2GB",  "tier": "minimal",  "description": "Small model for low-RAM systems — decent accuracy"},
]

# Timeout for generation (some prompts take 60s+ on CPU-only)
_GENERATE_TIMEOUT = 120.0
_HEALTH_TIMEOUT = 5.0


def matches_model_name(installed_name: str, requested_name: str) -> bool:
    """Match Ollama model names by exact name or explicit tag (handling :latest)."""
    cand = installed_name.strip()
    req = requested_name.strip()
    if not cand or not req:
        return False
    if cand == req:
        return True
    if ":" not in req:
        return cand == f"{req}:latest" or cand.startswith(f"{req}:")
    if req.endswith(":latest") and cand == req[:-7]:
        return True
    return False


class OllamaClient:
    """Synchronous Ollama REST client wrapping the /api/* endpoints."""

    def __init__(self, host: str = "http://127.0.0.1:11434") -> None:
        self.host = host.rstrip("/")
        self._client = httpx.Client(base_url=self.host, timeout=_HEALTH_TIMEOUT)

    def __enter__(self) -> "OllamaClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Health ────────────────────────────────────────────────────

    def is_alive(self) -> bool:
        """Return True if Ollama is reachable."""
        try:
            r = self._client.get("/api/tags", timeout=_HEALTH_TIMEOUT)
            return r.status_code == 200
        except (httpx.HTTPError, OSError, ValueError):
            return False

    # ── Models ────────────────────────────────────────────────────

    def list_models(self) -> list[str]:
        """Return names of locally available models, or [] on failure."""
        try:
            r = self._client.get("/api/tags", timeout=_HEALTH_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        except Exception:
            return []

    def has_model(self, name: str) -> bool:
        """Check if a model is locally available."""
        return any(matches_model_name(m, name) for m in self.list_models())

    def pull_model(self, name: str) -> bool:
        """Pull a model.  Returns True on success."""
        try:
            r = self._client.post(
                "/api/pull",
                json={"name": name, "stream": False},
                timeout=600.0,
            )
            r.raise_for_status()
            payload = r.json() if r.content else {}
            if isinstance(payload, dict) and payload.get("error"):
                log.warning("Ollama pull error for %s: %s", name, payload.get("error"))
                return False
            return True
        except Exception as exc:
            log.warning("Failed to pull model %s: %s", name, exc)
            return False

    # ── Generation ────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        model: str = "dolphin-mistral",
        *,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        stop: list[str] | None = None,
    ) -> str:
        """Generate a completion.  Returns empty string on failure."""
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system
        if stop:
            payload["options"]["stop"] = stop

        try:
            r = self._client.post("/api/generate", json=payload, timeout=_GENERATE_TIMEOUT)
            r.raise_for_status()
            return r.json().get("response", "").strip()
        except Exception as exc:
            log.warning("Ollama generate failed: %s", exc)
            return ""

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str = "dolphin-mistral",
        *,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """Chat completion.  Returns empty string on failure."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        try:
            r = self._client.post("/api/chat", json=payload, timeout=_GENERATE_TIMEOUT)
            r.raise_for_status()
            msg = r.json().get("message", {})
            return msg.get("content", "").strip()
        except Exception as exc:
            log.warning("Ollama chat failed: %s", exc)
            return ""

    # ── Embedding (for future vector search enhancement) ──────────

    def embed(self, text: str, model: str = "dolphin-mistral") -> list[float]:
        """Get embeddings for text.  Returns [] on failure."""
        try:
            r = self._client.post(
                "/api/embeddings",
                json={"model": model, "prompt": text},
                timeout=30.0,
            )
            r.raise_for_status()
            return r.json().get("embedding", [])
        except Exception:
            return []

    def close(self) -> None:
        self._client.close()

    def __del__(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
