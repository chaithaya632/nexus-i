"""Ollama API client with hybrid thinking parser and streaming support."""

from __future__ import annotations

import json
import re
from typing import Any, Iterator
import httpx

from arjuna.config import settings


class OllamaClient:
    """Handles communication with the local Ollama inference service."""

    def __init__(self, host: str | None = None, model: str | None = None) -> None:
        self.host = (host or settings.ollama_host).rstrip("/")
        self.model = model or settings.model
        self.client = httpx.Client(base_url=self.host, timeout=120.0)

    def is_alive(self) -> bool:
        """Check if the Ollama service is reachable and responsive."""
        try:
            res = self.client.get("/")
            return res.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[dict[str, Any]]:
        """Retrieve list of locally available models."""
        try:
            res = self.client.get("/api/tags")
            if res.status_code == 200:
                data = res.json()
                return data.get("models", [])
            return []
        except Exception:
            return []

    def chat_stream(
        self,
        messages: list[dict[str, str]],
        system: str | None = None,
        temperature: float | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Stream chat tokens from Ollama, tagging thinking vs final answer."""
        url = f"{self.host}/api/chat"
        formatted_messages = []

        if system:
            formatted_messages.append({"role": "system", "content": system})

        formatted_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "stream": True,
            "options": {
                "num_ctx": settings.context_length,
                "temperature": temperature if temperature is not None else settings.temperature,
                "top_p": settings.top_p,
            },
        }

        with self.client.stream("POST", url, json=payload, timeout=180.0) as response:
            if response.status_code != 200:
                err_text = response.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Ollama API Error ({response.status_code}): {err_text}")

            in_think = False
            for line in response.iter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue

                token = chunk.get("message", {}).get("content", "")
                if not token:
                    if chunk.get("done"):
                        yield {"token": "", "in_think": in_think, "done": True, "meta": chunk}
                    continue

                # Detect think tag transitions
                if "<think>" in token:
                    in_think = True
                    token = token.replace("<think>", "")
                if "</think>" in token:
                    in_think = False
                    token = token.replace("</think>", "")

                yield {
                    "token": token,
                    "in_think": in_think,
                    "done": chunk.get("done", False),
                    "meta": chunk if chunk.get("done") else None,
                }

    def chat(
        self,
        messages: list[dict[str, str]],
        system: str | None = None,
        temperature: float | None = None,
    ) -> tuple[str, str]:
        """Non-streaming chat. Returns (final_content, thinking_trace)."""
        content_parts: list[str] = []
        thinking_parts: list[str] = []

        for chunk in self.chat_stream(messages, system=system, temperature=temperature):
            token = chunk["token"]
            if chunk["in_think"]:
                thinking_parts.append(token)
            else:
                content_parts.append(token)

        final_content = "".join(content_parts).strip()
        thinking_trace = "".join(thinking_parts).strip()

        # Handle models that output unseparated <think> in full block
        if "<think>" in final_content and "</think>" in final_content:
            match = re.search(r"<think>(.*?)</think>", final_content, re.DOTALL)
            if match:
                thinking_trace = match.group(1).strip()
                final_content = re.sub(r"<think>.*?</think>", "", final_content, flags=re.DOTALL).strip()

        return final_content, thinking_trace
