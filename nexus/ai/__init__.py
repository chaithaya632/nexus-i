"""NEXUS AI Boost Layer — 100% optional LLM enhancement.

If Ollama isn't running or no model is loaded, everything falls back to
the expert system.  Zero functionality loss without AI.
"""

from nexus.ai.boost import AIBoost
from nexus.ai.guard import AIGuard, GuardResult
from nexus.ai.ollama_client import RECOMMENDED_MODELS, OllamaClient

__all__ = ["AIBoost", "AIGuard", "GuardResult", "OllamaClient", "RECOMMENDED_MODELS"]
