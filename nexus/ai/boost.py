"""AI Boost Layer — optional AI enhancement for every NEXUS phase.

The boost layer wraps expert-system calls with optional LLM enhancement.
If Ollama is unavailable, every function silently falls back to the expert
system result (or returns the input unchanged).  Zero degradation without AI.

Usage from engine.py:
    booster = AIBoost(config, knowledge, expert, taxonomy)
    booster.connect()  # tries Ollama; sets .available = True/False
    enhanced = booster.enhance_findings(findings)
    summary  = booster.executive_summary(target, severity_counts, ...)
"""

from __future__ import annotations

import logging
from typing import Any

from nexus.ai.ollama_client import OllamaClient, matches_model_name
from nexus.ai.prompts import (
    SECURITY_ANALYST_SYSTEM,
    EXPLOIT_ADVISOR_SYSTEM,
    REPORT_WRITER_SYSTEM,
    finding_analysis_prompt,
    chain_analysis_prompt,
    executive_summary_prompt,
    exploit_suggestion_prompt,
    remediation_prompt,
)
from nexus.ai.guard import AIGuard

log = logging.getLogger("nexus.ai.boost")


class AIBoost:
    """Optional AI enhancement layer — wraps the expert system with LLM boost."""

    def __init__(
        self,
        ollama_host: str = "http://127.0.0.1:11434",
        model_name: str = "dolphin-mistral",
        knowledge_graph: Any = None,
        expert: Any = None,
        taxonomy: Any = None,
    ) -> None:
        self.host = ollama_host
        self.model = model_name
        self.client: OllamaClient | None = None
        self.guard = AIGuard(knowledge_graph, expert, taxonomy)
        self.available = False
        self._knowledge = knowledge_graph
        self._expert = expert

    # ── Connection ────────────────────────────────────────────────

    def connect(self) -> bool:
        """Attempt to connect to Ollama.  Sets self.available accordingly."""
        if self.client is not None:
            self.client.close()
        self.client = OllamaClient(self.host)
        self.available = self.client.is_alive()
        if self.available:
            models = self.client.list_models()
            has_model = any(matches_model_name(m, self.model) for m in models)
            if not has_model:
                log.warning(
                    "Ollama is running but model '%s' not found.  "
                    "Available: %s.  AI boost disabled.",
                    self.model, models or "none",
                )
                self.available = False
            else:
                log.info("AI boost connected: model=%s", self.model)
        else:
            log.info("Ollama not available — AI boost disabled (expert system only)")
        return self.available

    def status(self) -> dict[str, Any]:
        """Return current AI boost status."""
        return {
            "available": self.available,
            "host": self.host,
            "model": self.model,
            "models_local": self.client.list_models() if self.client and self.available else [],
        }

    # ── Finding Enhancement ───────────────────────────────────────

    def enhance_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enhance a single finding with AI analysis.

        Returns the finding dict with an added 'ai_analysis' key.
        Falls back to empty string if AI unavailable.
        """
        if not self.available or not self.client:
            return finding

        prompt = finding_analysis_prompt(finding)
        raw = self.client.generate(
            prompt, self.model, system=SECURITY_ANALYST_SYSTEM,
            temperature=0.3, max_tokens=1024,
        )
        if not raw:
            return finding

        guarded = self.guard.validate(raw)
        if self.guard.is_trustworthy(guarded):
            finding["ai_analysis"] = guarded.text
            finding["ai_confidence"] = guarded.confidence
        else:
            log.info(
                "AI analysis for '%s' rejected by guard: %s",
                finding.get("title", "?"), guarded.warnings,
            )
            finding["ai_analysis"] = ""
            finding["ai_confidence"] = 0.0
        return finding

    def enhance_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enhance a list of findings.  Only enhances high/critical ones to save time."""
        if not self.available:
            return findings

        for f in findings:
            sev = f.get("severity", "info")
            if hasattr(sev, "value"):
                sev = sev.value
            if sev in ("critical", "high"):
                self.enhance_finding(f)
        return findings

    # ── Attack Chain Enhancement ──────────────────────────────────

    def enhance_chain(
        self,
        chain: dict[str, Any],
        related_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Enhance an attack chain with AI analysis."""
        if not self.available or not self.client:
            return chain

        prompt = chain_analysis_prompt(chain, related_findings)
        raw = self.client.generate(
            prompt, self.model, system=SECURITY_ANALYST_SYSTEM,
            temperature=0.3, max_tokens=1024,
        )
        if raw:
            guarded = self.guard.validate(raw)
            if self.guard.is_trustworthy(guarded):
                chain["ai_analysis"] = guarded.text
        return chain

    # ── Report Enhancement ────────────────────────────────────────

    def executive_summary(
        self,
        target: str,
        total_findings: int,
        severity_counts: dict[str, int],
        chains_count: int = 0,
        credentials_count: int = 0,
    ) -> str:
        """Generate an AI-enhanced executive summary.

        Falls back to empty string (caller uses the expert system summary).
        """
        if not self.available or not self.client:
            return ""

        prompt = executive_summary_prompt(
            target, total_findings, severity_counts, chains_count, credentials_count,
        )
        raw = self.client.generate(
            prompt, self.model, system=REPORT_WRITER_SYSTEM,
            temperature=0.4, max_tokens=1024,
        )
        if not raw:
            return ""

        guarded = self.guard.validate(raw)
        return guarded.text if self.guard.is_trustworthy(guarded) else ""

    # ── Exploit Suggestion ────────────────────────────────────────

    def suggest_exploits(
        self,
        finding: dict[str, Any],
        available_tools: list[str] | None = None,
    ) -> str:
        """Suggest exploitation approaches for a finding.

        Falls back to empty string.
        """
        if not self.available or not self.client:
            return ""

        tools = available_tools or [
            "nmap", "sqlmap", "hydra", "nuclei", "ffuf", "msfconsole",
        ]
        prompt = exploit_suggestion_prompt(finding, tools)
        raw = self.client.generate(
            prompt, self.model, system=EXPLOIT_ADVISOR_SYSTEM,
            temperature=0.3, max_tokens=1024,
        )
        if not raw:
            return ""

        guarded = self.guard.validate(raw)
        return guarded.text if self.guard.is_trustworthy(guarded) else ""

    # ── Remediation Enhancement ───────────────────────────────────

    def enhanced_remediation(self, finding: dict[str, Any]) -> str:
        """Generate AI-enhanced remediation guidance.

        Falls back to the existing finding['remediation'] or empty string.
        """
        if not self.available or not self.client:
            return finding.get("remediation", "")

        prompt = remediation_prompt(finding)
        raw = self.client.generate(
            prompt, self.model, system=SECURITY_ANALYST_SYSTEM,
            temperature=0.3, max_tokens=1024,
        )
        if not raw:
            return finding.get("remediation", "")

        guarded = self.guard.validate(raw)
        if self.guard.is_trustworthy(guarded):
            return guarded.text
        return finding.get("remediation", "")

    def close(self) -> None:
        if self.client:
            self.client.close()
