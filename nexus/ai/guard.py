"""AI Hallucination Guard — cross-references AI output against the expert system.

Before accepting any AI suggestion, the guard checks it against the knowledge
base, CVE database, and rule engine.  Flagged outputs get a confidence
downgrade; clearly fabricated CVEs are stripped entirely.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("nexus.ai.guard")

# CVE format: CVE-YYYY-NNNNN (4 digits year, 4-7 digits ID)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


@dataclass
class GuardResult:
    """Result of AI output validation."""
    text: str                           # the (possibly sanitized) output
    confidence: float = 1.0             # 0.0–1.0 confidence in accuracy
    warnings: list[str] = field(default_factory=list)
    stripped_cves: list[str] = field(default_factory=list)
    verified_cves: list[str] = field(default_factory=list)


class AIGuard:
    """Cross-checks AI outputs against the expert system knowledge base."""

    def __init__(
        self,
        knowledge_graph: Any = None,
        expert: Any = None,
        taxonomy: Any = None,
    ) -> None:
        self.knowledge = knowledge_graph
        self.expert = expert
        self.taxonomy = taxonomy

    def validate(self, ai_output: str) -> GuardResult:
        """Validate AI-generated text.

        - Checks referenced CVE IDs against the knowledge graph.
        - Strips fabricated CVEs with a warning.
        - Downgrades confidence if many unverifiable claims are found.
        """
        result = GuardResult(text=ai_output)

        # 1. Validate CVE references
        cve_ids = _CVE_PATTERN.findall(ai_output)
        if cve_ids and self.knowledge:
            for cve_id in cve_ids:
                if self.knowledge.has_cve(cve_id):
                    result.verified_cves.append(cve_id)
                else:
                    result.stripped_cves.append(cve_id)
                    result.warnings.append(
                        f"Unverified CVE reference: {cve_id} — not in knowledge base"
                    )

            # Strip unverified CVEs from the output text
            if result.stripped_cves:
                sanitized = ai_output
                for cve in result.stripped_cves:
                    sanitized = sanitized.replace(
                        cve, f"[UNVERIFIED: {cve}]"
                    )
                result.text = sanitized
                # Confidence penalty: 10% per fabricated CVE, floor at 0.3
                penalty = len(result.stripped_cves) * 0.1
                result.confidence = max(0.3, 1.0 - penalty)

        # 2. Check for unrealistic severity claims
        result = self._check_severity_inflation(result)

        # 3. Flag vague or generic advice
        result = self._check_vague_output(result)

        if result.warnings:
            log.info(
                "AI Guard: %d warnings, confidence %.0f%%",
                len(result.warnings), result.confidence * 100,
            )
        return result

    def _check_severity_inflation(self, result: GuardResult) -> GuardResult:
        """Flag if AI claims critical severity without supporting evidence."""
        text_lower = result.text.lower()
        if "critical" in text_lower and "cve" not in text_lower:
            # Claims critical with no CVE backing — flag it
            if "remote code execution" not in text_lower and "rce" not in text_lower:
                result.warnings.append(
                    "AI claims critical severity without CVE or RCE evidence"
                )
                result.confidence = min(result.confidence, 0.7)
        return result

    def _check_vague_output(self, result: GuardResult) -> GuardResult:
        """Flag vague, non-actionable AI outputs."""
        text = result.text.strip()

        # Too short to be useful
        if len(text) < 50:
            result.warnings.append("AI output is too short to be actionable")
            result.confidence = min(result.confidence, 0.5)

        # Generic phrases that signal hallucination or hedging
        hedge_phrases = [
            "i would recommend",
            "it's important to note",
            "in general,",
            "as a best practice",
            "it depends on",
        ]
        hedge_count = sum(1 for p in hedge_phrases if p in text.lower())
        if hedge_count >= 3:
            result.warnings.append(
                "AI output contains too many generic hedge phrases"
            )
            result.confidence = min(result.confidence, 0.6)

        return result

    def is_trustworthy(self, result: GuardResult) -> bool:
        """Return True if the guarded output is trustworthy enough to use."""
        return result.confidence >= 0.5 and len(result.stripped_cves) == 0
