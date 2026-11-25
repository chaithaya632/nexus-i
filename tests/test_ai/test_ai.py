"""Tests for the AI Boost Layer — all tests run WITHOUT Ollama (fully mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from nexus.ai.ollama_client import OllamaClient, RECOMMENDED_MODELS
from nexus.ai.prompts import (
    SECURITY_ANALYST_SYSTEM,
    finding_analysis_prompt,
    chain_analysis_prompt,
    executive_summary_prompt,
    exploit_suggestion_prompt,
    remediation_prompt,
)
from nexus.ai.guard import AIGuard, GuardResult
from nexus.ai.boost import AIBoost


# ── OllamaClient tests (mocked HTTP) ─────────────────────────────


class TestOllamaClient:
    def test_is_alive_returns_false_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.is_alive() is False

    def test_list_models_returns_empty_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.list_models() == []

    def test_has_model_returns_false_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.has_model("dolphin-mistral") is False

    def test_generate_returns_empty_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.generate("test prompt") == ""

    def test_chat_returns_empty_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.chat([{"role": "user", "content": "test"}]) == ""

    def test_embed_returns_empty_when_offline(self):
        client = OllamaClient("http://127.0.0.1:99999")
        assert client.embed("test") == []

    def test_recommended_models_has_entries(self):
        assert len(RECOMMENDED_MODELS) >= 4
        for m in RECOMMENDED_MODELS:
            assert "name" in m
            assert "tier" in m


# ── Prompt tests ──────────────────────────────────────────────────


class TestPrompts:
    def test_system_prompts_are_strings(self):
        assert "NEXUS-AI" in SECURITY_ANALYST_SYSTEM
        assert len(SECURITY_ANALYST_SYSTEM) > 50

    def test_finding_analysis_prompt(self):
        finding = {
            "title": "SQL Injection",
            "severity": "critical",
            "host": "example.com",
            "port": 443,
            "cve_ids": ["CVE-2023-1234"],
            "cwe_id": "CWE-89",
            "description": "Union-based SQLi in login form",
            "evidence": "SELECT * FROM users",
        }
        prompt = finding_analysis_prompt(finding)
        assert "SQL Injection" in prompt
        assert "CVE-2023-1234" in prompt
        assert "CWE-89" in prompt
        assert "exploitability" in prompt.lower()

    def test_chain_analysis_prompt(self):
        chain = {
            "name": "RCE via upload",
            "steps": [{"action": "upload", "tool": "curl", "target": "example.com"}],
            "confidence": 0.8,
        }
        prompt = chain_analysis_prompt(chain, [])
        assert "RCE via upload" in prompt
        assert "80%" in prompt

    def test_executive_summary_prompt(self):
        prompt = executive_summary_prompt(
            "example.com", 42, {"critical": 3, "high": 10, "medium": 20}, 5, 2,
        )
        assert "example.com" in prompt
        assert "42" in prompt
        assert "Critical: 3" in prompt

    def test_exploit_suggestion_prompt(self):
        prompt = exploit_suggestion_prompt(
            {"title": "SQLi", "severity": "high", "host": "x.com", "port": 80, "cve_ids": []},
            ["sqlmap", "hydra"],
        )
        assert "sqlmap" in prompt
        assert "SQLi" in prompt

    def test_remediation_prompt(self):
        prompt = remediation_prompt({"title": "XSS", "severity": "medium", "cwe_id": "CWE-79"})
        assert "XSS" in prompt
        assert "CWE-79" in prompt


# ── Guard tests ───────────────────────────────────────────────────


class TestAIGuard:
    def test_valid_text_passes(self):
        guard = AIGuard()
        result = guard.validate("This is a detailed finding analysis with specific remediation steps. " * 3)
        assert result.confidence >= 0.9
        assert len(result.warnings) == 0

    def test_fabricated_cve_flagged(self):
        # Mock a knowledge graph that doesn't know about this CVE
        mock_kg = MagicMock()
        mock_kg.has_cve.return_value = False
        guard = AIGuard(knowledge_graph=mock_kg)
        result = guard.validate("This exploits CVE-2099-99999 for remote code execution.")
        assert "CVE-2099-99999" in result.stripped_cves
        assert result.confidence < 1.0
        assert "[UNVERIFIED:" in result.text

    def test_verified_cve_passes(self):
        mock_kg = MagicMock()
        mock_kg.has_cve.return_value = True
        guard = AIGuard(knowledge_graph=mock_kg)
        result = guard.validate("This exploits CVE-2023-1234 for remote code execution.")
        assert "CVE-2023-1234" in result.verified_cves
        assert len(result.stripped_cves) == 0

    def test_short_output_flagged(self):
        guard = AIGuard()
        result = guard.validate("OK")
        assert result.confidence < 1.0
        assert any("too short" in w for w in result.warnings)

    def test_hedge_phrases_flagged(self):
        guard = AIGuard()
        text = (
            "I would recommend that you check this. It's important to note "
            "that in general, this is a concern. As a best practice, you should "
            "review this. It depends on many factors."
        )
        result = guard.validate(text)
        assert result.confidence < 1.0

    def test_is_trustworthy(self):
        guard = AIGuard()
        good = GuardResult(text="detailed analysis " * 10, confidence=0.9)
        bad = GuardResult(text="ok", confidence=0.3, stripped_cves=["CVE-2099-1"])
        assert guard.is_trustworthy(good) is True
        assert guard.is_trustworthy(bad) is False


# ── AIBoost tests (Ollama mocked) ─────────────────────────────────


class TestAIBoost:
    def test_boost_unavailable_by_default(self):
        boost = AIBoost(ollama_host="http://127.0.0.1:99999")
        boost.connect()
        assert boost.available is False

    def test_enhance_finding_noop_when_unavailable(self):
        boost = AIBoost()
        finding = {"title": "SQLi", "severity": "critical"}
        result = boost.enhance_finding(finding)
        assert result is finding  # unchanged
        assert "ai_analysis" not in result

    def test_enhance_findings_noop_when_unavailable(self):
        boost = AIBoost()
        findings = [{"title": "XSS", "severity": "high"}]
        result = boost.enhance_findings(findings)
        assert result is findings

    def test_executive_summary_empty_when_unavailable(self):
        boost = AIBoost()
        result = boost.executive_summary("example.com", 10, {"critical": 1})
        assert result == ""

    def test_suggest_exploits_empty_when_unavailable(self):
        boost = AIBoost()
        result = boost.suggest_exploits({"title": "SQLi", "severity": "high"})
        assert result == ""

    def test_enhanced_remediation_fallback_when_unavailable(self):
        boost = AIBoost()
        result = boost.enhanced_remediation({"title": "XSS", "remediation": "Encode output"})
        assert result == "Encode output"

    def test_status_dict(self):
        boost = AIBoost()
        status = boost.status()
        assert "available" in status
        assert status["available"] is False

    @patch.object(OllamaClient, "is_alive", return_value=True)
    @patch.object(OllamaClient, "list_models", return_value=["dolphin-mistral:latest"])
    @patch.object(OllamaClient, "generate", return_value="Detailed analysis of the SQL injection vulnerability showing high risk. Remediation: use parameterized queries.")
    def test_enhance_finding_with_mocked_ai(self, mock_gen, mock_models, mock_alive):
        boost = AIBoost(model_name="dolphin-mistral")
        boost.connect()
        assert boost.available is True

        finding = {"title": "SQLi", "severity": "critical", "host": "x.com", "port": 80}
        result = boost.enhance_finding(finding)
        assert "ai_analysis" in result
        assert len(result["ai_analysis"]) > 0

    @patch.object(OllamaClient, "is_alive", return_value=True)
    @patch.object(OllamaClient, "list_models", return_value=["dolphin-mistral:latest"])
    @patch.object(OllamaClient, "generate", return_value="The overall security posture is concerning with 3 critical vulnerabilities requiring immediate remediation.")
    def test_executive_summary_with_mocked_ai(self, mock_gen, mock_models, mock_alive):
        boost = AIBoost(model_name="dolphin-mistral")
        boost.connect()
        summary = boost.executive_summary("example.com", 10, {"critical": 3, "high": 5})
        assert "security posture" in summary.lower()
