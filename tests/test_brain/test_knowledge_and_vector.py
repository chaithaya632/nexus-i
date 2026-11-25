"""Tests for Wave 1 KnowledgeGraph banner/SemVer matching and VectorSearch indexing."""

from __future__ import annotations

from pathlib import Path

from nexus.brain.knowledge_graph import KnowledgeGraph, _version_in_range
from nexus.core.config import NexusConfig, ScanProfile, StealthLevel, Tier
from nexus.core.engine import NexusEngine


class TestBannerVersionMatching:
    """SemVer and range-aware banner-to-CVE correlation."""

    def test_apache_2449_matches_path_traversal_patched_2462_does_not(self) -> None:
        cfg = NexusConfig()
        kg = KnowledgeGraph()
        kg.load_from_directory(cfg.knowledge_dir)

        vuln_matches = kg.match_banner_vulns("http", "Apache/2.4.49")
        vuln_cves = {entry.cve for _, entry in vuln_matches}
        assert "CVE-2021-41773" in vuln_cves

        patched_matches = kg.match_banner_vulns("http", "Apache/2.4.62")
        patched_cves = {entry.cve for _, entry in patched_matches}
        assert "CVE-2021-41773" not in patched_cves

    def test_openssh_range_85_to_97_matches_89_not_98(self) -> None:
        cfg = NexusConfig()
        kg = KnowledgeGraph()
        kg.load_from_directory(cfg.knowledge_dir)

        vuln_cves = {entry.cve for _, entry in kg.match_banner_vulns("ssh", "OpenSSH 8.9p1")}
        assert "CVE-2024-6387" in vuln_cves
        assert "CVE-2023-38408" in vuln_cves

        patched_cves = {entry.cve for _, entry in kg.match_banner_vulns("ssh", "OpenSSH 9.8p1")}
        assert "CVE-2024-6387" not in patched_cves
        assert "CVE-2023-38408" not in patched_cves

    def test_version_in_range_comparators(self) -> None:
        assert _version_in_range("Apache/2.4.49", "apache-2.4.49") is True
        assert _version_in_range("Apache/2.4.62", "apache-2.4.49-2.4.50") is False
        assert _version_in_range("OpenSSH 9.3p1", "openssh-8.5-9.7") is True
        assert _version_in_range("OpenSSH 9.8p1", "openssh-8.5-9.7") is False
        assert _version_in_range("nginx 1.18.0", "<1.20.0") is True
        assert _version_in_range("nginx 1.24.0", "<1.20.0") is False


class TestVectorSearchBootIndex:
    """Engine boot populates VectorSearch from KnowledgeGraph and RemediationDB."""

    def test_engine_populates_vector_search(self, tmp_path: Path) -> None:
        cfg = NexusConfig(
            data_dir=tmp_path / "vec_data",
            db_path=str(tmp_path / "vec.db"),
            tier=Tier.MINIMAL,
            stealth=StealthLevel.OFF,
            profile=ScanProfile.QUICK,
        )
        eng = NexusEngine(cfg)
        eng.boot()
        try:
            assert eng.vector is not None
            assert eng.vector.entry_count >= 20
            stats = eng.brain_stats()
            assert stats.get("vector_entries", 0) >= 20

            hits = eng.vector.search("Apache Log4j JNDI RCE", top_k=5)
            hit_ids = [item[0] for item in hits]
            assert "CVE-2021-44228" in hit_ids
        finally:
            eng.shutdown()
