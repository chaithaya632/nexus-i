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


class TestWave6ExtendedCatalogAndKevSync:
    """Extended standalone CVE catalog (>=75 CVEs) and CISA KEV / NVD offline import."""

    def test_extended_catalog_count_and_database_version_bounds(self) -> None:
        cfg = NexusConfig()
        kg = KnowledgeGraph()
        kg.load_from_directory(cfg.knowledge_dir)
        assert kg.cve_count >= 75

        pg_vuln = {e.cve for _, e in kg.match_banner_vulns("postgresql", "PostgreSQL 15.3")}
        assert "CVE-2023-39417" in pg_vuln
        pg_safe = {e.cve for _, e in kg.match_banner_vulns("postgresql", "PostgreSQL 16.4")}
        assert "CVE-2023-39417" not in pg_safe

        ssl_vuln = {e.cve for _, e in kg.match_banner_vulns("ssl", "OpenSSL 3.0.2")}
        assert "CVE-2022-3602" in ssl_vuln
        ssl_safe = {e.cve for _, e in kg.match_banner_vulns("ssl", "OpenSSL 3.3.2")}
        assert "CVE-2022-3602" not in ssl_safe

    def test_import_cisa_kev_and_nvd_autoloaded_on_engine_boot(self, tmp_path: Path) -> None:
        import json

        from nexus.brain.cve_sync import import_cisa_kev_file, import_nvd_json_file

        kev_json = tmp_path / "kev.json"
        kev_json.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-99991",
                            "vendorProject": "Acme",
                            "product": "EdgeGateway",
                            "shortDescription": "Acme EdgeGateway auth bypass",
                            "requiredAction": "Upgrade EdgeGateway to 5.1+",
                            "knownRansomwareCampaignUse": "Known",
                            "cwes": ["CWE-287"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        nvd_json = tmp_path / "nvd.json"
        nvd_json.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-99992",
                                "descriptions": [
                                    {"lang": "en", "value": "Acme EdgePortal path traversal"}
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseScore": 8.6, "baseSeverity": "HIGH"}}
                                    ]
                                },
                                "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                                "configurations": [
                                    {
                                        "nodes": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "vulnerable": True,
                                                        "criteria": "cpe:2.3:a:acme:edgeportal:*:*:*:*:*:*:*:*",
                                                        "versionStartIncluding": "2.0.0",
                                                        "versionEndExcluding": "2.4.1",
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        data_dir = tmp_path / "nexus_data"
        c_kev, _ = import_cisa_kev_file(kev_json, data_dir)
        c_nvd, _ = import_nvd_json_file(nvd_json, data_dir)
        assert c_kev == 1 and c_nvd == 1

        cfg = NexusConfig(
            data_dir=data_dir, db_path=tmp_path / "sync.db", output_dir=tmp_path / "out"
        )
        eng = NexusEngine(cfg)
        eng.boot()
        try:
            assert eng.knowledge.has_cve("CVE-2024-99991")
            assert eng.knowledge.has_cve("CVE-2024-99992")
            matched = {
                e.cve for _, e in eng.knowledge.match_banner_vulns("edgeportal", "EdgePortal 2.2.0")
            }
            assert "CVE-2024-99992" in matched
            patched = {
                e.cve for _, e in eng.knowledge.match_banner_vulns("edgeportal", "EdgePortal 2.4.1")
            }
            assert "CVE-2024-99992" not in patched
        finally:
            eng.shutdown()

    def test_bundled_cisa_kev_snapshot_enriches_without_banner_false_positives(self) -> None:
        cfg = NexusConfig()
        kg = KnowledgeGraph()
        kg.load_from_directory(cfg.knowledge_dir)

        assert kg.cve_count >= 1500
        assert kg.has_cve("CVE-2021-44228")

        # Unversioned KEV entries must not false-positive on patched banners
        patched_cves = {e.cve for _, e in kg.match_banner_vulns("http", "Apache/2.4.62")}
        assert "CVE-2021-41773" not in patched_cves
