"""NEXUS Correlator — deduplication, enrichment, and attack chain building."""

from nexus.correlator.dedup import deduplicate_findings
from nexus.correlator.engine import correlate
from nexus.correlator.enrichment import enrich_findings
from nexus.correlator.graph import build_attack_chains

__all__ = [
    "deduplicate_findings",
    "enrich_findings",
    "build_attack_chains",
    "correlate",
]
