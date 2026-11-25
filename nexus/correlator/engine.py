"""Correlation engine — orchestrates dedup, enrichment, and chain building."""

from __future__ import annotations

import logging
from typing import Any

from nexus.correlator.dedup import deduplicate_findings
from nexus.correlator.enrichment import enrich_findings
from nexus.correlator.graph import build_attack_chains
from nexus.db.models import AttackChain, Finding

log = logging.getLogger("nexus.correlator.engine")


def correlate(
    findings: list[Finding],
    *,
    taxonomy: Any = None,
    remediation_db: Any = None,
    knowledge_graph: Any = None,
    chain_builder: Any = None,
    expert: Any = None,
) -> tuple[list[Finding], list[AttackChain]]:
    """Full correlation pipeline: dedup → enrich → chain.

    Args:
        findings: raw findings from all scanners.
        taxonomy: TaxonomyMapper.
        remediation_db: RemediationDB.
        knowledge_graph: KnowledgeGraph.
        chain_builder: ChainBuilder.
        expert: RuleEngine.

    Returns:
        (deduplicated_enriched_findings, attack_chains)
    """
    log.info("Starting correlation of %d findings", len(findings))

    # Step 1: Deduplicate
    findings = deduplicate_findings(findings)

    # Step 2: Enrich
    findings = enrich_findings(
        findings,
        taxonomy=taxonomy,
        remediation_db=remediation_db,
        knowledge_graph=knowledge_graph,
    )

    # Step 3: Build attack chains
    chains = build_attack_chains(
        findings,
        chain_builder=chain_builder,
        expert=expert,
    )

    log.info(
        "Correlation complete: %d findings, %d attack chains",
        len(findings), len(chains),
    )
    return findings, chains
