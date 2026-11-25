"""Correlation engine — orchestrates dedup, enrichment, and chain building."""

from __future__ import annotations

import logging

from nexus.correlator.dedup import deduplicate_findings
from nexus.correlator.enrichment import (
    KnowledgeGraphLike,
    RemediationLike,
    TaxonomyLike,
    enrich_findings,
)
from nexus.correlator.graph import (
    ChainBuilderLike,
    ExpertEngineLike,
    build_attack_chains,
)
from nexus.db.models import AttackChain, Finding

log = logging.getLogger("nexus.correlator.engine")


def correlate(
    findings: list[Finding],
    *,
    taxonomy: TaxonomyLike | None = None,
    remediation_db: RemediationLike | None = None,
    knowledge_graph: KnowledgeGraphLike | None = None,
    chain_builder: ChainBuilderLike | None = None,
    expert: ExpertEngineLike | None = None,
) -> tuple[list[Finding], list[AttackChain]]:
    """Full correlation pipeline: dedup → enrich → chain."""
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
        len(findings),
        len(chains),
    )
    return findings, chains
