"""Correlation phase runner — dedup, enrichment, baseline suppression, and chains."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from nexus.correlator.baseline import (
    apply_baseline_suppressions,
    load_ignore_rules,
    resolve_ignore_path,
)
from nexus.db.models import AttackChain, EngagementPhase, Severity

if TYPE_CHECKING:
    from nexus.core.engine import NexusEngine

log = logging.getLogger("nexus.engine.correlate")


class CorrelatePhase:
    """Executes finding deduplication, enrichment, chain building, and post-hooks."""

    async def run(self, engine: NexusEngine, eng_id: str) -> list[AttackChain]:
        import nexus.core.engine as eng_mod

        engine._require_boot()
        engine._require_subsystems("db", "audit")
        if engine.db is None or engine.audit is None:
            raise RuntimeError("Database or audit logger not initialized.")

        engine._advance_phase(eng_id, EngagementPhase.CORRELATE)

        findings = engine.db.get_findings(eng_id)
        if not findings:
            log.info("[CORRELATE] No findings to correlate.")
            return []

        enriched, chains = eng_mod.correlate_findings(
            findings,
            taxonomy=engine.taxonomy,
            remediation_db=engine.remediation,
            knowledge_graph=engine.knowledge,
            chain_builder=engine.chains,
            expert=engine.expert,
        )

        # AI-enhance high/critical findings in threadpool (optional, silent fallback)
        if engine.ai_boost and engine.ai_boost.available:
            try:
                for f in enriched:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        enhanced_dict = await asyncio.to_thread(
                            engine.ai_boost.enhance_finding,
                            f.model_dump(),
                        )
                        analysis = enhanced_dict.get("ai_analysis", "")
                        if analysis:
                            f.evidence = (f.evidence + "\n\n[AI Analysis]\n" + analysis).strip()[
                                :4000
                            ]
                log.info("[CORRELATE] AI enhanced critical/high findings")
            except Exception as exc:
                log.debug("[CORRELATE] AI enhancement skipped: %s", exc)

        ignore_path = resolve_ignore_path(engine.config.ignore_file)
        suppressed_count = 0
        if ignore_path:
            rules = load_ignore_rules(ignore_path)
            if rules:
                enriched, suppressed_count = apply_baseline_suppressions(enriched, rules)
                if suppressed_count:
                    engine.audit.log_action(
                        "baseline_suppressed",
                        extra={
                            "id": eng_id,
                            "ignore_file": str(ignore_path),
                            "suppressed": suppressed_count,
                        },
                    )
                    log.info(
                        "[CORRELATE] Suppressed %d finding(s) via %s",
                        suppressed_count,
                        ignore_path,
                    )

        engine.db.replace_findings(eng_id, enriched)

        for chain in chains:
            chain.engagement_id = eng_id
        if hasattr(engine.db, "replace_chains"):
            engine.db.replace_chains(eng_id, chains)
        else:
            with engine.db._cursor() as cur:
                cur.execute("DELETE FROM chains WHERE engagement_id = ?", (eng_id,))
            for chain in chains:
                engine.db.add_chain(chain)

        if engine.plugins and engine.plugins.registry.post_hooks:
            await engine.plugins.registry.run_post_hooks(
                eng_id=eng_id,
                findings=enriched,
                chains=chains,
            )

        engine.audit.log_action(
            "correlate_complete",
            extra={
                "id": eng_id,
                "findings_enriched": len(enriched),
                "chains_built": len(chains),
            },
        )
        await engine._emit_progress(
            "correlate_complete",
            {
                "engagement_id": eng_id,
                "findings_enriched": len(enriched),
                "chains_built": len(chains),
            },
        )
        log.info(
            "[CORRELATE] Complete — %d enriched findings, %d attack chains",
            len(enriched),
            len(chains),
        )
        return chains
