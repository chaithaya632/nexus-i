"""NexusEngine — central orchestrator for the entire engagement pipeline."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from nexus.core.audit import AuditLogger
from nexus.core.config import NexusConfig, Tier, get_config, set_config
from nexus.core.hardware import HardwareInfo, auto_select_tier, detect_hardware
from nexus.core.scheduler import TaskScheduler
from nexus.core.scope import ScopeEnforcer
from nexus.brain.chain_builder import ChainBuilder
from nexus.brain.credentials import CredentialDB
from nexus.brain.expert import RuleEngine, build_service_rules
from nexus.brain.knowledge_graph import KnowledgeGraph
from nexus.brain.payloads import PayloadDB
from nexus.brain.remediation import RemediationDB
from nexus.brain.router import ServiceRouter
from nexus.brain.taxonomy import TaxonomyMapper
from nexus.brain.vector_search import VectorSearch
from nexus.brain.waf_bypass import WAFBypassLibrary
from nexus.recon.runner import ToolRunner
from nexus.recon.subdomains import enumerate_subdomains
from nexus.recon.ports import nmap_scan
from nexus.recon.tech import detect_tech_stack
from nexus.recon.dns import enumerate_dns
from nexus.recon.waf import detect_waf
from nexus.recon.osint import gather_osint
from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.web import ffuf_scan
from nexus.scanner.nikto import nikto_scan
from nexus.correlator.engine import correlate as correlate_findings
from nexus.exploit.executor import ExploitExecutor, ExploitResult
from nexus.exploit.sqli import sqlmap_scan
from nexus.exploit.credential import hydra_attack, test_default_creds
from nexus.exploit.msf_bridge import MSFBridge
from nexus.stealth.controller import StealthController
from nexus.reporter.generator import generate_report
from nexus.ai.boost import AIBoost
from nexus.plugins import PluginLoader
from nexus.db.models import (
    AttackChain,
    ChainStep,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
    Port,
    Severity,
    Target,
)
from nexus.db.store import EngagementStore


log = logging.getLogger("nexus.engine")
console = Console()

# Map config StealthLevel values -> StealthController/tool profile names
_STEALTH_MAP: dict[str, str] = {
    "off": "loud",
    "low": "loud",
    "medium": "normal",
    "high": "quiet",
    "paranoid": "ghost",
    "loud": "loud",
    "normal": "normal",
    "quiet": "quiet",
    "ghost": "ghost",
}


class NexusEngine:
    """Central orchestrator — wires together every NEXUS subsystem.

    Lifecycle:
        engine = NexusEngine(config)
        engine.boot()
        eng_id = engine.engage("example.com", scope_file="scope.yaml")
        # ... or run individual phases
        engine.shutdown()
    """

    def __init__(self, config: NexusConfig | None = None) -> None:
        self.config = config or get_config()
        set_config(self.config)

        # Hardware
        self.hw: HardwareInfo | None = None

        # Core subsystems (initialized in boot())
        self.db: EngagementStore | None = None
        self.audit: AuditLogger | None = None
        self.scope: ScopeEnforcer | None = None
        self.scheduler: TaskScheduler | None = None

        # Brain subsystems
        self.expert: RuleEngine | None = None
        self.knowledge: KnowledgeGraph | None = None
        self.chains: ChainBuilder | None = None
        self.vector: VectorSearch | None = None
        self.router: ServiceRouter | None = None
        self.cred_db: CredentialDB | None = None
        self.waf: WAFBypassLibrary | None = None
        self.taxonomy: TaxonomyMapper | None = None
        self.payloads: PayloadDB | None = None
        self.remediation: RemediationDB | None = None

        # Stealth + Exploit subsystems
        self.stealth: StealthController | None = None
        self.exploit_executor: ExploitExecutor | None = None
        self.msf: MSFBridge | None = None

        # AI Boost (100% optional)
        self.ai_boost: AIBoost | None = None

        # Plugins
        self.plugins: PluginLoader | None = None

        # State
        self._booted = False
        self._current_engagement: str | None = None

    # ── Boot / Shutdown ───────────────────────────────────────────

    def boot(self) -> None:
        """Initialize all subsystems. Call once before any engagement."""
        if self._booted:
            return

        log.info("Booting NEXUS engine...")

        # Detect hardware and auto-select tier if not forced
        self.hw = detect_hardware()
        if self.config.tier == Tier.MINIMAL:
            auto_tier = auto_select_tier(self.hw)
            if auto_tier != Tier.MINIMAL:
                self.config.tier = auto_tier
                log.info("Auto-selected tier: %s", auto_tier.value)

        # Database
        self.db = EngagementStore(self.config.db_path)

        # Audit log
        audit_path = self.config.data_dir / "audit.jsonl"
        self.audit = AuditLogger(audit_path)

        # Scheduler
        self.scheduler = TaskScheduler(max_concurrent=self.config.max_threads)

        # Brain — Expert System
        self.expert = RuleEngine()
        for rule in build_service_rules():
            self.expert.add_rule(rule)

        # Brain — Knowledge Graph
        self.knowledge = KnowledgeGraph()
        kb_dir = self.config.knowledge_dir
        if kb_dir and kb_dir.is_dir():
            self.knowledge.load_from_directory(kb_dir)

        # Brain — Chain Builder
        self.chains = ChainBuilder()
        self.chains.build_default_graph()
        if kb_dir and kb_dir.is_dir():
            self.chains.load_templates(kb_dir)

        # Brain — Vector Search
        self.vector = VectorSearch()

        # Brain — Service Router
        self.router = ServiceRouter()
        if kb_dir and kb_dir.is_dir():
            self.router.load_from_directory(kb_dir)

        # Brain — Credentials
        self.cred_db = CredentialDB()
        if kb_dir and kb_dir.is_dir():
            self.cred_db.load_from_directory(kb_dir)

        # Brain — WAF Bypass
        self.waf = WAFBypassLibrary()
        if kb_dir and kb_dir.is_dir():
            self.waf.load_from_directory(kb_dir)

        # Brain — Taxonomy Mapper
        self.taxonomy = TaxonomyMapper()

        # Brain — Payloads
        self.payloads = PayloadDB()
        if kb_dir and kb_dir.is_dir():
            self.payloads.load_from_yaml(kb_dir / "payloads")

        # Brain — Remediation
        self.remediation = RemediationDB()
        if kb_dir and kb_dir.is_dir():
            self.remediation.load_from_yaml(kb_dir / "remediations")

        # Stealth controller — map config levels to controller profiles
        stealth_profile = _STEALTH_MAP.get(self.config.stealth.value, "normal")
        self.stealth = StealthController(stealth_profile)

        # Exploit executor (scope + audit enforced)
        self.exploit_executor = ExploitExecutor(
            scope=self.scope,
            audit=self.audit,
        )

        # Plugins
        self.plugins = PluginLoader()
        self.plugins.load_builtin()

        # MSF bridge (optional)
        self.msf = MSFBridge()

        # AI Boost (optional — tries Ollama, falls back to expert system)
        self.ai_boost = AIBoost(
            ollama_host=self.config.ollama_host,
            model_name=self.config.model_name,
            knowledge_graph=self.knowledge,
            expert=self.expert,
            taxonomy=self.taxonomy,
        )
        self.ai_boost.connect()  # Non-blocking — sets .available flag

        self._booted = True
        self.audit.log_action("engine_boot", tool="nexus", result="success",
                              extra={"tier": self.config.tier.value,
                                     "ram_mb": self.hw.ram_total_mb,
                                     "cpu_cores": self.hw.cpu_cores})
        log.info("NEXUS engine booted — Tier: %s, RAM: %dMB, CPUs: %d",
                 self.config.tier.value, self.hw.ram_total_mb, self.hw.cpu_cores)

    def shutdown(self) -> None:
        if self.ai_boost:
            self.ai_boost.close()
        if self.audit:
            self.audit.log_action("engine_shutdown", tool="nexus", result="clean")
        self._booted = False
        log.info("NEXUS engine shut down.")

    def _require_boot(self) -> None:
        if not self._booted:
            raise RuntimeError("NexusEngine.boot() must be called before operations.")

    # ── Engagement Management ─────────────────────────────────────

    def _set_scope(self, enforcer: ScopeEnforcer) -> None:
        """Bind a ScopeEnforcer to both engine and exploit executor."""
        self.scope = enforcer
        if self.exploit_executor is not None:
            self.exploit_executor._scope = enforcer

    def _active_stealth_profile(self) -> str:
        """Sync StealthController with config.stealth and return tool profile name."""
        profile = _STEALTH_MAP.get(self.config.stealth.value, "normal")
        if self.stealth is not None and self.stealth.level != profile:
            self.stealth.set_level(profile)
        return profile

    def _is_in_scope(self, target: str, port: int | None = None) -> bool:
        """Return True if target (and optional port) is permitted by active scope."""
        if self.scope is None:
            return True
        if not self.scope.is_in_scope(target):
            return False
        if port is not None and not self.scope.is_port_allowed(port):
            return False
        return True

    def create_engagement(
        self,
        target: str,
        name: str = "",
        scope_file: str | None = None,
    ) -> Engagement:
        """Create a new engagement and return its model."""
        self._require_boot()
        assert self.db is not None
        assert self.audit is not None

        eng = Engagement(
            name=name or f"engagement_{target}",
            target=target,
            scope_file=scope_file or "",
            stealth=self.config.stealth.value,
            tier=self.config.tier.value,
        )
        self.db.create_engagement(eng)
        self._current_engagement = eng.id

        # Load scope if provided (enforces both engine phases and ExploitExecutor)
        if scope_file:
            self._set_scope(ScopeEnforcer.from_file(scope_file))
        else:
            self._set_scope(ScopeEnforcer.allow_all())
            log.warning("No scope file — running with unrestricted scope (testing only).")

        self.audit.log_action("engagement_created", target=target,
                              extra={"id": eng.id, "scope_file": scope_file or "none"})
        return eng

    def resume_engagement(self, eng_id: str) -> Engagement | None:
        """Resume an existing engagement."""
        self._require_boot()
        assert self.db is not None

        eng = self.db.get_engagement(eng_id)
        if not eng:
            return None
        self._current_engagement = eng.id

        if eng.scope_file:
            self._set_scope(ScopeEnforcer.from_file(eng.scope_file))
        else:
            self._set_scope(ScopeEnforcer.allow_all())

        if self.audit:
            self.audit.log_action("engagement_resumed", target=eng.target,
                                  extra={"id": eng.id, "phase": eng.phase.value})
        return eng

    def _advance_phase(self, eng_id: str, phase: EngagementPhase) -> None:
        assert self.db is not None
        assert self.audit is not None
        self.db.update_phase(eng_id, phase)
        self.audit.log_action("phase_change", extra={"id": eng_id, "phase": phase.value})

    # ── Phase Runners (stubs for Phase 2–4 tool integration) ──────

    async def run_recon(self, eng_id: str, target: str) -> list[Finding]:
        """Run reconnaissance phase — subdomain enum → DNS → ports → tech → WAF → OSINT."""
        self._require_boot()
        assert self.audit is not None
        assert self.db is not None
        assert self.scheduler is not None

        if not self._is_in_scope(target):
            raise ValueError(f"SCOPE VIOLATION: Target '{target}' is outside authorized scope.")

        self._advance_phase(eng_id, EngagementPhase.RECON)
        self.audit.log_action("recon_start", target=target, extra={"id": eng_id})

        all_findings: list[Finding] = []
        stealth = self._active_stealth_profile()

        # 1. Subdomain enumeration (use bounded passive mode; filter by scope)
        log.info("[RECON] Subdomain enumeration for %s (stealth=%s)", target, stealth)
        raw_targets = await enumerate_subdomains(
            target,
            use_amass=(stealth in ("loud", "normal")),
            passive_only=(stealth in ("quiet", "ghost")),
            timeout=90,
        )
        targets: list[Target] = []
        seen_hosts: set[str] = set()
        for t in raw_targets:
            host_l = t.host.lower().strip()
            if not host_l or host_l in seen_hosts:
                continue
            if not self._is_in_scope(host_l):
                log.debug("[RECON] Skipping out-of-scope subdomain: %s", host_l)
                continue
            seen_hosts.add(host_l)
            t.engagement_id = eng_id
            targets.append(t)

        if not targets:
            targets = [Target(engagement_id=eng_id, host=target.strip().lower())]
            seen_hosts.add(targets[0].host)
        log.info("[RECON] %d in-scope target(s) discovered", len(targets))

        # 2. DNS resolution
        log.info("[RECON] DNS resolution")
        targets, dns_findings = await enumerate_dns(targets)
        for f in dns_findings:
            f.engagement_id = eng_id
        all_findings.extend(dns_findings)

        # Persist targets BEFORE adding ports so FK(target_id -> targets.id) never fails
        for t in targets:
            self.db.add_target(t)

        # 3. Port scanning (bounded parallelism; stealth-ordered if needed)
        scan_targets = self.stealth.shuffle_targets(targets) if self.stealth else targets
        log.info("[RECON] Port scanning %d targets", len(scan_targets))
        for t in scan_targets:
            scan_target = t.ip or t.host
            if not scan_target or not self._is_in_scope(scan_target):
                continue
            try:
                result = await nmap_scan(scan_target, stealth=stealth)
                for scanned_t in result["targets"]:
                    if scanned_t.os_guess and not t.os_guess:
                        t.os_guess = scanned_t.os_guess
                    if scanned_t.is_live:
                        t.is_live = True
                self.db.add_target(t)
                for port in result["ports"]:
                    if not self._is_in_scope(scan_target, port.port):
                        continue
                    port.target_id = t.id
                    self.db.add_port(port)
                for f in result["findings"]:
                    if f.port and not self._is_in_scope(f.host or scan_target, f.port):
                        continue
                    f.engagement_id = eng_id
                    all_findings.append(f)
            except Exception as exc:
                log.warning("[RECON] nmap failed for %s: %s", scan_target, exc)

        # 4. Tech-stack detection
        log.info("[RECON] Tech-stack detection")
        targets = await detect_tech_stack(targets)

        # 5. WAF detection
        log.info("[RECON] WAF detection")
        targets, waf_findings = await detect_waf(targets)
        for f in waf_findings:
            f.engagement_id = eng_id
        all_findings.extend(waf_findings)

        # Feed WAF results into brain
        if self.waf:
            for t in targets:
                if t.waf_detected and self.expert:
                    self.expert.add_fact(
                        f"waf_{t.waf_detected.lower().replace(' ', '_')}",
                        True, source="wafw00f",
                    )

        # 6. OSINT gathering (filter new targets against scope)
        log.info("[RECON] OSINT gathering")
        osint_targets, osint_findings = await gather_osint(target)
        for t2 in osint_targets:
            h_l = t2.host.lower().strip()
            if h_l and h_l not in seen_hosts and self._is_in_scope(h_l):
                seen_hosts.add(h_l)
                t2.engagement_id = eng_id
                targets.append(t2)
        for f in osint_findings:
            f.engagement_id = eng_id
        all_findings.extend(osint_findings)

        # 7. Plugin recon modules
        if self.plugins and self.plugins.registry.recon_modules:
            for pname, rfn in self.plugins.registry.recon_modules.items():
                try:
                    p_findings = await rfn(target, targets=targets)
                    for pf in p_findings or []:
                        if isinstance(pf, Finding):
                            pf.engagement_id = eng_id
                            all_findings.append(pf)
                except Exception as exc:
                    log.warning("[RECON] Plugin '%s' failed: %s", pname, exc)

        # Persist final enriched target state (safe ON CONFLICT UPDATE)
        for t in targets:
            self.db.add_target(t)

        # Persist findings
        for f in all_findings:
            self.db.add_finding(f)

        # Feed open ports into expert system
        if self.expert:
            for f in all_findings:
                if f.port:
                    self.expert.add_fact(f"port_{f.port}", True, source=f.tool_source)

        self.audit.log_action("recon_complete", target=target, extra={
            "id": eng_id,
            "targets_found": len(targets),
            "findings": len(all_findings),
        })
        log.info(
            "[RECON] Complete — %d targets, %d findings",
            len(targets), len(all_findings),
        )
        return all_findings

    async def run_scan(self, eng_id: str, target: str) -> list[Finding]:
        """Run scanning phase — nuclei, ffuf, nikto on discovered targets."""
        self._require_boot()
        assert self.audit is not None
        assert self.db is not None
        self._advance_phase(eng_id, EngagementPhase.SCAN)
        self.audit.log_action("scan_start", target=target, extra={"id": eng_id})

        all_findings: list[Finding] = []
        stealth = self._active_stealth_profile()
        targets_db = self.db.get_targets(eng_id)

        url_set: list[str] = []
        seen_urls: set[str] = set()

        def _add_url(u: str) -> None:
            if u not in seen_urls:
                seen_urls.add(u)
                url_set.append(u)

        for t in targets_db:
            host = t.host
            if not host or not self._is_in_scope(host):
                continue
            open_ports = self.db.get_ports(t.id)
            if open_ports:
                for p in open_ports:
                    if not self._is_in_scope(host, p.port):
                        continue
                    svc = p.service.lower()
                    if p.port in (443, 8443, 4443) or "https" in svc or "ssl" in svc:
                        scheme = "https"
                        suffix = "" if p.port == 443 else f":{p.port}"
                        _add_url(f"{scheme}://{host}{suffix}")
                    elif p.port in (80, 8000, 8080, 8081, 8888, 3000, 5000, 9000) or "http" in svc:
                        suffix = "" if p.port == 80 else f":{p.port}"
                        _add_url(f"http://{host}{suffix}")
            else:
                _add_url(f"http://{host}")
                _add_url(f"https://{host}")

        if not url_set and self._is_in_scope(target):
            _add_url(f"http://{target}")
            _add_url(f"https://{target}")

        urls = url_set

        # 1. Nuclei vulnerability scan
        if ToolRunner.is_available("nuclei") and urls:
            log.info("[SCAN] Running nuclei on %d URLs", len(urls))
            try:
                nuclei_findings = await nuclei_scan(
                    urls, stealth=stealth,
                    severity_filter=["critical", "high", "medium", "low"],
                )
                for f in nuclei_findings:
                    f.engagement_id = eng_id
                all_findings.extend(nuclei_findings)
            except Exception as exc:
                log.warning("[SCAN] nuclei failed: %s", exc)
        elif urls:
            log.warning("[SCAN] nuclei not found — skipping vulnerability scan")

        # 2. ffuf directory brute-force (base URLs discovered, fallback to target)
        ffuf_targets = urls[:4] if urls else ([f"http://{target}", f"https://{target}"] if self._is_in_scope(target) else [])
        if ToolRunner.is_available("ffuf") and ffuf_targets:
            for base in ffuf_targets:
                log.info("[SCAN] Running ffuf on %s", base)
                try:
                    ffuf_findings = await ffuf_scan(base, stealth=stealth)
                    for f in ffuf_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(ffuf_findings)
                except Exception as exc:
                    log.warning("[SCAN] ffuf failed on %s: %s", base, exc)
        elif ffuf_targets:
            log.warning("[SCAN] ffuf not found — skipping directory scan")

        # 3. Nikto web server scan
        if ToolRunner.is_available("nikto") and ffuf_targets:
            for base in ffuf_targets[:2]:
                log.info("[SCAN] Running nikto on %s", base)
                try:
                    nikto_findings = await nikto_scan(base)
                    for f in nikto_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(nikto_findings)
                except Exception as exc:
                    log.warning("[SCAN] nikto failed on %s: %s", base, exc)
        elif ffuf_targets:
            log.warning("[SCAN] nikto not found — skipping web server scan")

        # 4. Plugin scanners
        if self.plugins and self.plugins.registry.scanners:
            for pname, sfn in self.plugins.registry.scanners.items():
                try:
                    p_findings = await sfn(target, urls=urls)
                    for pf in p_findings or []:
                        if isinstance(pf, Finding):
                            pf.engagement_id = eng_id
                            all_findings.append(pf)
                except Exception as exc:
                    log.warning("[SCAN] Plugin '%s' failed: %s", pname, exc)

        # Persist
        for f in all_findings:
            self.db.add_finding(f)

        self.audit.log_action("scan_complete", target=target, extra={
            "id": eng_id, "findings": len(all_findings),
        })
        log.info("[SCAN] Complete — %d findings", len(all_findings))
        return all_findings

    async def run_correlate(self, eng_id: str) -> list[AttackChain]:
        """Correlate findings — dedup, enrich, build attack chains."""
        self._require_boot()
        assert self.db is not None
        assert self.audit is not None

        self._advance_phase(eng_id, EngagementPhase.CORRELATE)

        findings = self.db.get_findings(eng_id)
        if not findings:
            log.info("[CORRELATE] No findings to correlate.")
            return []

        # Run the full correlation pipeline
        enriched, chains = correlate_findings(
            findings,
            taxonomy=self.taxonomy,
            remediation_db=self.remediation,
            knowledge_graph=self.knowledge,
            chain_builder=self.chains,
            expert=self.expert,
        )

        # AI-enhance high/critical findings (optional, silent fallback)
        if self.ai_boost and self.ai_boost.available:
            try:
                for f in enriched:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        enhanced_dict = self.ai_boost.enhance_finding(f.model_dump())
                        analysis = enhanced_dict.get("ai_analysis", "")
                        if analysis:
                            f.evidence = (f.evidence + "\n\n[AI Analysis]\n" + analysis).strip()[:4000]
                log.info("[CORRELATE] AI enhanced critical/high findings")
            except Exception as exc:
                log.debug("[CORRELATE] AI enhancement skipped: %s", exc)

        # Persist deduplicated & enriched findings back to SQLite so reports reflect enrichment
        self.db.replace_findings(eng_id, enriched)

        # Persist chains
        for chain in chains:
            chain.engagement_id = eng_id
            self.db.add_chain(chain)

        # Plugin post-correlation hooks
        if self.plugins and self.plugins.registry.post_hooks:
            for hook in self.plugins.registry.post_hooks:
                try:
                    hook(eng_id=eng_id, findings=enriched, chains=chains)
                except Exception as exc:
                    log.warning("[CORRELATE] Plugin post-hook failed: %s", exc)

        self.audit.log_action("correlate_complete", extra={
            "id": eng_id,
            "findings_enriched": len(enriched),
            "chains_built": len(chains),
        })
        log.info(
            "[CORRELATE] Complete — %d enriched findings, %d attack chains",
            len(enriched), len(chains),
        )
        return chains

    async def run_exploit(self, eng_id: str) -> list[Finding]:
        """Run exploitation phase — test default creds and known SQLi on discovered services."""
        self._require_boot()
        assert self.audit is not None
        assert self.db is not None

        self._advance_phase(eng_id, EngagementPhase.EXPLOIT)
        self.audit.log_action("exploit_start", extra={"id": eng_id})

        all_findings: list[Finding] = []
        all_creds: list[Credential] = []

        findings = self.db.get_findings(eng_id)
        targets = self.db.get_targets(eng_id)

        # 1. Test default credentials on open services (scope + audit enforced)
        if ToolRunner.is_available("hydra") and self.cred_db:
            tested_services: set[tuple[str, int, str]] = set()
            for t in targets:
                host = t.host
                if not host:
                    continue
                service_ports: dict[int, str] = {
                    22: "ssh", 21: "ftp", 3306: "mysql", 5432: "postgres",
                }
                for f in findings:
                    if f.host != host or not f.port:
                        continue
                    service = service_ports.get(f.port, "")
                    key = (host, f.port, service)
                    if not service or key in tested_services:
                        continue
                    tested_services.add(key)

                    default_creds = self.cred_db.lookup(service)
                    if not default_creds:
                        continue
                    cred_pairs = [
                        (c.get("username", ""), c.get("password", ""))
                        for c in default_creds[:5]
                        if c.get("username") or c.get("password")
                    ]
                    if not cred_pairs:
                        continue

                    if not self._is_in_scope(host, f.port):
                        log.warning("[EXPLOIT] Blocked by scope: %s:%s", host, f.port)
                        self.audit.log_action(
                            "exploit_scope_denied", tool="hydra", target=host,
                            result="denied", extra={"port": f.port},
                        )
                        continue

                    try:
                        self.audit.log_action(
                            "exploit_attempt", tool="hydra", target=host,
                            extra={"port": f.port, "service": service},
                        )
                        creds, cred_findings = await test_default_creds(
                            host, f.port, service, cred_pairs, timeout=60,
                        )
                        for c in creds:
                            c.engagement_id = eng_id
                            self.db.add_credential(c)
                        all_creds.extend(creds)
                        for ef in cred_findings:
                            ef.engagement_id = eng_id
                        all_findings.extend(cred_findings)
                    except Exception as exc:
                        log.warning("[EXPLOIT] hydra failed on %s:%d: %s", host, f.port, exc)
        else:
            log.warning("[EXPLOIT] hydra not found — skipping credential testing")

        # 2. SQLi testing on HTTP findings with parameters (scope + audit enforced)
        if ToolRunner.is_available("sqlmap"):
            tested_urls: set[str] = set()
            for f in findings:
                if "?" in f.evidence and "=" in f.evidence:
                    for line in f.evidence.splitlines():
                        if "?" in line and "=" in line and "http" in line.lower():
                            url = line.strip().split()[-1] if line.strip() else ""
                            if not url.startswith("http") or url in tested_urls:
                                continue
                            tested_urls.add(url)
                            sqli_host = url.split("://", 1)[1].split("/")[0].split(":")[0]
                            if not self._is_in_scope(sqli_host, f.port):
                                log.warning("[EXPLOIT] Blocked by scope: %s", url)
                                self.audit.log_action(
                                    "exploit_scope_denied", tool="sqlmap", target=sqli_host,
                                    result="denied", extra={"url": url},
                                )
                                break
                            try:
                                self.audit.log_action(
                                    "exploit_attempt", tool="sqlmap", target=sqli_host,
                                    extra={"url": url},
                                )
                                sqli_findings = await sqlmap_scan(url, timeout=120)
                                for sf in sqli_findings:
                                    sf.engagement_id = eng_id
                                all_findings.extend(sqli_findings)
                            except Exception as exc:
                                log.warning("[EXPLOIT] sqlmap failed: %s", exc)
                            break
        else:
            log.warning("[EXPLOIT] sqlmap not found — skipping SQLi testing")

        # Persist findings
        for f in all_findings:
            self.db.add_finding(f)

        self.audit.log_action("exploit_complete", extra={
            "id": eng_id,
            "findings": len(all_findings),
            "credentials": len(all_creds),
        })
        log.info("[EXPLOIT] Complete — %d findings, %d credentials", len(all_findings), len(all_creds))
        return all_findings

    # ── Full Engagement Pipeline ──────────────────────────────────

    async def engage(
        self,
        target: str,
        name: str = "",
        scope_file: str | None = None,
        skip_exploit: bool = False,
    ) -> str:
        """Run the complete engagement pipeline: Recon → Scan → Correlate → Exploit → Report.

        Returns the engagement ID.
        """
        self._require_boot()
        assert self.audit is not None

        eng = self.create_engagement(target, name, scope_file)
        eng_id = eng.id

        self.audit.log_action("engage_start", target=target,
                              extra={"id": eng_id, "skip_exploit": skip_exploit})

        try:
            # Phase 1: Recon
            await self.run_recon(eng_id, target)

            # Phase 2: Scan
            await self.run_scan(eng_id, target)

            # Phase 3: Correlate
            await self.run_correlate(eng_id)

            # Phase 4: Exploit (optional)
            if not skip_exploit:
                await self.run_exploit(eng_id)

            # Phase 5: Report
            self._advance_phase(eng_id, EngagementPhase.REPORT)

            # AI executive summary (optional, silent fallback)
            ai_summary = ""
            if self.ai_boost and self.ai_boost.available:
                try:
                    sev_counts = self.db.count_findings_by_severity(eng_id)
                    chains_list = self.db.get_chains(eng_id)
                    creds_list = self.db.get_credentials(eng_id)
                    ai_summary = self.ai_boost.executive_summary(
                        target=target,
                        total_findings=sum(sev_counts.values()),
                        severity_counts=sev_counts,
                        chains_count=len(chains_list),
                        credentials_count=len(creds_list),
                    )
                    if ai_summary:
                        log.info("[REPORT] AI executive summary generated (%d chars)", len(ai_summary))
                except Exception as exc:
                    log.debug("[REPORT] AI summary skipped: %s", exc)

            report_dir = self.config.data_dir / "reports" / eng_id
            generated = generate_report(
                self.db, eng_id, report_dir,
                formats=["md", "html"],
                ai_summary=ai_summary,
            )
            log.info("[REPORT] Generated %d reports: %s", len(generated), generated)

            # Complete
            self._advance_phase(eng_id, EngagementPhase.COMPLETE)
            self.audit.log_action("engage_complete", target=target, extra={"id": eng_id})

        except Exception as exc:
            log.error("Engagement failed: %s", exc)
            self.audit.log_action("engage_failed", target=target, result=str(exc),
                                  extra={"id": eng_id})
            raise

        return eng_id

    # ── Stats / Info ──────────────────────────────────────────────

    def brain_stats(self) -> dict[str, Any]:
        """Return stats about the loaded brain subsystems."""
        stats: dict[str, Any] = {}
        if self.expert:
            stats["expert_rules"] = self.expert.rule_count
        if self.knowledge:
            stats["knowledge_cves"] = self.knowledge.cve_count
        if self.chains:
            stats.update(self.chains.stats())
        if self.payloads:
            stats["payloads"] = self.payloads.count
        if self.remediation:
            stats["remediations"] = self.remediation.count
        if self.cred_db:
            stats["default_creds"] = self.cred_db.count
        if self.router:
            stats["routing_services"] = len(self.router.get_all_services())
        if self.waf:
            stats["waf_profiles"] = self.waf.waf_count
            stats["waf_techniques"] = self.waf.technique_count
        if self.plugins:
            stats["plugins"] = self.plugins.registry.count
        if self.ai_boost:
            stats["ai_available"] = self.ai_boost.available
            if self.ai_boost.available:
                stats["ai_model"] = self.ai_boost.model
        return stats

    def engagement_summary(self, eng_id: str) -> dict[str, Any]:
        """Return a summary of an engagement."""
        self._require_boot()
        assert self.db is not None

        eng = self.db.get_engagement(eng_id)
        if not eng:
            return {}

        severity_counts = self.db.count_findings_by_severity(eng_id)
        targets = self.db.get_targets(eng_id)
        chains = self.db.get_chains(eng_id)
        creds = self.db.get_credentials(eng_id)

        return {
            "id": eng.id,
            "name": eng.name,
            "target": eng.target,
            "phase": eng.phase.value,
            "created": eng.created_at.isoformat(),
            "targets_found": len(targets),
            "severity_counts": severity_counts,
            "chains_found": len(chains),
            "credentials_found": len(creds),
        }
