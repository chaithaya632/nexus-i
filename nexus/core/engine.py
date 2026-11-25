"""NexusEngine — central orchestrator for the entire engagement pipeline."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from nexus.ai.boost import AIBoost
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
from nexus.core.audit import AuditLogger
from nexus.core.config import (
    SCAN_PROFILE_SETTINGS,
    NexusConfig,
    ScanProfile,
    Tier,
    get_config,
    set_config,
)
from nexus.core.hardware import HardwareInfo, auto_select_tier, detect_hardware
from nexus.core.phases import CorrelatePhase, ExploitPhase, ReconPhase, ScanPhase
from nexus.core.scheduler import TaskScheduler
from nexus.core.scope import Scope, ScopeEnforcer
from nexus.correlator.baseline import (
    apply_baseline_suppressions,
    load_ignore_rules,
    resolve_ignore_path,
)
from nexus.correlator.engine import correlate as correlate_findings
from nexus.db.models import (
    AttackChain,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
    Severity,
    Target,
)
from nexus.db.store import EngagementStore, create_store
from nexus.exploit.credential import test_default_creds
from nexus.exploit.executor import ExploitExecutor, ExploitResult
from nexus.exploit.msf_bridge import MSFBridge
from nexus.exploit.sqli import sqlmap_scan
from nexus.plugins import PluginLoader
from nexus.recon.dns import enumerate_dns
from nexus.recon.osint import gather_osint
from nexus.recon.ports import nmap_scan
from nexus.recon.runner import ToolRunner
from nexus.recon.subdomains import enumerate_subdomains
from nexus.recon.tech import detect_tech_stack
from nexus.recon.waf import detect_waf
from nexus.reporter.generator import generate_report
from nexus.scanner._http import parse_url_target, redact_headers
from nexus.scanner.cms_scan import wpscan_audit
from nexus.scanner.crawler import crawl_web
from nexus.scanner.exposure import audit_exposed_artifacts
from nexus.scanner.headers import audit_http_security
from nexus.scanner.host_audit import audit_host_packages
from nexus.scanner.network_services import audit_network_service
from nexus.scanner.nikto import nikto_scan
from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.openapi import audit_openapi_spec
from nexus.scanner.passive_dast import audit_auth_enforcement, audit_graphql_introspection
from nexus.scanner.ssh_audit import audit_ssh
from nexus.scanner.tls import audit_tls
from nexus.scanner.web import ffuf_scan
from nexus.scanner.yaml_rules import YamlPassiveRuleEngine
from nexus.scanner.zap import zap_scan
from nexus.stealth.controller import StealthController, set_active_stealth

log = logging.getLogger("nexus.engine")
console = Console()

# Re-export phase symbols used directly by tests and phase runners
_PHASE_EXPORTS = (
    SCAN_PROFILE_SETTINGS,
    apply_baseline_suppressions,
    load_ignore_rules,
    resolve_ignore_path,
    correlate_findings,
    Credential,
    Target,
    test_default_creds,
    ExploitResult,
    sqlmap_scan,
    enumerate_dns,
    gather_osint,
    nmap_scan,
    ToolRunner,
    enumerate_subdomains,
    detect_tech_stack,
    detect_waf,
    parse_url_target,
    redact_headers,
    wpscan_audit,
    crawl_web,
    audit_exposed_artifacts,
    audit_http_security,
    audit_host_packages,
    audit_network_service,
    nikto_scan,
    nuclei_scan,
    audit_openapi_spec,
    audit_auth_enforcement,
    audit_graphql_introspection,
    audit_ssh,
    audit_tls,
    ffuf_scan,
    zap_scan,
)

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

_SEV_STR_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_TECH_NUCLEI_TAGS: dict[str, str] = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "tomcat": "tomcat",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "spring": "springboot",
    "struts": "struts",
    "php": "php",
    "graphql": "graphql",
    "swagger": "swagger",
    "openapi": "openapi",
    "laravel": "laravel",
    "django": "django",
    "express": "nodejs",
    "node": "nodejs",
    "flask": "flask",
    "grafana": "grafana",
    "kibana": "kibana",
    "elastic": "elasticsearch",
    "redis": "redis",
    "weblogic": "weblogic",
    "citrix": "citrix",
    "confluence": "confluence",
    "jira": "jira",
    "sharepoint": "sharepoint",
    "exchange": "exchange",
}

_PHASE_ORDER: dict[EngagementPhase, int] = {
    EngagementPhase.INIT: 0,
    EngagementPhase.RECON: 1,
    EngagementPhase.SCAN: 2,
    EngagementPhase.CORRELATE: 3,
    EngagementPhase.EXPLOIT: 4,
    EngagementPhase.REPORT: 5,
    EngagementPhase.COMPLETE: 6,
}


class NexusEngine:
    """Central orchestrator — wires together subsystems and phase runners.

    Lifecycle:
        engine = NexusEngine(config)
        engine.boot()
        eng_id = await engine.engage("example.com", scope_file="scope.yaml")
        engine.shutdown()
    """

    def __init__(
        self,
        config: NexusConfig | None = None,
        *,
        on_progress: Callable[[str, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.config = config or get_config()
        set_config(self.config)
        self.on_progress = on_progress

        self.hw: HardwareInfo | None = None
        self.db: EngagementStore | Any | None = None
        self.audit: AuditLogger | None = None
        self.scope: ScopeEnforcer | None = None
        self.scheduler: TaskScheduler | None = None

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
        self.yaml_rules: YamlPassiveRuleEngine | None = None

        self.stealth: StealthController | None = None
        self.exploit_executor: ExploitExecutor | None = None
        self.msf: MSFBridge | None = None
        self.ai_boost: AIBoost | None = None
        self.plugins: PluginLoader | None = None

        self._recon_phase = ReconPhase()
        self._scan_phase = ScanPhase()
        self._correlate_phase = CorrelatePhase()
        self._exploit_phase = ExploitPhase()

        self._booted = False
        self._current_engagement: str | None = None

    # ── Boot / Shutdown ───────────────────────────────────────────

    def boot(self, *, auto_tier: bool = False, connect_ai: bool = True) -> None:
        """Initialize all subsystems. Call once before any engagement."""
        if self._booted:
            return

        log.info("Booting NEXUS engine...")
        self.config.ensure_dirs()

        self.hw = detect_hardware()
        if auto_tier or (
            self.config.tier == Tier.MINIMAL and "tier" not in self.config.model_fields_set
        ):
            auto_selected = auto_select_tier(self.hw)
            if auto_selected != Tier.MINIMAL:
                self.config.tier = auto_selected
                log.info("Auto-selected tier: %s", auto_selected.value)

        self.db = create_store(self.config.db_path, db_url=getattr(self.config, "db_url", None))
        audit_path = self.config.data_dir / "audit.jsonl"
        self.audit = AuditLogger(audit_path)
        self.scheduler = TaskScheduler(max_concurrent=self.config.max_threads)

        self.expert = RuleEngine()
        for rule in build_service_rules():
            self.expert.add_rule(rule)

        self.knowledge = KnowledgeGraph()
        kb_dir = self.config.knowledge_dir
        if kb_dir and kb_dir.is_dir():
            self.knowledge.load_from_directory(kb_dir)
        if (self.config.data_dir / "cves").is_dir() and self.config.data_dir != kb_dir:
            self.knowledge.load_from_directory(self.config.data_dir)

        self.chains = ChainBuilder()
        self.chains.build_default_graph()
        if kb_dir and kb_dir.is_dir():
            self.chains.load_templates(kb_dir)

        self.vector = VectorSearch()
        self.router = ServiceRouter()
        if kb_dir and kb_dir.is_dir():
            self.router.load_from_directory(kb_dir)

        self.cred_db = CredentialDB()
        if kb_dir and kb_dir.is_dir():
            self.cred_db.load_from_directory(kb_dir)

        self.waf = WAFBypassLibrary()
        if kb_dir and kb_dir.is_dir():
            self.waf.load_from_directory(kb_dir)

        self.taxonomy = TaxonomyMapper()

        self.payloads = PayloadDB()
        if kb_dir and kb_dir.is_dir():
            self.payloads.load_from_yaml(kb_dir / "payloads")

        self.remediation = RemediationDB()
        if kb_dir and kb_dir.is_dir():
            self.remediation.load_from_yaml(kb_dir / "remediations")

        self.yaml_rules = YamlPassiveRuleEngine()
        if kb_dir and (kb_dir / "rules").is_dir():
            self.yaml_rules.load_directory(kb_dir / "rules")

        if self.vector:
            for cve_id, (svc_name, entry) in self.knowledge._cve_index.items():
                self.vector.add_entry(
                    id=cve_id,
                    text=f"{cve_id} {svc_name} {entry.description} {entry.affected_versions}",
                    metadata={
                        "type": "cve",
                        "service": svc_name,
                        "severity": entry.severity,
                        "cvss": entry.cvss,
                    },
                )
            for rem in self.remediation._by_id.values():
                self.vector.add_entry(
                    id=f"rem:{rem.id}",
                    text=f"{rem.id} {rem.title} {rem.short_fix} {' '.join(rem.tags)}",
                    metadata={
                        "type": "remediation",
                        "id": rem.id,
                        "severity": rem.severity,
                    },
                )
            self.vector.build_index()

        stealth_profile = _STEALTH_MAP.get(self.config.stealth.value, "normal")
        self.stealth = StealthController(stealth_profile)
        set_active_stealth(self.stealth)

        self.exploit_executor = ExploitExecutor(
            scope=self.scope,
            audit=self.audit,
            auto_confirm=self.config.auto_confirm_exploits,
        )

        self.plugins = PluginLoader()
        self.plugins.load_builtin()

        self.msf = MSFBridge()
        self.msf._scope = self.scope
        self.msf._audit = self.audit

        self.ai_boost = AIBoost(
            ollama_host=self.config.ollama_host,
            model_name=self.config.model_name,
            knowledge_graph=self.knowledge,
            expert=self.expert,
            taxonomy=self.taxonomy,
        )
        if connect_ai:
            self.ai_boost.connect()

        self._booted = True
        self.audit.log_action(
            "engine_boot",
            tool="nexus",
            result="success",
            extra={
                "tier": self.config.tier.value,
                "ram_mb": self.hw.ram_total_mb,
                "cpu_cores": self.hw.cpu_cores,
            },
        )
        log.info(
            "NEXUS engine booted — Tier: %s, RAM: %dMB, CPUs: %d",
            self.config.tier.value,
            self.hw.ram_total_mb,
            self.hw.cpu_cores,
        )

    def shutdown(self) -> None:
        if self.ai_boost:
            self.ai_boost.close()
        if self.audit:
            self.audit.log_action("engine_shutdown", tool="nexus", result="clean")
        set_active_stealth(None)
        self._booted = False
        log.info("NEXUS engine shut down.")

    def _require_boot(self) -> None:
        if not self._booted:
            raise RuntimeError("NexusEngine.boot() must be called before operations.")

    def _require_subsystems(self, *names: str) -> None:
        for name in names:
            if getattr(self, name, None) is None:
                raise RuntimeError(
                    f"Engine subsystem '{name}' is not initialized; call boot() first."
                )

    async def _emit_progress(self, event: str, data: dict[str, Any]) -> None:
        if self.on_progress is None:
            return
        try:
            res = self.on_progress(event, data)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:
            log.debug("Progress callback failed for %s: %s", event, exc)

    # ── Engagement & Scope Management ─────────────────────────────

    def _set_scope(self, enforcer: ScopeEnforcer) -> None:
        """Bind a ScopeEnforcer to engine, ExploitExecutor, and MSFBridge."""
        self.scope = enforcer
        if self.exploit_executor is not None:
            self.exploit_executor._scope = enforcer
        if self.msf is not None:
            self.msf._scope = enforcer
            self.msf._audit = self.audit

    def _scope_for_target(self, target: str) -> ScopeEnforcer:
        """Build a strict target-scoped enforcer (unless lab unrestricted_scope=True)."""
        if getattr(self.config, "unrestricted_scope", False):
            log.warning(
                "unrestricted_scope=True — using lab-only allow_all scope for '%s'.", target
            )
            return ScopeEnforcer.allow_all()
        if hasattr(ScopeEnforcer, "for_target"):
            return ScopeEnforcer.for_target(target)
        raw = target.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").strip().lower()
            ports = [parsed.port] if parsed.port else None
        else:
            host = raw
            ports = None
        if not host:
            return ScopeEnforcer(Scope())
        try:
            net = ipaddress.ip_network(host, strict=False)
            if "/" in host:
                return ScopeEnforcer(Scope(allowed_cidrs=[net], allowed_ports=ports))
            return ScopeEnforcer(Scope(allowed_ips=[str(net.network_address)], allowed_ports=ports))
        except ValueError:
            clean_host = host.rstrip(".").lower()
            return ScopeEnforcer(
                Scope(allowed_domains=[clean_host, f"*.{clean_host}"], allowed_ports=ports)
            )

    def _active_stealth_profile(self) -> str:
        profile = _STEALTH_MAP.get(self.config.stealth.value, "normal")
        if self.stealth is not None:
            if self.stealth.level != profile:
                self.stealth.set_level(profile)
            set_active_stealth(self.stealth)
        return profile

    def _is_excluded(self, target: str) -> bool:
        if self.scope is None or not target:
            return False
        if hasattr(self.scope, "is_excluded"):
            return bool(self.scope.is_excluded(target))
        norm = target.strip().lower().rstrip(".")
        return norm in getattr(self.scope, "_excluded", set())

    def _is_in_scope(self, target: str, port: int | None = None) -> bool:
        if self.scope is None or not target:
            return False
        if not self.scope.is_in_scope(target):
            return False
        if port is not None and not self.scope.is_port_allowed(port):
            return False
        return True

    def _is_target_in_scope(self, host: str, ip: str = "", port: int | None = None) -> bool:
        if self.scope is None:
            return False
        if port is not None and not self.scope.is_port_allowed(port):
            return False
        if host and self._is_excluded(host):
            return False
        if ip and self._is_excluded(ip):
            return False
        return (bool(host) and self.scope.is_in_scope(host)) or (
            bool(ip) and self.scope.is_in_scope(ip)
        )

    def _coerce_plugin_finding(
        self,
        raw: Any,
        eng_id: str,
        default_host: str,
    ) -> Finding | None:
        if isinstance(raw, Finding):
            finding = raw
            finding.engagement_id = eng_id
            if not finding.host:
                finding.host = default_host
        elif isinstance(raw, dict):
            data = dict(raw)
            data["engagement_id"] = eng_id
            data.setdefault("host", default_host)
            data.setdefault("title", "Plugin Finding")
            data.setdefault("tool_source", "plugin")
            sev = data.get("severity", Severity.INFO)
            if isinstance(sev, str):
                data["severity"] = _SEV_STR_MAP.get(sev.lower().strip(), Severity.INFO)
            finding = Finding(**data)
        else:
            return None

        if not self._is_in_scope(finding.host, finding.port):
            log.debug(
                "[PLUGIN] Skipping out-of-scope finding for %s:%s", finding.host, finding.port
            )
            return None
        return finding

    def create_engagement(
        self,
        target: str,
        name: str = "",
        scope_file: str | None = None,
    ) -> Engagement:
        self._require_boot()
        self._require_subsystems("db", "audit")
        if self.db is None or self.audit is None:
            raise RuntimeError("Database or audit logger not initialized.")

        eng = Engagement(
            name=name or f"engagement_{target}",
            target=target,
            scope_file=scope_file or "",
            stealth=self.config.stealth.value,
            tier=self.config.tier.value,
        )
        self.db.create_engagement(eng)
        self._current_engagement = eng.id

        if scope_file:
            self._set_scope(ScopeEnforcer.from_file(scope_file))
        else:
            self._set_scope(self._scope_for_target(target))
            log.info("No scope file — enforcing strict target scope for '%s'.", target)

        self.audit.log_action(
            "engagement_created",
            target=target,
            extra={"id": eng.id, "scope_file": scope_file or "auto_target"},
        )
        return eng

    def resume_engagement(self, eng_id: str) -> Engagement | None:
        self._require_boot()
        self._require_subsystems("db")
        if self.db is None:
            raise RuntimeError("Database not initialized.")

        eng = self.db.get_engagement(eng_id)
        if not eng:
            return None
        self._current_engagement = eng.id

        if eng.scope_file:
            self._set_scope(ScopeEnforcer.from_file(eng.scope_file))
        else:
            self._set_scope(self._scope_for_target(eng.target))

        if self.audit:
            self.audit.log_action(
                "engagement_resumed",
                target=eng.target,
                extra={"id": eng.id, "phase": eng.phase.value},
            )
        return eng

    def _advance_phase(self, eng_id: str, phase: EngagementPhase) -> None:
        self._require_subsystems("db", "audit")
        if self.db is None or self.audit is None:
            raise RuntimeError("Database or audit logger not initialized.")
        self.db.update_phase(eng_id, phase)
        self.audit.log_action("phase_change", extra={"id": eng_id, "phase": phase.value})

    # ── Phase Delegates ───────────────────────────────────────────

    async def run_recon(self, eng_id: str, target: str) -> list[Finding]:
        return await self._recon_phase.run(self, eng_id, target)

    async def run_scan(self, eng_id: str, target: str) -> list[Finding]:
        return await self._scan_phase.run(self, eng_id, target)

    async def run_correlate(self, eng_id: str) -> list[AttackChain]:
        return await self._correlate_phase.run(self, eng_id)

    async def run_exploit(self, eng_id: str, confirm: bool | None = None) -> list[Finding]:
        return await self._exploit_phase.run(self, eng_id, confirm=confirm)

    # ── Full Engagement Pipeline ──────────────────────────────────

    async def engage(
        self,
        target: str = "",
        name: str = "",
        scope_file: str | None = None,
        skip_exploit: bool = False,
        profile: str | None = None,
        resume_id: str | None = None,
        auth_headers: dict[str, str] | None = None,
        openapi_spec: str | Path | None = None,
        ignore_file: str | Path | None = None,
        confirm_exploit: bool | None = None,
    ) -> str:
        """Run the complete engagement pipeline: Recon -> Scan -> Correlate -> Exploit -> Report."""
        self._require_boot()
        self._require_subsystems("audit", "db")
        if self.audit is None or self.db is None:
            raise RuntimeError("Database or audit logger not initialized.")

        orig_config = self.config
        config_override = orig_config.model_copy(deep=True)
        if profile:
            config_override.profile = ScanProfile(profile)
        if auth_headers:
            config_override.auth_headers = dict(auth_headers)
        if openapi_spec:
            config_override.openapi_spec = Path(openapi_spec)
        if ignore_file:
            config_override.ignore_file = Path(ignore_file)
        if confirm_exploit is not None:
            config_override.auto_confirm_exploits = bool(confirm_exploit)

        self.config = config_override
        try:
            if resume_id:
                eng = self.resume_engagement(resume_id)
                if not eng:
                    raise ValueError(f"Engagement '{resume_id}' not found.")
                eng_id = eng.id
                target = eng.target
                start_phase = eng.phase
            else:
                if not target:
                    raise ValueError("Target is required when not resuming an engagement.")
                eng = self.create_engagement(target, name, scope_file)
                eng_id = eng.id
                start_phase = EngagementPhase.INIT

            start_idx = _PHASE_ORDER.get(start_phase, 0)
            self.audit.log_action(
                "engage_start",
                target=target,
                extra={
                    "id": eng_id,
                    "skip_exploit": skip_exploit,
                    "profile": self.config.profile.value,
                    "resume_from": start_phase.value if resume_id else None,
                },
            )

            try:
                if start_idx >= _PHASE_ORDER[EngagementPhase.COMPLETE]:
                    log.info("[ENGAGE] Engagement %s is already complete", eng_id)
                    return eng_id

                if start_idx <= _PHASE_ORDER[EngagementPhase.RECON]:
                    await self.run_recon(eng_id, target)
                if start_idx <= _PHASE_ORDER[EngagementPhase.SCAN]:
                    await self.run_scan(eng_id, target)
                if start_idx <= _PHASE_ORDER[EngagementPhase.CORRELATE]:
                    await self.run_correlate(eng_id)
                if not skip_exploit and start_idx <= _PHASE_ORDER[EngagementPhase.EXPLOIT]:
                    await self.run_exploit(eng_id, confirm=confirm_exploit)

                if start_idx <= _PHASE_ORDER[EngagementPhase.REPORT]:
                    self._advance_phase(eng_id, EngagementPhase.REPORT)

                    ai_summary = ""
                    if self.ai_boost and self.ai_boost.available:
                        try:
                            sev_counts = self.db.count_findings_by_severity(eng_id)
                            chains_list = self.db.get_chains(eng_id)
                            creds_list = self.db.get_credentials(eng_id)
                            ai_summary = await asyncio.to_thread(
                                self.ai_boost.executive_summary,
                                target=target,
                                total_findings=sum(sev_counts.values()),
                                severity_counts=sev_counts,
                                chains_count=len(chains_list),
                                credentials_count=len(creds_list),
                            )
                        except Exception as exc:
                            log.debug("[REPORT] AI summary skipped: %s", exc)

                    report_dir = self.config.output_dir / eng_id
                    generated = generate_report(
                        self.db,
                        eng_id,
                        report_dir,
                        formats=["md", "html", "sarif"],
                        ai_summary=ai_summary,
                    )
                    log.info("[REPORT] Generated %d reports: %s", len(generated), generated)

                self._advance_phase(eng_id, EngagementPhase.COMPLETE)
                self.audit.log_action("engage_complete", target=target, extra={"id": eng_id})
                await self._emit_progress(
                    "engage_complete", {"engagement_id": eng_id, "target": target}
                )

            except Exception as exc:
                log.error("Engagement failed: %s", exc)
                self.audit.log_action(
                    "engage_failed", target=target, result=str(exc), extra={"id": eng_id}
                )
                raise

            return eng_id
        finally:
            self.config = orig_config

    # ── Stats / Info ──────────────────────────────────────────────

    def brain_stats(self) -> dict[str, Any]:
        stats: dict[str, Any] = {}
        if self.expert:
            stats["expert_rules"] = self.expert.rule_count
        if self.knowledge:
            stats["knowledge_cves"] = self.knowledge.cve_count
        if self.vector:
            stats["vector_entries"] = self.vector.entry_count
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
        if self.yaml_rules:
            stats["yaml_rules"] = self.yaml_rules.rule_count
        if self.plugins:
            stats["plugins"] = self.plugins.registry.count
        if self.ai_boost:
            stats["ai_available"] = self.ai_boost.available
            if self.ai_boost.available:
                stats["ai_model"] = self.ai_boost.model
        return stats

    def engagement_summary(self, eng_id: str) -> dict[str, Any]:
        self._require_boot()
        self._require_subsystems("db")
        if self.db is None:
            raise RuntimeError("Database not initialized.")

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
