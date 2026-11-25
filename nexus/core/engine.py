"""NexusEngine — central orchestrator for the entire engagement pipeline."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from rich.console import Console

from nexus.core.audit import AuditLogger
from nexus.core.config import (
    NexusConfig,
    SCAN_PROFILE_SETTINGS,
    ScanProfile,
    Tier,
    get_config,
    set_config,
)
from nexus.core.hardware import HardwareInfo, auto_select_tier, detect_hardware
from nexus.core.scheduler import TaskScheduler
from nexus.core.scope import Scope, ScopeEnforcer
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
from nexus.scanner.ssh_audit import audit_ssh
from nexus.scanner.tls import audit_tls
from nexus.scanner._http import parse_url_target, redact_headers
from nexus.scanner.crawler import crawl_web
from nexus.scanner.exposure import audit_exposed_artifacts
from nexus.scanner.headers import audit_http_security
from nexus.scanner.network_services import audit_network_service
from nexus.scanner.cms_scan import wpscan_audit
from nexus.scanner.openapi import audit_openapi_spec
from nexus.scanner.passive_dast import audit_auth_enforcement, audit_graphql_introspection
from nexus.scanner.host_audit import audit_host_packages
from nexus.correlator.baseline import apply_baseline_suppressions, load_ignore_rules, resolve_ignore_path
from nexus.correlator.engine import correlate as correlate_findings
from nexus.exploit.executor import ExploitExecutor, ExploitResult
from nexus.exploit.sqli import sqlmap_scan
from nexus.exploit.credential import test_default_creds
from nexus.exploit.msf_bridge import MSFBridge
from nexus.stealth.controller import StealthController, set_active_stealth
from nexus.reporter.generator import generate_report
from nexus.ai.boost import AIBoost
from nexus.plugins import PluginLoader
from nexus.db.models import (
    AttackChain,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
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
    """Central orchestrator — wires together every NEXUS subsystem.

    Lifecycle:
        engine = NexusEngine(config)
        engine.boot()
        eng_id = engine.engage("example.com", scope_file="scope.yaml")
        # ... or run individual phases
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

    def boot(self, *, auto_tier: bool = False, connect_ai: bool = True) -> None:
        """Initialize all subsystems. Call once before any engagement."""
        if self._booted:
            return

        log.info("Booting NEXUS engine...")
        self.config.ensure_dirs()

        # Detect hardware and auto-select tier only when not explicitly set (or auto_tier=True)
        self.hw = detect_hardware()
        if auto_tier or (
            self.config.tier == Tier.MINIMAL and "tier" not in self.config.model_fields_set
        ):
            auto_selected = auto_select_tier(self.hw)
            if auto_selected != Tier.MINIMAL:
                self.config.tier = auto_selected
                log.info("Auto-selected tier: %s", auto_selected.value)

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

        # Brain — Knowledge Graph (bundled + user-synced KEV/NVD catalogs)
        self.knowledge = KnowledgeGraph()
        kb_dir = self.config.knowledge_dir
        if kb_dir and kb_dir.is_dir():
            self.knowledge.load_from_directory(kb_dir)
        if (self.config.data_dir / "cves").is_dir() and self.config.data_dir != kb_dir:
            self.knowledge.load_from_directory(self.config.data_dir)

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

        # Populate Vector Search index from Knowledge Graph CVEs & Remediations
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

        # Stealth controller — map config levels to controller profiles
        stealth_profile = _STEALTH_MAP.get(self.config.stealth.value, "normal")
        self.stealth = StealthController(stealth_profile)
        set_active_stealth(self.stealth)

        # Exploit executor (scope + audit enforced)
        self.exploit_executor = ExploitExecutor(
            scope=self.scope,
            audit=self.audit,
            auto_confirm=self.config.auto_confirm_exploits,
        )

        # Plugins
        self.plugins = PluginLoader()
        self.plugins.load_builtin()

        # MSF bridge (optional)
        self.msf = MSFBridge()
        self.msf._scope = self.scope
        self.msf._audit = self.audit

        # AI Boost (optional — tries Ollama, falls back to expert system)
        self.ai_boost = AIBoost(
            ollama_host=self.config.ollama_host,
            model_name=self.config.model_name,
            knowledge_graph=self.knowledge,
            expert=self.expert,
            taxonomy=self.taxonomy,
        )
        if connect_ai:
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
        set_active_stealth(None)
        self._booted = False
        log.info("NEXUS engine shut down.")

    def _require_boot(self) -> None:
        if not self._booted:
            raise RuntimeError("NexusEngine.boot() must be called before operations.")

    def _require_subsystems(self, *names: str) -> None:
        for name in names:
            if getattr(self, name, None) is None:
                raise RuntimeError(f"Engine subsystem '{name}' is not initialized; call boot() first.")

    async def _emit_progress(self, event: str, data: dict[str, Any]) -> None:
        if self.on_progress is None:
            return
        try:
            res = self.on_progress(event, data)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:
            log.debug("Progress callback failed for %s: %s", event, exc)

    # ── Engagement Management ─────────────────────────────────────

    def _set_scope(self, enforcer: ScopeEnforcer) -> None:
        """Bind a ScopeEnforcer to engine, ExploitExecutor, and MSFBridge."""
        self.scope = enforcer
        if self.exploit_executor is not None:
            self.exploit_executor._scope = enforcer
        if self.msf is not None:
            self.msf._scope = enforcer
            self.msf._audit = self.audit

    def _scope_for_target(self, target: str) -> ScopeEnforcer:
        """Build a strict target-scoped enforcer when no scope.yaml is provided."""
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
            return ScopeEnforcer(Scope(allowed_domains=[clean_host, f"*.{clean_host}"], allowed_ports=ports))

    def _active_stealth_profile(self) -> str:
        """Sync StealthController with config.stealth and return tool profile name."""
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
        """Return True if target (and optional port) is permitted by active scope (fail-closed)."""
        if self.scope is None or not target:
            return False
        if not self.scope.is_in_scope(target):
            return False
        if port is not None and not self.scope.is_port_allowed(port):
            return False
        return True

    def _is_target_in_scope(self, host: str, ip: str = "", port: int | None = None) -> bool:
        """Check whether a Target (domain host and/or resolved IP) is in scope and not excluded."""
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
        self, raw: Any, eng_id: str, default_host: str,
    ) -> Finding | None:
        """Convert a plugin Finding or dict into a scope-checked Finding."""
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
            log.debug("[PLUGIN] Skipping out-of-scope finding for %s:%s", finding.host, finding.port)
            return None
        return finding

    def create_engagement(
        self,
        target: str,
        name: str = "",
        scope_file: str | None = None,
    ) -> Engagement:
        """Create a new engagement and return its model."""
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

        # Load explicit scope file or fall back to strict single-target scope
        if scope_file:
            self._set_scope(ScopeEnforcer.from_file(scope_file))
        else:
            self._set_scope(self._scope_for_target(target))
            log.info("No scope file — enforcing strict target scope for '%s'.", target)

        self.audit.log_action("engagement_created", target=target,
                              extra={"id": eng.id, "scope_file": scope_file or "auto_target"})
        return eng

    def resume_engagement(self, eng_id: str) -> Engagement | None:
        """Resume an existing engagement."""
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
            self.audit.log_action("engagement_resumed", target=eng.target,
                                  extra={"id": eng.id, "phase": eng.phase.value})
        return eng

    def _advance_phase(self, eng_id: str, phase: EngagementPhase) -> None:
        self._require_subsystems("db", "audit")
        if self.db is None or self.audit is None:
            raise RuntimeError("Database or audit logger not initialized.")
        self.db.update_phase(eng_id, phase)
        self.audit.log_action("phase_change", extra={"id": eng_id, "phase": phase.value})

    # ── Phase Runners (stubs for Phase 2–4 tool integration) ──────

    async def run_recon(self, eng_id: str, target: str) -> list[Finding]:
        """Run reconnaissance phase — subdomain enum → DNS → ports → tech → WAF → OSINT."""
        self._require_boot()
        self._require_subsystems("audit", "db", "scheduler")
        if self.audit is None or self.db is None or self.scheduler is None:
            raise RuntimeError("Engine subsystems not initialized; call boot() first.")

        if not self._is_in_scope(target):
            raise ValueError(f"SCOPE VIOLATION: Target '{target}' is outside authorized scope.")

        self._advance_phase(eng_id, EngagementPhase.RECON)
        self.audit.log_action("recon_start", target=target, extra={"id": eng_id})
        await self._emit_progress("recon_start", {"engagement_id": eng_id, "target": target})

        all_findings: list[Finding] = []
        stealth = self._active_stealth_profile()
        profile_cfg = SCAN_PROFILE_SETTINGS.get(
            self.config.profile.value, SCAN_PROFILE_SETTINGS[ScanProfile.FULL.value]
        )

        # 1. Subdomain enumeration (use bounded passive mode; filter by scope)
        log.info(
            "[RECON] Subdomain enumeration for %s (stealth=%s, profile=%s)",
            target, stealth, self.config.profile.value,
        )
        raw_targets = await enumerate_subdomains(
            target,
            use_amass=bool(profile_cfg.get("use_amass", True)) and (stealth in ("loud", "normal")),
            passive_only=(stealth in ("quiet", "ghost")),
            timeout=90,
        )
        targets: list[Target] = []
        seen_hosts: set[str] = set()
        for t in raw_targets:
            host_l = t.host.lower().strip()
            if not host_l or host_l in seen_hosts:
                continue
            if not self._is_target_in_scope(host_l, t.ip):
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
        target_ip_map = {t.host.lower(): t.ip for t in targets if t.host}
        for f in dns_findings:
            f_host = (f.host or target).strip()
            if not self._is_target_in_scope(f_host, target_ip_map.get(f_host.lower(), ""), f.port):
                continue
            f.engagement_id = eng_id
            all_findings.append(f)

        # Persist targets BEFORE adding ports so FK(target_id -> targets.id) never fails
        for t in targets:
            self.db.add_target(t)

        # 3. Port scanning (bounded parallelism; stealth-ordered if needed)
        scan_targets = self.stealth.shuffle_targets(targets) if self.stealth else targets
        in_scope_targets = [
            (t, t.ip or t.host)
            for t in scan_targets
            if (t.ip or t.host) and self._is_target_in_scope(t.host, t.ip)
        ]
        log.info("[RECON] Port scanning %d targets", len(in_scope_targets))

        async def _scan_target_ports(t: Target, scan_target: str) -> tuple[Target, str, dict[str, Any]]:
            result = await nmap_scan(scan_target, stealth=stealth)
            return t, scan_target, result

        scan_tasks = [
            (f"nmap:{scan_target}", _scan_target_ports(t, scan_target))
            for t, scan_target in in_scope_targets
        ]
        task_results = await self.scheduler.run_parallel(scan_tasks) if scan_tasks else []

        seen_banner_cves: set[tuple[str, int, str]] = set()
        for tr in task_results:
            if tr.error or tr.result is None:
                log.warning("[RECON] nmap failed (%s): %s", tr.name, tr.error)
                continue
            t, scan_target, result = tr.result
            for scanned_t in result["targets"]:
                if scanned_t.os_guess and not t.os_guess:
                    t.os_guess = scanned_t.os_guess
                if scanned_t.is_live:
                    t.is_live = True
            self.db.add_target(t)
            for port in result["ports"]:
                if not self._is_target_in_scope(t.host, t.ip, port.port):
                    continue
                port.target_id = t.id
                self.db.add_port(port)
                if self.knowledge and port.state.lower().startswith("open") and (port.service or port.version):
                    banner = f"{port.service} {port.version}".strip()
                    for svc_name, entry in self.knowledge.match_banner_vulns(port.service, port.version):
                        dedup_key = (t.host, port.port, entry.cve)
                        if dedup_key in seen_banner_cves:
                            continue
                        seen_banner_cves.add(dedup_key)
                        all_findings.append(Finding(
                            engagement_id=eng_id,
                            host=t.host,
                            port=port.port,
                            protocol=port.protocol or port.service or "tcp",
                            title=f"{entry.cve}: {entry.description or svc_name}",
                            description=(
                                f"Discovered service banner '{banner}' on port {port.port} matched "
                                f"{entry.cve} (affected: {entry.affected_versions})."
                            ),
                            severity=_SEV_STR_MAP.get(entry.severity.lower(), Severity.MEDIUM),
                            cvss_score=float(entry.cvss or 0.0),
                            cve_ids=[entry.cve],
                            cwe_id=entry.vuln_type if entry.vuln_type.startswith("CWE-") else "",
                            evidence=f"Detected service banner: {banner}",
                            remediation=entry.remediation,
                            tool_source="knowledge_banner",
                            confirmed=False,
                        ))
            for f in result["findings"]:
                f_host = (f.host or t.host or scan_target).strip()
                if f_host in (t.host, t.ip, scan_target):
                    allowed = self._is_target_in_scope(t.host, t.ip, f.port)
                else:
                    allowed = self._is_in_scope(f_host, f.port)
                if not allowed:
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)

        # 4. Tech-stack detection
        log.info("[RECON] Tech-stack detection")
        targets = await detect_tech_stack(targets)

        # 5. WAF detection
        if profile_cfg.get("run_waf", True):
            log.info("[RECON] WAF detection")
            targets, waf_findings = await detect_waf(targets)
            for f in waf_findings:
                f_host = (f.host or target).strip()
                if not self._is_target_in_scope(f_host, target_ip_map.get(f_host.lower(), ""), f.port):
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)

            # Feed WAF results into brain
            if self.waf:
                for t in targets:
                    if t.waf_detected and self.expert:
                        self.expert.add_fact(
                            f"waf_{t.waf_detected.lower().replace(' ', '_')}",
                            True, source="wafw00f",
                        )
        else:
            log.info("[RECON] Skipping WAF detection for profile=%s", self.config.profile.value)

        # 6. OSINT gathering (filter new targets & findings against scope)
        if profile_cfg.get("run_osint", True):
            log.info("[RECON] OSINT gathering")
            osint_targets, osint_findings = await gather_osint(target)
            for t2 in osint_targets:
                h_l = t2.host.lower().strip()
                if h_l and h_l not in seen_hosts and self._is_target_in_scope(h_l, t2.ip):
                    seen_hosts.add(h_l)
                    t2.engagement_id = eng_id
                    targets.append(t2)
            for f in osint_findings:
                f_host = (f.host or target).strip()
                if not self._is_target_in_scope(f_host, target_ip_map.get(f_host.lower(), ""), f.port):
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)
        else:
            log.info("[RECON] Skipping OSINT gathering for profile=%s", self.config.profile.value)

        # 7. Plugin recon modules (supports both Finding objects & dicts, scope-checked)
        if self.plugins and self.plugins.registry.recon_modules:
            for pname, rfn in self.plugins.registry.recon_modules.items():
                try:
                    p_findings = await rfn(target, targets=targets)
                    for raw_pf in p_findings or []:
                        pf = self._coerce_plugin_finding(raw_pf, eng_id, target)
                        if pf is not None:
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
        await self._emit_progress("recon_complete", {
            "engagement_id": eng_id,
            "target": target,
            "targets_found": len(targets),
            "findings": len(all_findings),
        })
        log.info(
            "[RECON] Complete — %d targets, %d findings",
            len(targets), len(all_findings),
        )
        return all_findings

    async def run_scan(self, eng_id: str, target: str) -> list[Finding]:
        """Run scanning phase — brain-routed web, TLS, and SSH checks on discovered targets."""
        self._require_boot()
        self._require_subsystems("audit", "db", "scheduler")
        if self.audit is None or self.db is None or self.scheduler is None:
            raise RuntimeError("Engine subsystems not initialized; call boot() first.")
        self._advance_phase(eng_id, EngagementPhase.SCAN)

        profile_cfg = SCAN_PROFILE_SETTINGS.get(
            self.config.profile.value, SCAN_PROFILE_SETTINGS[ScanProfile.FULL.value]
        )
        auth_headers = dict(self.config.auth_headers) if self.config.auth_headers else {}
        openapi_spec = self.config.openapi_spec
        self.audit.log_action(
            "scan_start",
            target=target,
            extra={
                "id": eng_id,
                "profile": self.config.profile.value,
                "auth_headers": redact_headers(auth_headers),
                "openapi_spec": str(openapi_spec) if openapi_spec else None,
            },
        )
        await self._emit_progress("scan_start", {"engagement_id": eng_id, "target": target})

        all_findings: list[Finding] = []
        stealth = self._active_stealth_profile()
        targets_db = self.db.get_targets(eng_id)

        url_set: list[str] = []
        seen_urls: set[str] = set()
        tls_endpoints: list[tuple[str, int]] = []
        seen_tls: set[tuple[str, int]] = set()
        ssh_endpoints: list[tuple[str, int]] = []
        seen_ssh: set[tuple[str, int]] = set()
        net_endpoints: list[tuple[str, int, str]] = []
        seen_net: set[tuple[str, int]] = set()
        tech_tokens: set[str] = set()
        wp_hosts: set[str] = set()
        wafs_detected: set[str] = set()
        discovered_services: set[str] = set()

        def _add_url(u: str) -> None:
            if u not in seen_urls:
                seen_urls.add(u)
                url_set.append(u)

        if self.expert:
            self.expert.clear_facts()

        port_service_hints = {
            445: "smb",
            21: "ftp",
            3306: "mysql",
            1433: "mssql",
            3389: "rdp",
            25: "smtp",
            53: "dns",
        }

        for t in targets_db:
            host = t.host
            if not host or not self._is_target_in_scope(host, t.ip):
                continue
            for tech in t.tech_stack:
                tok = tech.lower().strip()
                if tok:
                    tech_tokens.add(tok)
                    if "wordpress" in tok:
                        wp_hosts.add(host.lower())
            if t.waf_detected:
                wafs_detected.add(t.waf_detected)

            open_ports = self.db.get_ports(t.id)
            if open_ports:
                for p in open_ports:
                    if p.state and not p.state.lower().startswith("open"):
                        continue
                    if not self._is_target_in_scope(host, t.ip, p.port):
                        continue
                    svc = p.service.lower().strip()
                    # Infer service name via ServiceRouter when banner/service is missing
                    if (not svc or svc in ("unknown", "tcpwrapped")) and self.router:
                        inferred = self.router.identify_service_by_port(p.port)
                        if inferred:
                            svc = inferred[0]
                    if self.expert:
                        self.expert.add_fact(f"port_{p.port}", True, source="db")
                        if svc:
                            self.expert.add_fact(f"service_{svc}", True, source="db")

                    route_info = self.router.route(svc) if (self.router and svc) else {}
                    routed_tools_for_port = set(route_info.get("tools", []))

                    if (
                        p.port in (443, 8443, 4443)
                        or "https" in svc
                        or "ssl" in svc
                        or "tls" in svc
                        or "sslyze" in routed_tools_for_port
                    ):
                        suffix = "" if p.port == 443 else f":{p.port}"
                        _add_url(f"https://{host}{suffix}")
                        if (host, p.port) not in seen_tls:
                            seen_tls.add((host, p.port))
                            tls_endpoints.append((host, p.port))
                        if self.expert:
                            self.expert.add_fact("service_https", True, source="db")
                        discovered_services.add("https" if not svc or "http" in svc else svc)
                    elif p.port in (80, 8000, 8080, 8081, 8888, 3000, 5000, 9000) or "http" in svc:
                        suffix = "" if p.port == 80 else f":{p.port}"
                        _add_url(f"http://{host}{suffix}")
                        if self.expert:
                            self.expert.add_fact("service_http", True, source="db")
                        discovered_services.add("http" if not svc else svc)

                    if p.port == 22 or "ssh" in svc or "nmap_ssh_audit" in routed_tools_for_port:
                        if (host, p.port) not in seen_ssh:
                            seen_ssh.add((host, p.port))
                            ssh_endpoints.append((host, p.port))
                        if self.expert:
                            self.expert.add_fact("service_ssh", True, source="db")
                        discovered_services.add("ssh")

                    hint = port_service_hints.get(p.port)
                    for alias in ("smb", "ftp", "mysql", "mssql", "rdp", "smtp", "dns"):
                        if alias == hint or alias in svc:
                            if self.expert:
                                self.expert.add_fact(f"service_{alias}", True, source="db")
                            discovered_services.add(alias)

                    if p.port in (6379, 21, 445, 139, 9200, 2375, 11211, 27017, 5432, 3306, 25, 587, 2379, 8500, 10250, 10255) or any(
                        tok in svc
                        for tok in (
                            "redis", "ftp", "smb", "microsoft-ds", "netbios-ssn",
                            "elastic", "docker", "memcache", "mongo", "postgres",
                            "mysql", "mariadb", "smtp", "etcd", "consul", "kubelet",
                        )
                    ):
                        if (host, p.port) not in seen_net:
                            seen_net.add((host, p.port))
                            net_endpoints.append((host, p.port, svc))
            else:
                if self._is_target_in_scope(host, t.ip, 80):
                    _add_url(f"http://{host}")
                if self._is_target_in_scope(host, t.ip, 443):
                    _add_url(f"https://{host}")

        if not url_set and self._is_in_scope(target):
            if self._is_in_scope(target, 80):
                _add_url(f"http://{target}")
            if self._is_in_scope(target, 443):
                _add_url(f"https://{target}")

        # Populate Expert RuleEngine, query ServiceRouter & WAFBypassLibrary
        effective_stealth = stealth
        waf_bypasses: dict[str, list[dict[str, str]]] = {}
        waf_bypass_count = 0
        if self.expert:
            if tech_tokens:
                self.expert.add_fact("tech_stack", " ".join(sorted(tech_tokens)), source="recon")
            if wafs_detected:
                self.expert.add_fact("waf_status", ", ".join(sorted(wafs_detected)), source="wafw00f")
                for w in wafs_detected:
                    self.expert.add_fact(f"waf_{w.lower().replace(' ', '_')}", True, source="wafw00f")
            else:
                self.expert.add_fact("waf_status", "none", source="wafw00f")

        if wafs_detected:
            if stealth in ("loud", "normal"):
                effective_stealth = "quiet"
            if self.waf:
                for w in sorted(wafs_detected):
                    bypasses = self.waf.get_bypasses(w)
                    waf_bypasses[w] = bypasses
                    waf_bypass_count += len(bypasses)
                    if any(b.get("technique") == "slow_rate" for b in bypasses) and effective_stealth == "normal":
                        effective_stealth = "quiet"
            if self.stealth is not None and self.stealth.level != effective_stealth:
                self.stealth.set_level(effective_stealth)
                set_active_stealth(self.stealth)
            log.info(
                "[SCAN] WAF detected (%s) — throttling stealth %s -> %s (%d bypass techniques)",
                ", ".join(sorted(wafs_detected)), stealth, effective_stealth, waf_bypass_count,
            )

        expert_recs = self.expert.evaluate() if self.expert else []
        service_routes = (
            {svc: self.router.route(svc) for svc in sorted(discovered_services)}
            if self.router else {}
        )
        routed_tools: set[str] = {
            t for r in service_routes.values() for t in r.get("tools", [])
        }
        routed_checks: set[str] = {
            c for r in service_routes.values() for c in r.get("checks", [])
        }
        self.audit.log_action("routing_plan", target=target, extra={
            "id": eng_id,
            "profile": self.config.profile.value,
            "effective_stealth": effective_stealth,
            "auth_headers": redact_headers(auth_headers),
            "openapi_spec": str(openapi_spec) if openapi_spec else None,
            "wafs_detected": sorted(wafs_detected),
            "waf_bypass_techniques": waf_bypass_count,
            "waf_recommended_techniques": sorted({
                b.get("technique", "") for b_list in waf_bypasses.values() for b in b_list if b.get("technique")
            }),
            "expert_rules": [{"rule": name, "actions": actions} for name, actions in expert_recs],
            "service_routes": service_routes,
            "routed_tools": sorted(routed_tools),
            "routed_checks": sorted(routed_checks),
        })

        # Keep clean root origins for directory/server scanners (avoid fuzzing crawled subpaths)
        base_roots = list(url_set)

        # 0a. OpenAPI / Swagger specification parsing (feeds scoped API endpoints & schema checks)
        if openapi_spec:
            base_hint = url_set[0] if url_set else f"https://{target}"
            try:
                api_urls, api_findings = audit_openapi_spec(openapi_spec, base_url_override=base_hint)
                for au in api_urls:
                    ehost, eport, _ = parse_url_target(au)
                    if ehost and self._is_in_scope(ehost, eport) and len(url_set) < 60:
                        _add_url(au)
                for af in api_findings:
                    af.engagement_id = eng_id
                    all_findings.append(af)
            except Exception as exc:
                log.warning("[SCAN] OpenAPI spec parsing failed (%s): %s", openapi_spec, exc)

        # 0b. SPA / JS crawling & passive client-side secret detection (katana + Python fallback)
        if profile_cfg.get("run_crawl", True) and url_set:
            crawl_seeds = [
                u for u in url_set[:2]
                if self._is_in_scope(*parse_url_target(u)[:2])
            ]
            if crawl_seeds:
                log.info("[SCAN] Crawling %d seed URL(s) for SPA/JS routes & secrets", len(crawl_seeds))
                crawl_tasks = [
                    (f"crawl:{u}", crawl_web(u, stealth=effective_stealth, headers=auth_headers or None))
                    for u in crawl_seeds
                ]
                crawl_results = await self.scheduler.run_parallel(crawl_tasks)
                for tr in crawl_results:
                    if tr.error or tr.result is None:
                        log.warning("[SCAN] crawl_web failed (%s): %s", tr.name, tr.error)
                        continue
                    crawled_urls, secret_findings = tr.result
                    for cu in crawled_urls:
                        ehost, eport, _ = parse_url_target(cu)
                        if ehost and self._is_in_scope(ehost, eport) and len(url_set) < 60:
                            _add_url(cu)
                    for sf in secret_findings:
                        sf.engagement_id = eng_id
                        all_findings.append(sf)

        urls = url_set

        # 1. Nuclei vulnerability scan (profile + tech-tag + router aware)
        run_nuclei = profile_cfg.get("run_nuclei", True) or (
            "nuclei" in routed_tools and self.config.profile != ScanProfile.NETWORK
        )
        if run_nuclei and ToolRunner.is_available("nuclei") and urls:
            nuclei_extra: list[str] | None = None
            if profile_cfg.get("targeted_nuclei", False):
                matched_tags = {
                    tag for key, tag in _TECH_NUCLEI_TAGS.items()
                    if any(key in tok for tok in tech_tokens)
                }
                if self.config.profile == ScanProfile.API:
                    matched_tags.update({"api", "graphql", "swagger"})
                elif self.config.profile == ScanProfile.QUICK and not matched_tags:
                    routed_tag_candidates = {
                        c for c in routed_checks
                        if c in {"sqli", "xss", "lfi", "ssrf", "cve_scan"}
                    }
                    if "cve_scan" in routed_tag_candidates:
                        routed_tag_candidates.discard("cve_scan")
                        routed_tag_candidates.add("cve")
                    matched_tags.update(routed_tag_candidates or {"exposure", "misconfig"})
                if matched_tags:
                    nuclei_extra = ["-tags", ",".join(sorted(matched_tags))]

            log.info("[SCAN] Running nuclei on %d URLs (stealth=%s, tags=%s)",
                     len(urls), effective_stealth, nuclei_extra)
            try:
                nuclei_kwargs: dict[str, Any] = {
                    "stealth": effective_stealth,
                    "severity_filter": ["critical", "high", "medium", "low"],
                    "extra_args": nuclei_extra,
                }
                if auth_headers:
                    nuclei_kwargs["headers"] = auth_headers
                nuclei_findings = await nuclei_scan(urls, **nuclei_kwargs)
                for f in nuclei_findings:
                    f.engagement_id = eng_id
                all_findings.extend(nuclei_findings)
            except Exception as exc:
                log.warning("[SCAN] nuclei failed: %s", exc)
        elif run_nuclei and urls:
            log.warning("[SCAN] nuclei not found — skipping vulnerability scan")

        # 2. ffuf directory brute-force (root URLs discovered, fallback to scoped target ports)
        ffuf_targets = list(base_roots[:4])
        if not ffuf_targets and self._is_in_scope(target):
            if self._is_in_scope(target, 80):
                ffuf_targets.append(f"http://{target}")
            if self._is_in_scope(target, 443):
                ffuf_targets.append(f"https://{target}")
        if profile_cfg.get("run_ffuf", True) and ToolRunner.is_available("ffuf") and ffuf_targets:
            ffuf_wl = str(profile_cfg.get("ffuf_wordlist", "common"))
            for base in ffuf_targets:
                log.info("[SCAN] Running ffuf on %s (wordlist=%s, stealth=%s)", base, ffuf_wl, effective_stealth)
                try:
                    ffuf_kwargs: dict[str, Any] = {"wordlist_name": ffuf_wl, "stealth": effective_stealth}
                    if auth_headers:
                        ffuf_kwargs["headers"] = auth_headers
                    ffuf_findings = await ffuf_scan(base, **ffuf_kwargs)
                    for f in ffuf_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(ffuf_findings)
                except Exception as exc:
                    log.warning("[SCAN] ffuf failed on %s: %s", base, exc)
        elif profile_cfg.get("run_ffuf", True) and ffuf_targets:
            log.warning("[SCAN] ffuf not found — skipping directory scan")

        # 3. Nikto web server scan
        if profile_cfg.get("run_nikto", True) and ToolRunner.is_available("nikto") and ffuf_targets:
            for base in ffuf_targets[:2]:
                log.info("[SCAN] Running nikto on %s", base)
                try:
                    nikto_kwargs: dict[str, Any] = {}
                    if auth_headers:
                        nikto_kwargs["headers"] = auth_headers
                    nikto_findings = await nikto_scan(base, **nikto_kwargs)
                    for f in nikto_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(nikto_findings)
                except Exception as exc:
                    log.warning("[SCAN] nikto failed on %s: %s", base, exc)
        elif profile_cfg.get("run_nikto", True) and ffuf_targets:
            log.warning("[SCAN] nikto not found — skipping web server scan")

        # 4. TLS configuration & certificate audit
        if profile_cfg.get("run_tls", True) and tls_endpoints:
            log.info("[SCAN] Auditing TLS on %d endpoint(s)", len(tls_endpoints))
            tls_tasks = [
                (f"tls:{h}:{p}", audit_tls(h, p))
                for h, p in tls_endpoints
                if self._is_in_scope(h, p)
            ]
            tls_results = await self.scheduler.run_parallel(tls_tasks) if tls_tasks else []
            for tr in tls_results:
                if tr.error or tr.result is None:
                    log.warning("[SCAN] audit_tls failed (%s): %s", tr.name, tr.error)
                    continue
                for f in tr.result:
                    f.engagement_id = eng_id
                    all_findings.append(f)

        # 5. SSH configuration & crypto audit
        if profile_cfg.get("run_ssh", True) and ssh_endpoints:
            log.info("[SCAN] Auditing SSH on %d endpoint(s)", len(ssh_endpoints))
            ssh_tasks = [
                (f"ssh:{h}:{p}", audit_ssh(h, p))
                for h, p in ssh_endpoints
                if self._is_in_scope(h, p)
            ]
            ssh_results = await self.scheduler.run_parallel(ssh_tasks) if ssh_tasks else []
            for tr in ssh_results:
                if tr.error or tr.result is None:
                    log.warning("[SCAN] audit_ssh failed (%s): %s", tr.name, tr.error)
                    continue
                for f in tr.result:
                    f.engagement_id = eng_id
                    all_findings.append(f)

        # 6. Verified HTTP security headers, CORS & CSP audit
        if profile_cfg.get("run_headers", True) and urls:
            header_urls = [
                u for u in urls[:8]
                if self._is_in_scope(*parse_url_target(u)[:2])
            ]
            if header_urls:
                log.info("[SCAN] Auditing HTTP security headers & CORS on %d URL(s)", len(header_urls))
                try:
                    hdr_findings = await audit_http_security(header_urls, headers=auth_headers or None)
                    for hf in hdr_findings:
                        hf.engagement_id = eng_id
                    all_findings.extend(hdr_findings)
                except Exception as exc:
                    log.warning("[SCAN] audit_http_security failed: %s", exc)

        # 6b. Signature-verified web exposure checks (/.git/HEAD, /.env, /actuator, /metrics)
        if profile_cfg.get("run_exposure", True) and base_roots:
            exp_roots = [
                u for u in base_roots[:2]
                if self._is_in_scope(*parse_url_target(u)[:2])
            ]
            if exp_roots:
                log.info("[SCAN] Verifying exposed web artifacts on %d root(s)", len(exp_roots))
                try:
                    exp_findings = await audit_exposed_artifacts(exp_roots, headers=auth_headers or None)
                    for ef in exp_findings:
                        ef.engagement_id = eng_id
                    all_findings.extend(exp_findings)
                except Exception as exc:
                    log.warning("[SCAN] audit_exposed_artifacts failed: %s", exc)

        # 6c. WordPress passive enumeration when WordPress fingerprinted
        if (
            self.config.profile in (ScanProfile.WEB, ScanProfile.FULL)
            and base_roots
            and wp_hosts
            and ToolRunner.is_available("wpscan")
        ):
            wp_candidates = [u for u in base_roots if parse_url_target(u)[0] in wp_hosts]
            wp_candidates.sort(key=lambda u: 0 if u.startswith("https://") else 1)
            wp_url = wp_candidates[0] if wp_candidates else ""
            if wp_url and self._is_in_scope(*parse_url_target(wp_url)[:2]):
                log.info("[SCAN] Running WPScan passive audit on %s", wp_url)
                try:
                    wp_token = (
                        self.config.wpscan_api_token
                        or self.config.api_keys.get("wpscan")
                        or os.environ.get("NEXUS_WPSCAN_API_TOKEN")
                        or os.environ.get("WPSCAN_API_TOKEN")
                    )
                    wp_kwargs: dict[str, Any] = {
                        "stealth": effective_stealth,
                        "headers": auth_headers or None,
                    }
                    if wp_token:
                        wp_kwargs["api_token"] = wp_token
                    wp_findings = await wpscan_audit(wp_url, **wp_kwargs)
                    for wf in wp_findings:
                        wf.engagement_id = eng_id
                    all_findings.extend(wp_findings)
                except Exception as exc:
                    log.warning("[SCAN] wpscan_audit failed: %s", exc)

        # 6d. GraphQL introspection & API Auth-Diff verification
        scoped_urls = [u for u in urls if self._is_in_scope(*parse_url_target(u)[:2])]
        if profile_cfg.get("run_graphql", False) and scoped_urls:
            try:
                gql_findings = await audit_graphql_introspection(scoped_urls, headers=auth_headers or None)
                for gf in gql_findings:
                    gf.engagement_id = eng_id
                all_findings.extend(gql_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_graphql_introspection failed: %s", exc)

        if profile_cfg.get("run_auth_diff", False) and auth_headers and scoped_urls:
            try:
                auth_findings = await audit_auth_enforcement(scoped_urls, auth_headers)
                for af in auth_findings:
                    af.engagement_id = eng_id
                all_findings.extend(auth_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_auth_enforcement failed: %s", exc)

        # 7. Network & datastore configuration audits (SMB, FTP, Redis, Elasticsearch, Docker, Memcached, DBs, SMTP, Cloud)
        if profile_cfg.get("run_network_audits", True) and net_endpoints:
            log.info("[SCAN] Auditing %d network/datastore service endpoint(s)", len(net_endpoints))
            net_tasks = [
                (f"net:{h}:{p}", audit_network_service(h, p, svc))
                for h, p, svc in net_endpoints
                if self._is_in_scope(h, p)
            ]
            net_results = await self.scheduler.run_parallel(net_tasks) if net_tasks else []
            for tr in net_results:
                if tr.error or tr.result is None:
                    log.warning("[SCAN] audit_network_service failed (%s): %s", tr.name, tr.error)
                    continue
                for nf in tr.result:
                    nf.engagement_id = eng_id
                    all_findings.append(nf)

        # 7b. Authorized credentialed SSH / local OS package patch audit
        ssh_key = getattr(self.config, "ssh_key_path", None)
        ssh_user = getattr(self.config, "ssh_user", None)
        local_audit = bool(getattr(self.config, "local_pkg_audit", False))
        if (local_audit or (ssh_user and ssh_key)) and self._is_in_scope(target):
            try:
                host_findings = await audit_host_packages(
                    target,
                    knowledge=self.knowledge,
                    ssh_user=ssh_user,
                    ssh_key_path=ssh_key,
                    local=local_audit,
                )
                for hf in host_findings:
                    hf.engagement_id = eng_id
                all_findings.extend(host_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_host_packages failed: %s", exc)

        # 8. Plugin scanners (supports both Finding objects & dicts, scope-checked)
        if self.plugins and self.plugins.registry.scanners:
            for pname, sfn in self.plugins.registry.scanners.items():
                try:
                    p_findings = await sfn(target, urls=urls)
                    for raw_pf in p_findings or []:
                        pf = self._coerce_plugin_finding(raw_pf, eng_id, target)
                        if pf is not None:
                            all_findings.append(pf)
                except Exception as exc:
                    log.warning("[SCAN] Plugin '%s' failed: %s", pname, exc)

        # Persist
        for f in all_findings:
            self.db.add_finding(f)

        self.audit.log_action("scan_complete", target=target, extra={
            "id": eng_id, "findings": len(all_findings),
        })
        await self._emit_progress("scan_complete", {
            "engagement_id": eng_id,
            "target": target,
            "findings": len(all_findings),
        })
        log.info("[SCAN] Complete — %d findings", len(all_findings))
        return all_findings

    async def run_correlate(self, eng_id: str) -> list[AttackChain]:
        """Correlate findings — dedup, enrich, build attack chains."""
        self._require_boot()
        self._require_subsystems("db", "audit")
        if self.db is None or self.audit is None:
            raise RuntimeError("Database or audit logger not initialized.")

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

        # AI-enhance high/critical findings in threadpool (optional, silent fallback)
        if self.ai_boost and self.ai_boost.available:
            try:
                for f in enriched:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        enhanced_dict = await asyncio.to_thread(
                            self.ai_boost.enhance_finding, f.model_dump(),
                        )
                        analysis = enhanced_dict.get("ai_analysis", "")
                        if analysis:
                            f.evidence = (f.evidence + "\n\n[AI Analysis]\n" + analysis).strip()[:4000]
                log.info("[CORRELATE] AI enhanced critical/high findings")
            except Exception as exc:
                log.debug("[CORRELATE] AI enhancement skipped: %s", exc)

        # Apply `.nexusignore` baseline suppressions (marks false_positive=True + logs audit count)
        ignore_path = resolve_ignore_path(self.config.ignore_file)
        suppressed_count = 0
        if ignore_path:
            rules = load_ignore_rules(ignore_path)
            if rules:
                enriched, suppressed_count = apply_baseline_suppressions(enriched, rules)
                if suppressed_count:
                    self.audit.log_action(
                        "baseline_suppressed",
                        extra={"id": eng_id, "ignore_file": str(ignore_path), "suppressed": suppressed_count},
                    )
                    log.info("[CORRELATE] Suppressed %d finding(s) via %s", suppressed_count, ignore_path)

        # Persist deduplicated & enriched findings back to SQLite so reports reflect enrichment
        self.db.replace_findings(eng_id, enriched)

        # Replace chains atomically so resume/re-correlate never duplicates chains
        for chain in chains:
            chain.engagement_id = eng_id
        if hasattr(self.db, "replace_chains"):
            self.db.replace_chains(eng_id, chains)
        else:
            with self.db._cursor() as cur:
                cur.execute("DELETE FROM chains WHERE engagement_id = ?", (eng_id,))
            for chain in chains:
                self.db.add_chain(chain)

        # Plugin post-correlation hooks (sync and async supported)
        if self.plugins and self.plugins.registry.post_hooks:
            await self.plugins.registry.run_post_hooks(
                eng_id=eng_id, findings=enriched, chains=chains,
            )

        self.audit.log_action("correlate_complete", extra={
            "id": eng_id,
            "findings_enriched": len(enriched),
            "chains_built": len(chains),
        })
        await self._emit_progress("correlate_complete", {
            "engagement_id": eng_id,
            "findings_enriched": len(enriched),
            "chains_built": len(chains),
        })
        log.info(
            "[CORRELATE] Complete — %d enriched findings, %d attack chains",
            len(enriched), len(chains),
        )
        return chains

    async def run_exploit(self, eng_id: str, confirm: bool | None = None) -> list[Finding]:
        """Run exploitation phase — test default creds and known SQLi via ExploitExecutor."""
        self._require_boot()
        self._require_subsystems("audit", "db", "exploit_executor")
        if self.audit is None or self.db is None or self.exploit_executor is None:
            raise RuntimeError("Exploit subsystems not initialized; call boot() first.")

        self._advance_phase(eng_id, EngagementPhase.EXPLOIT)
        self.audit.log_action("exploit_start", extra={"id": eng_id})

        effective_confirm = (
            self.config.auto_confirm_exploits if confirm is None else bool(confirm)
        )
        has_confirm_cb = bool(
            getattr(self.exploit_executor, "confirm_callback", None)
            or getattr(self.exploit_executor, "_confirm_callback", None)
        )
        if not effective_confirm and not has_confirm_cb:
            log.warning(
                "[EXPLOIT] Active exploitation skipped — pass confirm=True or set auto_confirm_exploits=True."
            )
            self.audit.log_action("exploit_skipped", result="unconfirmed", extra={"id": eng_id})
            await self._emit_progress("exploit_complete", {"engagement_id": eng_id, "findings": 0, "skipped": True})
            return []

        all_findings: list[Finding] = []
        all_creds: list[Credential] = []

        findings = self.db.get_findings(eng_id)
        targets = self.db.get_targets(eng_id)

        prev_auto_confirm = self.exploit_executor._auto_confirm
        self.exploit_executor._auto_confirm = effective_confirm
        try:
            # 1. Test default credentials on open services (scope + audit + confirmation enforced)
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

                        creds_holder: list[Credential] = []
                        cred_findings_holder: list[Finding] = []

                        async def _run_cred(
                            _host: str = host,
                            _port: int = f.port,
                            _service: str = service,
                            _pairs: list[tuple[str, str]] = cred_pairs,
                            _ch: list[Credential] = creds_holder,
                            _fh: list[Finding] = cred_findings_holder,
                        ) -> str:
                            creds, cred_findings = await test_default_creds(
                                _host, _port, _service, _pairs, timeout=60,
                            )
                            _ch.extend(creds)
                            _fh.extend(cred_findings)
                            if not creds and not cred_findings:
                                raise RuntimeError("No valid default credentials found")
                            return f"Found {len(creds)} valid credential(s)"

                        attempt = await self.exploit_executor.execute(
                            "hydra",
                            host,
                            f.port,
                            f"Default credential test ({service})",
                            _run_cred,
                            severity_on_success=Severity.CRITICAL,
                        )
                        if attempt.result == ExploitResult.SUCCESS:
                            for c in creds_holder:
                                c.engagement_id = eng_id
                                self.db.add_credential(c)
                            all_creds.extend(creds_holder)
                            for ef in cred_findings_holder:
                                ef.engagement_id = eng_id
                            all_findings.extend(cred_findings_holder)
            else:
                log.warning("[EXPLOIT] hydra not found — skipping credential testing")

            # 2. SQLi testing on HTTP findings with parameters (scope + audit + IPv6-safe URL parsing)
            if ToolRunner.is_available("sqlmap"):
                tested_urls: set[str] = set()
                for f in findings:
                    if "?" in f.evidence and "=" in f.evidence:
                        for line in f.evidence.splitlines():
                            if "?" in line and "=" in line and "http" in line.lower():
                                url = line.strip().split()[-1] if line.strip() else ""
                                if not url.startswith(("http://", "https://")) or url in tested_urls:
                                    continue
                                tested_urls.add(url)
                                parsed_u = urlparse(url)
                                sqli_host = (parsed_u.hostname or "").strip().lower()
                                sqli_port = parsed_u.port or (
                                    443 if parsed_u.scheme.lower() == "https" else 80
                                )
                                if not sqli_host:
                                    continue

                                sqli_holder: list[Finding] = []

                                async def _run_sqli(
                                    _url: str = url,
                                    _sh: list[Finding] = sqli_holder,
                                ) -> str:
                                    sqli_findings = await sqlmap_scan(_url, timeout=120)
                                    _sh.extend(sqli_findings)
                                    if not sqli_findings:
                                        raise RuntimeError("No SQL injection confirmed")
                                    return f"Confirmed {len(sqli_findings)} SQLi finding(s)"

                                attempt = await self.exploit_executor.execute(
                                    "sqlmap",
                                    sqli_host,
                                    sqli_port,
                                    f"SQLi verification on {url}",
                                    _run_sqli,
                                    severity_on_success=Severity.CRITICAL,
                                )
                                if attempt.result == ExploitResult.SUCCESS:
                                    for sf in sqli_holder:
                                        sf.engagement_id = eng_id
                                    all_findings.extend(sqli_holder)
                                break
            else:
                log.warning("[EXPLOIT] sqlmap not found — skipping SQLi testing")
        finally:
            self.exploit_executor._auto_confirm = prev_auto_confirm

        # Persist findings
        for f in all_findings:
            self.db.add_finding(f)

        self.audit.log_action("exploit_complete", extra={
            "id": eng_id,
            "findings": len(all_findings),
            "credentials": len(all_creds),
        })
        await self._emit_progress("exploit_complete", {
            "engagement_id": eng_id,
            "findings": len(all_findings),
            "credentials": len(all_creds),
        })
        log.info("[EXPLOIT] Complete — %d findings, %d credentials", len(all_findings), len(all_creds))
        return all_findings

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
        """Run the complete engagement pipeline: Recon → Scan → Correlate → Exploit → Report.

        Supports scan profiles (quick/web/network/api/full) and phase resume via resume_id.
        Returns the engagement ID.
        """
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
            self.audit.log_action("engage_start", target=target, extra={
                "id": eng_id,
                "skip_exploit": skip_exploit,
                "profile": self.config.profile.value,
                "resume_from": start_phase.value if resume_id else None,
            })

            try:
                if start_idx >= _PHASE_ORDER[EngagementPhase.COMPLETE]:
                    log.info("[ENGAGE] Engagement %s is already complete", eng_id)
                    return eng_id

                # Phase 1: Recon
                if start_idx <= _PHASE_ORDER[EngagementPhase.RECON]:
                    await self.run_recon(eng_id, target)

                # Phase 2: Scan
                if start_idx <= _PHASE_ORDER[EngagementPhase.SCAN]:
                    await self.run_scan(eng_id, target)

                # Phase 3: Correlate
                if start_idx <= _PHASE_ORDER[EngagementPhase.CORRELATE]:
                    await self.run_correlate(eng_id)

                # Phase 4: Exploit (optional)
                if not skip_exploit and start_idx <= _PHASE_ORDER[EngagementPhase.EXPLOIT]:
                    await self.run_exploit(eng_id, confirm=confirm_exploit)

                # Phase 5: Report
                if start_idx <= _PHASE_ORDER[EngagementPhase.REPORT]:
                    self._advance_phase(eng_id, EngagementPhase.REPORT)

                    # AI executive summary in threadpool (optional, silent fallback)
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
                            if ai_summary:
                                log.info("[REPORT] AI executive summary generated (%d chars)", len(ai_summary))
                        except Exception as exc:
                            log.debug("[REPORT] AI summary skipped: %s", exc)

                    report_dir = self.config.output_dir / eng_id
                    generated = generate_report(
                        self.db, eng_id, report_dir,
                        formats=["md", "html", "sarif"],
                        ai_summary=ai_summary,
                    )
                    log.info("[REPORT] Generated %d reports: %s", len(generated), generated)

                # Complete
                self._advance_phase(eng_id, EngagementPhase.COMPLETE)
                self.audit.log_action("engage_complete", target=target, extra={"id": eng_id})
                await self._emit_progress("engage_complete", {"engagement_id": eng_id, "target": target})

            except Exception as exc:
                log.error("Engagement failed: %s", exc)
                self.audit.log_action("engage_failed", target=target, result=str(exc),
                                      extra={"id": eng_id})
                raise

            return eng_id
        finally:
            self.config = orig_config

    # ── Stats / Info ──────────────────────────────────────────────

    def brain_stats(self) -> dict[str, Any]:
        """Return stats about the loaded brain subsystems."""
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
