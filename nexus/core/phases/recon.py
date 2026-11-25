"""Reconnaissance phase runner (subdomains -> DNS -> ports -> tech -> WAF -> OSINT -> plugins)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from nexus.core.config import SCAN_PROFILE_SETTINGS, ScanProfile
from nexus.db.models import EngagementPhase, Finding, Severity, Target

if TYPE_CHECKING:
    from nexus.core.engine import NexusEngine

log = logging.getLogger("nexus.engine.recon")


class ReconPhase:
    """Executes the multi-step reconnaissance phase for NexusEngine."""

    async def run(self, engine: NexusEngine, eng_id: str, target: str) -> list[Finding]:
        import nexus.core.engine as eng_mod

        engine._require_boot()
        engine._require_subsystems("audit", "db", "scheduler")
        if engine.audit is None or engine.db is None or engine.scheduler is None:
            raise RuntimeError("Engine subsystems not initialized; call boot() first.")

        if not engine._is_in_scope(target):
            raise ValueError(f"SCOPE VIOLATION: Target '{target}' is outside authorized scope.")

        engine._advance_phase(eng_id, EngagementPhase.RECON)
        engine.audit.log_action("recon_start", target=target, extra={"id": eng_id})
        await engine._emit_progress("recon_start", {"engagement_id": eng_id, "target": target})

        all_findings: list[Finding] = []
        stealth = engine._active_stealth_profile()
        profile_cfg = SCAN_PROFILE_SETTINGS.get(
            engine.config.profile.value, SCAN_PROFILE_SETTINGS[ScanProfile.FULL.value]
        )

        # 1. Subdomain enumeration
        log.info(
            "[RECON] Subdomain enumeration for %s (stealth=%s, profile=%s)",
            target,
            stealth,
            engine.config.profile.value,
        )
        raw_targets = await eng_mod.enumerate_subdomains(
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
            if not engine._is_target_in_scope(host_l, t.ip):
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
        targets, dns_findings = await eng_mod.enumerate_dns(targets)
        target_ip_map = {t.host.lower(): t.ip for t in targets if t.host}
        for f in dns_findings:
            f_host = (f.host or target).strip()
            if not engine._is_target_in_scope(
                f_host, target_ip_map.get(f_host.lower(), ""), f.port
            ):
                continue
            f.engagement_id = eng_id
            all_findings.append(f)

        # Persist targets BEFORE adding ports so FK(target_id -> targets.id) never fails
        for t in targets:
            engine.db.add_target(t)

        # 3. Port scanning (bounded parallelism; stealth-ordered if needed)
        scan_targets = engine.stealth.shuffle_targets(targets) if engine.stealth else targets
        in_scope_targets = [
            (t, t.ip or t.host)
            for t in scan_targets
            if (t.ip or t.host) and engine._is_target_in_scope(t.host, t.ip)
        ]
        log.info("[RECON] Port scanning %d targets", len(in_scope_targets))

        async def _scan_target_ports(
            t: Target, scan_target: str
        ) -> tuple[Target, str, dict[str, Any]]:
            result = await eng_mod.nmap_scan(scan_target, stealth=stealth)
            return t, scan_target, result

        scan_tasks = [
            (f"nmap:{scan_target}", _scan_target_ports(t, scan_target))
            for t, scan_target in in_scope_targets
        ]
        task_results = await engine.scheduler.run_parallel(scan_tasks) if scan_tasks else []

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
            engine.db.add_target(t)
            for port in result["ports"]:
                if not engine._is_target_in_scope(t.host, t.ip, port.port):
                    continue
                port.target_id = t.id
                engine.db.add_port(port)
                if (
                    engine.knowledge
                    and port.state.lower().startswith("open")
                    and (port.service or port.version)
                ):
                    banner = f"{port.service} {port.version}".strip()
                    for svc_name, entry in engine.knowledge.match_banner_vulns(
                        port.service, port.version
                    ):
                        dedup_key = (t.host, port.port, entry.cve)
                        if dedup_key in seen_banner_cves:
                            continue
                        seen_banner_cves.add(dedup_key)
                        all_findings.append(
                            Finding(
                                engagement_id=eng_id,
                                host=t.host,
                                port=port.port,
                                protocol=port.protocol or port.service or "tcp",
                                title=f"{entry.cve}: {entry.description or svc_name}",
                                description=(
                                    f"Discovered service banner '{banner}' on port {port.port} matched "
                                    f"{entry.cve} (affected: {entry.affected_versions})."
                                ),
                                severity=eng_mod._SEV_STR_MAP.get(
                                    entry.severity.lower(), Severity.MEDIUM
                                ),
                                cvss_score=float(entry.cvss or 0.0),
                                cve_ids=[entry.cve],
                                cwe_id=(
                                    entry.vuln_type if entry.vuln_type.startswith("CWE-") else ""
                                ),
                                evidence=f"Detected service banner: {banner}",
                                remediation=entry.remediation,
                                tool_source="knowledge_banner",
                                confirmed=False,
                            )
                        )
            for f in result["findings"]:
                f_host = (f.host or t.host or scan_target).strip()
                if f_host in (t.host, t.ip, scan_target):
                    allowed = engine._is_target_in_scope(t.host, t.ip, f.port)
                else:
                    allowed = engine._is_in_scope(f_host, f.port)
                if not allowed:
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)

        # 4. Tech-stack detection
        log.info("[RECON] Tech-stack detection")
        targets = await eng_mod.detect_tech_stack(targets)

        # 5. WAF detection
        if profile_cfg.get("run_waf", True):
            log.info("[RECON] WAF detection")
            targets, waf_findings = await eng_mod.detect_waf(targets)
            for f in waf_findings:
                f_host = (f.host or target).strip()
                if not engine._is_target_in_scope(
                    f_host, target_ip_map.get(f_host.lower(), ""), f.port
                ):
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)

            if engine.waf:
                for t in targets:
                    if t.waf_detected and engine.expert:
                        engine.expert.add_fact(
                            f"waf_{t.waf_detected.lower().replace(' ', '_')}",
                            True,
                            source="wafw00f",
                        )
        else:
            log.info("[RECON] Skipping WAF detection for profile=%s", engine.config.profile.value)

        # 6. OSINT gathering
        if profile_cfg.get("run_osint", True):
            log.info("[RECON] OSINT gathering")
            osint_targets, osint_findings = await eng_mod.gather_osint(target)
            for t2 in osint_targets:
                h_l = t2.host.lower().strip()
                if h_l and h_l not in seen_hosts and engine._is_target_in_scope(h_l, t2.ip):
                    seen_hosts.add(h_l)
                    t2.engagement_id = eng_id
                    targets.append(t2)
            for f in osint_findings:
                f_host = (f.host or target).strip()
                if not engine._is_target_in_scope(
                    f_host, target_ip_map.get(f_host.lower(), ""), f.port
                ):
                    continue
                f.engagement_id = eng_id
                all_findings.append(f)
        else:
            log.info("[RECON] Skipping OSINT gathering for profile=%s", engine.config.profile.value)

        # 7. Plugin recon modules
        if engine.plugins and engine.plugins.registry.recon_modules:
            for pname, rfn in engine.plugins.registry.recon_modules.items():
                try:
                    p_findings = await rfn(target, targets=targets)
                    for raw_pf in p_findings or []:
                        pf = engine._coerce_plugin_finding(raw_pf, eng_id, target)
                        if pf is not None:
                            all_findings.append(pf)
                except Exception as exc:
                    log.warning("[RECON] Plugin '%s' failed: %s", pname, exc)

        for t in targets:
            engine.db.add_target(t)
        for f in all_findings:
            engine.db.add_finding(f)

        if engine.expert:
            for f in all_findings:
                if f.port:
                    engine.expert.add_fact(f"port_{f.port}", True, source=f.tool_source)

        engine.audit.log_action(
            "recon_complete",
            target=target,
            extra={
                "id": eng_id,
                "targets_found": len(targets),
                "findings": len(all_findings),
            },
        )
        await engine._emit_progress(
            "recon_complete",
            {
                "engagement_id": eng_id,
                "target": target,
                "targets_found": len(targets),
                "findings": len(all_findings),
            },
        )
        log.info("[RECON] Complete — %d targets, %d findings", len(targets), len(all_findings))
        return all_findings
