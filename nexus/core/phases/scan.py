"""Scanning phase runner — routed web, API, ZAP, TLS, SSH, and service audits."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nexus.core.auth import StatefulAuthSession
from nexus.core.config import SCAN_PROFILE_SETTINGS, ScanProfile
from nexus.correlator.dedup import extract_endpoint
from nexus.db.models import EngagementPhase, Finding
from nexus.scanner._http import parse_url_target, redact_headers
from nexus.scanner.passive_dast import analyze_html_passive
from nexus.scanner.yaml_rules import YamlPassiveRuleEngine
from nexus.scanner.zap import zap_scan
from nexus.stealth.controller import set_active_stealth

if TYPE_CHECKING:
    from nexus.core.engine import NexusEngine

log = logging.getLogger("nexus.engine.scan")


async def _run_passive_response_checks(
    urls: list[str],
    rule_engine: YamlPassiveRuleEngine,
    auth_headers: dict[str, str],
    eng_id: str,
    *,
    stealth: str | None = None,
    already_seen: set[tuple[str, int | None, str, str, str]] | None = None,
) -> list[Finding]:
    """Fetch up to 25 scoped URLs concurrently and run YAML + HTML/JS passive checks."""
    from nexus.scanner._http import make_http_client

    passive_urls = urls[:25]
    sem = asyncio.Semaphore(6)
    findings: list[Finding] = []
    seen: set[tuple[str, int | None, str, str, str]] = (
        set(already_seen) if already_seen is not None else set()
    )

    async def _inspect_one(client: Any, target_url: str) -> list[Finding]:
        async with sem:
            try:
                resp = await client.get(target_url)
            except Exception as exc:
                log.debug("[SCAN] YAML passive rule fetch failed for %s: %s", target_url, exc)
                return []
        raw_headers = getattr(resp, "headers", None)
        if hasattr(raw_headers, "multi_items"):
            hdr_items = list(raw_headers.multi_items())
            rule_headers: Any = raw_headers
        elif raw_headers is not None and hasattr(raw_headers, "items"):
            hdr_items = list(raw_headers.items())
            rule_headers = raw_headers
        else:
            hdr_items = []
            rule_headers = {}
        ctype = next(
            (str(v) for k, v in hdr_items if str(k).lower() == "content-type"),
            "",
        )
        raw_text = getattr(resp, "text", "")
        body = raw_text if isinstance(raw_text, str) else ""
        raw_status = getattr(resp, "status_code", 0)
        status_code = (
            raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 0
        )

        found: list[Finding] = []
        if rule_engine.rule_count > 0:
            found.extend(
                rule_engine.inspect_response(
                    target_url,
                    status_code=status_code,
                    headers=rule_headers,
                    body=body,
                )
            )
        found.extend(analyze_html_passive(target_url, body, content_type=ctype))
        return found

    async with make_http_client(
        headers=auth_headers or None, timeout=15.0, stealth=stealth
    ) as client:
        batches = await asyncio.gather(
            *(_inspect_one(client, u) for u in passive_urls),
            return_exceptions=True,
        )

    for target_url, batch in zip(passive_urls, batches, strict=True):
        if isinstance(batch, BaseException):
            log.debug("[SCAN] Passive inspection failed for %s: %s", target_url, batch)
            continue
        for pf in batch:
            endpoint = extract_endpoint(pf) or target_url
            dedup_key = (pf.host, pf.port, pf.tool_source, pf.title, endpoint)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            pf.engagement_id = eng_id
            findings.append(pf)

    return findings


class ScanPhase:
    """Executes the scanning phase for NexusEngine with crawler/proxy/OpenAPI feedback."""

    async def run(self, engine: NexusEngine, eng_id: str, target: str) -> list[Finding]:
        import nexus.core.engine as eng_mod

        engine._require_boot()
        engine._require_subsystems("audit", "db", "scheduler")
        if engine.audit is None or engine.db is None or engine.scheduler is None:
            raise RuntimeError("Engine subsystems not initialized; call boot() first.")
        engine._advance_phase(eng_id, EngagementPhase.SCAN)

        profile_cfg = SCAN_PROFILE_SETTINGS.get(
            engine.config.profile.value, SCAN_PROFILE_SETTINGS[ScanProfile.FULL.value]
        )
        auth_headers = dict(engine.config.auth_headers) if engine.config.auth_headers else {}

        # Optional stateful login/session refresh before scanning
        if getattr(engine.config, "auth_login_url", None):
            try:
                auth_sess = StatefulAuthSession(
                    engine.config.auth_login_url,
                    login_body=getattr(engine.config, "auth_login_body", None),
                    token_field=getattr(engine.config, "auth_token_field", "access_token"),
                    base_headers=auth_headers,
                )
                auth_headers = await auth_sess.authenticate(scope=engine.scope)
                engine.config.auth_headers = dict(auth_headers)
            except Exception as exc:
                log.warning("[SCAN] Stateful authentication failed: %s", exc)

        openapi_spec = engine.config.openapi_spec
        engine.audit.log_action(
            "scan_start",
            target=target,
            extra={
                "id": eng_id,
                "profile": engine.config.profile.value,
                "auth_headers": redact_headers(auth_headers),
                "openapi_spec": str(openapi_spec) if openapi_spec else None,
            },
        )
        await engine._emit_progress("scan_start", {"engagement_id": eng_id, "target": target})

        all_findings: list[Finding] = []
        stealth = engine._active_stealth_profile()
        targets_db = engine.db.get_targets(eng_id)

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

        if engine.expert:
            engine.expert.clear_facts()

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
            if not host or not engine._is_target_in_scope(host, t.ip):
                continue
            for tech in t.tech_stack:
                tok = tech.lower().strip()
                if tok:
                    tech_tokens.add(tok)
                    if "wordpress" in tok:
                        wp_hosts.add(host.lower())
            if t.waf_detected:
                wafs_detected.add(t.waf_detected)

            open_ports = engine.db.get_ports(t.id)
            if open_ports:
                for p in open_ports:
                    if p.state and not p.state.lower().startswith("open"):
                        continue
                    if not engine._is_target_in_scope(host, t.ip, p.port):
                        continue
                    svc = p.service.lower().strip()
                    if (not svc or svc in ("unknown", "tcpwrapped")) and engine.router:
                        inferred = engine.router.identify_service_by_port(p.port)
                        if inferred:
                            svc = inferred[0]
                    if engine.expert:
                        engine.expert.add_fact(f"port_{p.port}", True, source="db")
                        if svc:
                            engine.expert.add_fact(f"service_{svc}", True, source="db")

                    route_info = engine.router.route(svc) if (engine.router and svc) else {}
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
                        if engine.expert:
                            engine.expert.add_fact("service_https", True, source="db")
                        discovered_services.add("https" if not svc or "http" in svc else svc)
                    elif p.port in (80, 8000, 8080, 8081, 8888, 3000, 5000, 9000) or "http" in svc:
                        suffix = "" if p.port == 80 else f":{p.port}"
                        _add_url(f"http://{host}{suffix}")
                        if engine.expert:
                            engine.expert.add_fact("service_http", True, source="db")
                        discovered_services.add("http" if not svc else svc)

                    if p.port == 22 or "ssh" in svc or "nmap_ssh_audit" in routed_tools_for_port:
                        if (host, p.port) not in seen_ssh:
                            seen_ssh.add((host, p.port))
                            ssh_endpoints.append((host, p.port))
                        if engine.expert:
                            engine.expert.add_fact("service_ssh", True, source="db")
                        discovered_services.add("ssh")

                    hint = port_service_hints.get(p.port)
                    for alias in ("smb", "ftp", "mysql", "mssql", "rdp", "smtp", "dns"):
                        if alias == hint or alias in svc:
                            if engine.expert:
                                engine.expert.add_fact(f"service_{alias}", True, source="db")
                            discovered_services.add(alias)

                    if p.port in (
                        6379,
                        21,
                        445,
                        139,
                        9200,
                        2375,
                        11211,
                        27017,
                        5432,
                        3306,
                        25,
                        587,
                        2379,
                        8500,
                        10250,
                        10255,
                    ) or any(
                        tok in svc
                        for tok in (
                            "redis",
                            "ftp",
                            "smb",
                            "microsoft-ds",
                            "netbios-ssn",
                            "elastic",
                            "docker",
                            "memcache",
                            "mongo",
                            "postgres",
                            "mysql",
                            "mariadb",
                            "smtp",
                            "etcd",
                            "consul",
                            "kubelet",
                        )
                    ):
                        if (host, p.port) not in seen_net:
                            seen_net.add((host, p.port))
                            net_endpoints.append((host, p.port, svc))
            else:
                if engine._is_target_in_scope(host, t.ip, 80):
                    _add_url(f"http://{host}")
                if engine._is_target_in_scope(host, t.ip, 443):
                    _add_url(f"https://{host}")

        if not url_set and engine._is_in_scope(target):
            if "://" in target:
                thost, tport, _ = parse_url_target(target)
                if thost and engine._is_in_scope(thost, tport):
                    _add_url(target)
            else:
                if engine._is_in_scope(target, 80):
                    _add_url(f"http://{target}")
                if engine._is_in_scope(target, 443):
                    _add_url(f"https://{target}")

        # Populate Expert RuleEngine, query ServiceRouter & WAFBypassLibrary
        effective_stealth = stealth
        waf_bypasses: dict[str, list[dict[str, str]]] = {}
        waf_bypass_count = 0
        if engine.expert:
            if tech_tokens:
                engine.expert.add_fact("tech_stack", " ".join(sorted(tech_tokens)), source="recon")
            if wafs_detected:
                engine.expert.add_fact(
                    "waf_status", ", ".join(sorted(wafs_detected)), source="wafw00f"
                )
                for w in wafs_detected:
                    engine.expert.add_fact(
                        f"waf_{w.lower().replace(' ', '_')}", True, source="wafw00f"
                    )
            else:
                engine.expert.add_fact("waf_status", "none", source="wafw00f")

        if wafs_detected:
            if stealth in ("loud", "normal"):
                effective_stealth = "quiet"
            if engine.waf:
                for w in sorted(wafs_detected):
                    bypasses = engine.waf.get_bypasses(w)
                    waf_bypasses[w] = bypasses
                    waf_bypass_count += len(bypasses)
                    if (
                        any(b.get("technique") == "slow_rate" for b in bypasses)
                        and effective_stealth == "normal"
                    ):
                        effective_stealth = "quiet"
            if engine.stealth is not None and engine.stealth.level != effective_stealth:
                engine.stealth.set_level(effective_stealth)
                set_active_stealth(engine.stealth)
            log.info(
                "[SCAN] WAF detected (%s) — throttling stealth %s -> %s (%d bypass techniques)",
                ", ".join(sorted(wafs_detected)),
                stealth,
                effective_stealth,
                waf_bypass_count,
            )

        expert_recs = engine.expert.evaluate() if engine.expert else []
        service_routes = (
            {svc: engine.router.route(svc) for svc in sorted(discovered_services)}
            if engine.router
            else {}
        )
        routed_tools: set[str] = {t for r in service_routes.values() for t in r.get("tools", [])}
        routed_checks: set[str] = {c for r in service_routes.values() for c in r.get("checks", [])}
        engine.audit.log_action(
            "routing_plan",
            target=target,
            extra={
                "id": eng_id,
                "profile": engine.config.profile.value,
                "effective_stealth": effective_stealth,
                "auth_headers": redact_headers(auth_headers),
                "openapi_spec": str(openapi_spec) if openapi_spec else None,
                "wafs_detected": sorted(wafs_detected),
                "waf_bypass_techniques": waf_bypass_count,
                "waf_recommended_techniques": sorted(
                    {
                        b.get("technique", "")
                        for b_list in waf_bypasses.values()
                        for b in b_list
                        if b.get("technique")
                    }
                ),
                "expert_rules": [
                    {"rule": name, "actions": actions} for name, actions in expert_recs
                ],
                "service_routes": service_routes,
                "routed_tools": sorted(routed_tools),
                "routed_checks": sorted(routed_checks),
            },
        )

        base_roots = list(url_set)

        # Feed back any proxy-recorded in-scope URLs for this engagement
        if hasattr(engine.db, "get_proxy_history"):
            try:
                for p_entry in engine.db.get_proxy_history(eng_id, limit=50):
                    pu = p_entry.url
                    ehost, eport, _ = parse_url_target(pu)
                    if ehost and engine._is_in_scope(ehost, eport) and len(url_set) < 60:
                        _add_url(pu)
            except Exception as exc:
                log.debug("[SCAN] Proxy history URL feedback skipped: %s", exc)

        # 0a. OpenAPI / Swagger specification parsing
        if openapi_spec:
            base_hint = url_set[0] if url_set else f"https://{target}"
            try:
                api_urls, api_findings = eng_mod.audit_openapi_spec(
                    openapi_spec, base_url_override=base_hint
                )
                for au in api_urls:
                    ehost, eport, _ = parse_url_target(au)
                    if ehost and engine._is_in_scope(ehost, eport) and len(url_set) < 60:
                        _add_url(au)
                for af in api_findings:
                    af.engagement_id = eng_id
                    all_findings.append(af)
            except Exception as exc:
                log.warning("[SCAN] OpenAPI spec parsing failed (%s): %s", openapi_spec, exc)

        # 0b. SPA / JS crawling & passive client-side secret detection
        if profile_cfg.get("run_crawl", True) and url_set:
            crawl_seeds = [u for u in url_set[:2] if engine._is_in_scope(*parse_url_target(u)[:2])]
            if crawl_seeds:
                log.info(
                    "[SCAN] Crawling %d seed URL(s) for SPA/JS routes & secrets", len(crawl_seeds)
                )
                crawl_tasks = [
                    (
                        f"crawl:{u}",
                        eng_mod.crawl_web(
                            u, stealth=effective_stealth, headers=auth_headers or None
                        ),
                    )
                    for u in crawl_seeds
                ]
                crawl_results = await engine.scheduler.run_parallel(crawl_tasks)
                for tr in crawl_results:
                    if tr.error or tr.result is None:
                        log.warning("[SCAN] crawl_web failed (%s): %s", tr.name, tr.error)
                        continue
                    crawled_urls, secret_findings = tr.result
                    for cu in crawled_urls:
                        ehost, eport, _ = parse_url_target(cu)
                        if ehost and engine._is_in_scope(ehost, eport) and len(url_set) < 60:
                            _add_url(cu)
                    for sf in secret_findings:
                        sf.engagement_id = eng_id
                        all_findings.append(sf)

        urls = url_set

        # 1. Nuclei vulnerability scan
        run_nuclei = profile_cfg.get("run_nuclei", True) or (
            "nuclei" in routed_tools and engine.config.profile != ScanProfile.NETWORK
        )
        if run_nuclei and eng_mod.ToolRunner.is_available("nuclei") and urls:
            nuclei_extra: list[str] | None = None
            if profile_cfg.get("targeted_nuclei", False):
                matched_tags = {
                    tag
                    for key, tag in eng_mod._TECH_NUCLEI_TAGS.items()
                    if any(key in tok for tok in tech_tokens)
                }
                if engine.config.profile == ScanProfile.API:
                    matched_tags.update({"api", "graphql", "swagger"})
                elif engine.config.profile == ScanProfile.QUICK and not matched_tags:
                    routed_tag_candidates = {
                        c for c in routed_checks if c in {"sqli", "xss", "lfi", "ssrf", "cve_scan"}
                    }
                    if "cve_scan" in routed_tag_candidates:
                        routed_tag_candidates.discard("cve_scan")
                        routed_tag_candidates.add("cve")
                    matched_tags.update(routed_tag_candidates or {"exposure", "misconfig"})
                if matched_tags:
                    nuclei_extra = ["-tags", ",".join(sorted(matched_tags))]

            log.info(
                "[SCAN] Running nuclei on %d URLs (stealth=%s, tags=%s)",
                len(urls),
                effective_stealth,
                nuclei_extra,
            )
            try:
                nuclei_kwargs: dict[str, Any] = {
                    "stealth": effective_stealth,
                    "severity_filter": ["critical", "high", "medium", "low"],
                    "extra_args": nuclei_extra,
                }
                if auth_headers:
                    nuclei_kwargs["headers"] = auth_headers
                nuclei_findings = await eng_mod.nuclei_scan(urls, **nuclei_kwargs)
                for f in nuclei_findings:
                    f.engagement_id = eng_id
                all_findings.extend(nuclei_findings)
            except Exception as exc:
                log.warning("[SCAN] nuclei failed: %s", exc)
        elif run_nuclei and urls:
            log.warning("[SCAN] nuclei not found — skipping vulnerability scan")

        # 2. ffuf directory brute-force
        ffuf_targets = list(base_roots[:4])
        if not ffuf_targets and engine._is_in_scope(target):
            if engine._is_in_scope(target, 80):
                ffuf_targets.append(f"http://{target}")
            if engine._is_in_scope(target, 443):
                ffuf_targets.append(f"https://{target}")
        if (
            profile_cfg.get("run_ffuf", True)
            and eng_mod.ToolRunner.is_available("ffuf")
            and ffuf_targets
        ):
            ffuf_wl = str(profile_cfg.get("ffuf_wordlist", "common"))
            for base in ffuf_targets:
                log.info(
                    "[SCAN] Running ffuf on %s (wordlist=%s, stealth=%s)",
                    base,
                    ffuf_wl,
                    effective_stealth,
                )
                try:
                    ffuf_kwargs: dict[str, Any] = {
                        "wordlist_name": ffuf_wl,
                        "stealth": effective_stealth,
                    }
                    if auth_headers:
                        ffuf_kwargs["headers"] = auth_headers
                    ffuf_findings = await eng_mod.ffuf_scan(base, **ffuf_kwargs)
                    for f in ffuf_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(ffuf_findings)
                except Exception as exc:
                    log.warning("[SCAN] ffuf failed on %s: %s", base, exc)
        elif profile_cfg.get("run_ffuf", True) and ffuf_targets:
            log.warning("[SCAN] ffuf not found — skipping directory scan")

        # 3. Nikto web server scan
        if (
            profile_cfg.get("run_nikto", True)
            and eng_mod.ToolRunner.is_available("nikto")
            and ffuf_targets
        ):
            for base in ffuf_targets[:2]:
                log.info("[SCAN] Running nikto on %s", base)
                try:
                    nikto_kwargs: dict[str, Any] = {}
                    if auth_headers:
                        nikto_kwargs["headers"] = auth_headers
                    nikto_findings = await eng_mod.nikto_scan(base, **nikto_kwargs)
                    for f in nikto_findings:
                        f.engagement_id = eng_id
                    all_findings.extend(nikto_findings)
                except Exception as exc:
                    log.warning("[SCAN] nikto failed on %s: %s", base, exc)
        elif profile_cfg.get("run_nikto", True) and ffuf_targets:
            log.warning("[SCAN] nikto not found — skipping web server scan")

        # 3b. Optional OWASP ZAP Automation Framework scan when installed
        zap_exe = getattr(engine.config, "zap_path", "zap.sh")
        if (
            engine.config.profile in (ScanProfile.WEB, ScanProfile.API, ScanProfile.FULL)
            and base_roots
            and (
                eng_mod.ToolRunner.is_available(zap_exe)
                or eng_mod.ToolRunner.is_available("zaproxy")
            )
        ):
            for base in base_roots[:1]:
                if engine._is_in_scope(*parse_url_target(base)[:2]):
                    try:
                        zap_findings = await zap_scan(
                            base,
                            zap_path=zap_exe,
                            scope=engine.scope,
                            active_scan=False,
                        )
                        for zf in zap_findings:
                            zf.engagement_id = eng_id
                        all_findings.extend(zap_findings)
                    except Exception as exc:
                        log.warning("[SCAN] ZAP scan failed on %s: %s", base, exc)

        # 4. TLS configuration & certificate audit
        if profile_cfg.get("run_tls", True) and tls_endpoints:
            log.info("[SCAN] Auditing TLS on %d endpoint(s)", len(tls_endpoints))
            tls_tasks = [
                (f"tls:{h}:{p}", eng_mod.audit_tls(h, p))
                for h, p in tls_endpoints
                if engine._is_in_scope(h, p)
            ]
            tls_results = await engine.scheduler.run_parallel(tls_tasks) if tls_tasks else []
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
                (f"ssh:{h}:{p}", eng_mod.audit_ssh(h, p))
                for h, p in ssh_endpoints
                if engine._is_in_scope(h, p)
            ]
            ssh_results = await engine.scheduler.run_parallel(ssh_tasks) if ssh_tasks else []
            for tr in ssh_results:
                if tr.error or tr.result is None:
                    log.warning("[SCAN] audit_ssh failed (%s): %s", tr.name, tr.error)
                    continue
                for f in tr.result:
                    f.engagement_id = eng_id
                    all_findings.append(f)

        # 6. Verified HTTP security headers, CORS & CSP audit
        if profile_cfg.get("run_headers", True) and urls:
            header_urls = [u for u in urls[:8] if engine._is_in_scope(*parse_url_target(u)[:2])]
            if header_urls:
                log.info(
                    "[SCAN] Auditing HTTP security headers & CORS on %d URL(s)", len(header_urls)
                )
                try:
                    hdr_findings = await eng_mod.audit_http_security(
                        header_urls, headers=auth_headers or None
                    )
                    for hf in hdr_findings:
                        hf.engagement_id = eng_id
                    all_findings.extend(hdr_findings)
                except Exception as exc:
                    log.warning("[SCAN] audit_http_security failed: %s", exc)

        # 6b. Signature-verified web exposure checks
        if profile_cfg.get("run_exposure", True) and base_roots:
            exp_roots = [u for u in base_roots[:2] if engine._is_in_scope(*parse_url_target(u)[:2])]
            if exp_roots:
                log.info("[SCAN] Verifying exposed web artifacts on %d root(s)", len(exp_roots))
                try:
                    exp_findings = await eng_mod.audit_exposed_artifacts(
                        exp_roots, headers=auth_headers or None
                    )
                    for ef in exp_findings:
                        ef.engagement_id = eng_id
                    all_findings.extend(exp_findings)
                except Exception as exc:
                    log.warning("[SCAN] audit_exposed_artifacts failed: %s", exc)

        # 6c. WordPress passive enumeration when WordPress fingerprinted
        if (
            engine.config.profile in (ScanProfile.WEB, ScanProfile.FULL)
            and base_roots
            and wp_hosts
            and eng_mod.ToolRunner.is_available("wpscan")
        ):
            wp_candidates = [u for u in base_roots if parse_url_target(u)[0] in wp_hosts]
            wp_candidates.sort(key=lambda u: 0 if u.startswith("https://") else 1)
            wp_url = wp_candidates[0] if wp_candidates else ""
            if wp_url and engine._is_in_scope(*parse_url_target(wp_url)[:2]):
                log.info("[SCAN] Running WPScan passive audit on %s", wp_url)
                try:
                    wp_token = (
                        engine.config.wpscan_api_token
                        or engine.config.api_keys.get("wpscan")
                        or os.environ.get("NEXUS_WPSCAN_API_TOKEN")
                        or os.environ.get("WPSCAN_API_TOKEN")
                    )
                    wp_kwargs: dict[str, Any] = {
                        "stealth": effective_stealth,
                        "headers": auth_headers or None,
                    }
                    if wp_token:
                        wp_kwargs["api_token"] = wp_token
                    wp_findings = await eng_mod.wpscan_audit(wp_url, **wp_kwargs)
                    for wf in wp_findings:
                        wf.engagement_id = eng_id
                    all_findings.extend(wp_findings)
                except Exception as exc:
                    log.warning("[SCAN] wpscan_audit failed: %s", exc)

        # 6d. GraphQL introspection & API Auth-Diff verification
        scoped_urls = [u for u in urls if engine._is_in_scope(*parse_url_target(u)[:2])]
        if profile_cfg.get("run_graphql", False) and scoped_urls:
            try:
                gql_findings = await eng_mod.audit_graphql_introspection(
                    scoped_urls, headers=auth_headers or None
                )
                for gf in gql_findings:
                    gf.engagement_id = eng_id
                all_findings.extend(gql_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_graphql_introspection failed: %s", exc)

        if profile_cfg.get("run_auth_diff", False) and auth_headers and scoped_urls:
            try:
                auth_findings = await eng_mod.audit_auth_enforcement(scoped_urls, auth_headers)
                for af in auth_findings:
                    af.engagement_id = eng_id
                all_findings.extend(auth_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_auth_enforcement failed: %s", exc)

        # 6e. Declarative YAML passive detection rules & passive HTML/JS analysis
        if profile_cfg.get("run_headers", True) and scoped_urls:
            rule_engine = getattr(engine, "yaml_rules", None)
            if rule_engine is None:
                rules_dir = Path(__file__).resolve().parents[2] / "brain" / "knowledge" / "rules"
                rule_engine = YamlPassiveRuleEngine()
                rule_engine.load_directory(rules_dir)
            log.info(
                "[SCAN] Running %d YAML passive rule(s) + HTML/JS passive checks against %d URL(s)",
                rule_engine.rule_count,
                min(len(scoped_urls), 25),
            )
            prior_seen = {
                (f.host, f.port, f.tool_source, f.title, extract_endpoint(f)) for f in all_findings
            }
            try:
                all_findings.extend(
                    await _run_passive_response_checks(
                        scoped_urls,
                        rule_engine,
                        auth_headers,
                        eng_id,
                        stealth=effective_stealth,
                        already_seen=prior_seen,
                    )
                )
            except Exception as exc:
                log.warning("[SCAN] YAML passive rule engine failed: %s", exc)

        # 7. Network & datastore configuration audits
        if profile_cfg.get("run_network_audits", True) and net_endpoints:
            log.info("[SCAN] Auditing %d network/datastore service endpoint(s)", len(net_endpoints))
            net_tasks = [
                (f"net:{h}:{p}", eng_mod.audit_network_service(h, p, svc))
                for h, p, svc in net_endpoints
                if engine._is_in_scope(h, p)
            ]
            net_results = await engine.scheduler.run_parallel(net_tasks) if net_tasks else []
            for tr in net_results:
                if tr.error or tr.result is None:
                    log.warning("[SCAN] audit_network_service failed (%s): %s", tr.name, tr.error)
                    continue
                for nf in tr.result:
                    nf.engagement_id = eng_id
                    all_findings.append(nf)

        # 7b. Authorized credentialed SSH / local OS package patch audit
        ssh_key = getattr(engine.config, "ssh_key_path", None)
        ssh_user = getattr(engine.config, "ssh_user", None)
        local_audit = bool(getattr(engine.config, "local_pkg_audit", False))
        if (local_audit or (ssh_user and ssh_key)) and engine._is_in_scope(target):
            try:
                host_findings = await eng_mod.audit_host_packages(
                    target,
                    knowledge=engine.knowledge,
                    ssh_user=ssh_user,
                    ssh_key_path=ssh_key,
                    local=local_audit,
                )
                for hf in host_findings:
                    hf.engagement_id = eng_id
                all_findings.extend(host_findings)
            except Exception as exc:
                log.warning("[SCAN] audit_host_packages failed: %s", exc)

        # 8. Plugin scanners
        if engine.plugins and engine.plugins.registry.scanners:
            for pname, sfn in engine.plugins.registry.scanners.items():
                try:
                    p_findings = await sfn(target, urls=urls)
                    for raw_pf in p_findings or []:
                        pf = engine._coerce_plugin_finding(raw_pf, eng_id, target)
                        if pf is not None:
                            all_findings.append(pf)
                except Exception as exc:
                    log.warning("[SCAN] Plugin '%s' failed: %s", pname, exc)

        for f in all_findings:
            engine.db.add_finding(f)

        engine.audit.log_action(
            "scan_complete",
            target=target,
            extra={"id": eng_id, "findings": len(all_findings)},
        )
        await engine._emit_progress(
            "scan_complete",
            {"engagement_id": eng_id, "target": target, "findings": len(all_findings)},
        )
        log.info("[SCAN] Complete — %d findings", len(all_findings))
        return all_findings
