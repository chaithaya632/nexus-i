"""NEXUS CLI commands — the full command set wired to NexusEngine."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nexus import __codename__, __version__
from nexus.core.config import NexusConfig, ScanProfile, StealthLevel, Tier
from nexus.core.engine import NexusEngine
from nexus.core.hardware import auto_select_tier, detect_hardware, tier_description
from nexus.db.store import EngagementStore
from nexus.scanner._http import redact_headers

console = Console()


def _build_auth_headers(headers: tuple[str, ...], cookie: str, auth_bearer: str) -> dict[str, str]:
    """Parse CLI --header, --cookie, and --auth-bearer flags into an HTTP header dict."""
    parsed: dict[str, str] = {}
    for raw in headers:
        if ":" not in raw:
            raise click.BadParameter(f"Invalid header format '{raw}'; expected 'Name: Value'.")
        name, value = raw.split(":", 1)
        clean_name = name.strip()
        if not clean_name:
            raise click.BadParameter(f"Empty header name in '{raw}'.")
        parsed[clean_name] = value.strip()
    if cookie:
        parsed["Cookie"] = cookie
    if auth_bearer:
        parsed["Authorization"] = f"Bearer {auth_bearer}"
    return parsed


def _get_engine(
    ctx: click.Context,
    *,
    config: NexusConfig | None = None,
    connect_ai: bool = True,
) -> NexusEngine:
    """Create and boot an engine, caching it on the Click context."""
    obj = ctx.ensure_object(dict)
    if "engine" not in obj:
        cfg = config or NexusConfig.load()
        engine = NexusEngine(cfg)
        engine.boot(connect_ai=connect_ai)
        obj["engine"] = engine
        ctx.call_on_close(engine.shutdown)
    return obj["engine"]


def _get_store() -> tuple[NexusConfig, EngagementStore]:
    """Open EngagementStore directly for read-only/report commands without full boot."""
    config = NexusConfig.load()
    config.ensure_dirs()
    return config, EngagementStore(config.db_path)


def _run_async(coro):
    """Run an async coroutine from sync Click commands."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


# ── engage ────────────────────────────────────────────────────────


@click.command()
@click.argument("target", required=False, default="")
@click.option("--name", "-n", default="", help="Engagement name.")
@click.option("--scope", "-s", type=click.Path(exists=True), help="Path to scope.yaml.")
@click.option("--stealth", type=click.Choice([s.value for s in StealthLevel]), default="medium")
@click.option("--tier", type=click.Choice([t.value for t in Tier]), default=None)
@click.option(
    "--profile",
    "-p",
    type=click.Choice([p.value for p in ScanProfile]),
    default="full",
    show_default=True,
    help="Scan profile (quick, web, network, api, full).",
)
@click.option("--resume", default=None, help="Resume an existing engagement by ID.")
@click.option(
    "--header",
    "-H",
    "headers",
    multiple=True,
    help="Custom HTTP header ('Name: Value'); repeatable.",
)
@click.option(
    "--cookie", default="", help="Session Cookie header value for authenticated web scans."
)
@click.option("--auth-bearer", default="", help="Bearer token for Authorization header.")
@click.option(
    "--openapi",
    type=click.Path(exists=True),
    default=None,
    help="Path to OpenAPI/Swagger JSON or YAML spec.",
)
@click.option(
    "--ignore",
    type=click.Path(exists=True),
    default=None,
    help="Path to .nexusignore baseline suppression file.",
)
@click.option(
    "--ssh-user", default="", help="Optional authorized SSH username for OS package/patch audit."
)
@click.option(
    "--ssh-key",
    type=click.Path(exists=True),
    default=None,
    help="SSH private key path for package audit.",
)
@click.option(
    "--local-audit", is_flag=True, help="Run read-only local dpkg/rpm package vulnerability audit."
)
@click.option("--no-exploit", is_flag=True, help="Skip exploitation phase.")
@click.option("--yes", "-y", is_flag=True, help="Confirm active exploitation without prompting.")
@click.option(
    "--unrestricted-scope",
    is_flag=True,
    help="LAB ONLY: disable default target scoping when no --scope file is passed.",
)
@click.option("--login-url", default="", help="Optional stateful login POST URL before scanning.")
@click.option("--login-body", default="", help="Optional JSON body string for --login-url POST.")
@click.pass_context
def engage(
    ctx,
    target,
    name,
    scope,
    stealth,
    tier,
    profile,
    resume,
    headers,
    cookie,
    auth_bearer,
    openapi,
    ignore,
    ssh_user,
    ssh_key,
    local_audit,
    no_exploit,
    yes,
    unrestricted_scope,
    login_url,
    login_body,
):
    """Start or resume a penetration test engagement against TARGET."""
    if not target and not resume:
        raise click.UsageError("Provide TARGET or pass --resume <engagement_id>.")

    auth_hdrs = _build_auth_headers(headers, cookie, auth_bearer)
    config = NexusConfig.load()

    if stealth:
        config.stealth = StealthLevel(stealth)
    if tier:
        config.tier = Tier(tier)
    if profile:
        config.profile = ScanProfile(profile)
    if auth_hdrs:
        config.auth_headers = auth_hdrs
    if openapi:
        config.openapi_spec = Path(openapi)
    if ignore:
        config.ignore_file = Path(ignore)
    if ssh_user:
        config.ssh_user = ssh_user
    if ssh_key:
        config.ssh_key_path = Path(ssh_key)
    if local_audit:
        config.local_pkg_audit = True
    if unrestricted_scope:
        config.unrestricted_scope = True
    if login_url:
        config.auth_login_url = login_url
    if login_body:
        try:
            parsed_body = json.loads(login_body)
            if isinstance(parsed_body, dict):
                config.auth_login_body = parsed_body
        except json.JSONDecodeError as exc:
            raise click.BadParameter(f"Invalid JSON for --login-body: {exc}") from exc
    if yes:
        config.auto_confirm_exploits = True
    elif not no_exploit and not config.auto_confirm_exploits and sys.stdin.isatty():
        if click.confirm("Run active exploitation during this engagement?", default=False):
            config.auto_confirm_exploits = True
        else:
            no_exploit = True

    engine = _get_engine(ctx, config=config)

    display_target = target or f"resume:{resume}"
    auth_summary = ", ".join(redact_headers(auth_hdrs).keys()) or "none"
    console.print(
        Panel(
            f"[bold green]NEXUS Engagement[/]\n"
            f"Target: [cyan]{display_target}[/]\n"
            f"Profile: {engine.config.profile.value}\n"
            f"Stealth: {engine.config.stealth.value}\n"
            f"Tier: {engine.config.tier.value}\n"
            f"Scope: {scope or 'target-scoped'}\n"
            f"Auth Headers: {auth_summary}\n"
            f"OpenAPI: {openapi or 'none'}",
            title="🎯 Resuming Engagement" if resume else "🎯 New Engagement",
        )
    )

    eng_id = _run_async(
        engine.engage(
            target,
            name=name,
            scope_file=scope,
            skip_exploit=no_exploit,
            profile=profile,
            resume_id=resume,
        )
    )
    console.print(f"\n[bold green]✓[/] Engagement complete — ID: [cyan]{eng_id}[/]")


# ── recon ─────────────────────────────────────────────────────────


@click.command()
@click.argument("target")
@click.option("--scope", "-s", type=click.Path(exists=True), help="Path to scope.yaml.")
@click.option("--engagement", "-e", default=None, help="Existing engagement ID.")
@click.pass_context
def recon(ctx, target, scope, engagement):
    """Run reconnaissance only against TARGET."""
    engine = _get_engine(ctx)

    if engagement:
        eng = engine.resume_engagement(engagement)
        if not eng:
            console.print(f"[red]Engagement {engagement} not found.[/]")
            raise SystemExit(1)
        eng_id = eng.id
    else:
        eng = engine.create_engagement(target, scope_file=scope)
        eng_id = eng.id

    console.print(f"[bold cyan]🔍 Recon[/] → {target}")
    _run_async(engine.run_recon(eng_id, target))
    console.print(f"[green]✓[/] Recon complete — ID: {eng_id}")


# ── scan ──────────────────────────────────────────────────────────


@click.command()
@click.argument("target")
@click.option("--engagement", "-e", required=True, help="Engagement ID.")
@click.option("--profile", "-p", type=click.Choice([p.value for p in ScanProfile]), default=None)
@click.option(
    "--header",
    "-H",
    "headers",
    multiple=True,
    help="Custom HTTP header ('Name: Value'); repeatable.",
)
@click.option(
    "--cookie", default="", help="Session Cookie header value for authenticated web scans."
)
@click.option("--auth-bearer", default="", help="Bearer token for Authorization header.")
@click.option(
    "--openapi",
    type=click.Path(exists=True),
    default=None,
    help="Path to OpenAPI/Swagger JSON or YAML spec.",
)
@click.option(
    "--ssh-user", default="", help="Optional authorized SSH username for OS package/patch audit."
)
@click.option(
    "--ssh-key",
    type=click.Path(exists=True),
    default=None,
    help="SSH private key path for package audit.",
)
@click.option(
    "--local-audit", is_flag=True, help="Run read-only local dpkg/rpm package vulnerability audit."
)
@click.pass_context
def scan(
    ctx,
    target,
    engagement,
    profile,
    headers,
    cookie,
    auth_bearer,
    openapi,
    ssh_user,
    ssh_key,
    local_audit,
):
    """Run vulnerability scanning against TARGET within an engagement."""
    auth_hdrs = _build_auth_headers(headers, cookie, auth_bearer)
    config = NexusConfig.load()
    if profile:
        config.profile = ScanProfile(profile)
    if auth_hdrs:
        config.auth_headers = auth_hdrs
    if openapi:
        config.openapi_spec = Path(openapi)
    if ssh_user:
        config.ssh_user = ssh_user
    if ssh_key:
        config.ssh_key_path = Path(ssh_key)
    if local_audit:
        config.local_pkg_audit = True

    engine = _get_engine(ctx, config=config)
    eng = engine.resume_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    console.print(f"[bold yellow]🔎 Scanning[/] → {target}")
    _run_async(engine.run_scan(eng.id, target))
    console.print("[green]✓[/] Scan complete.")


# ── exploit ───────────────────────────────────────────────────────


@click.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID.")
@click.option("--yes", "-y", is_flag=True, help="Confirm active exploitation without prompting.")
@click.pass_context
def exploit(ctx, engagement, yes):
    """Run exploitation phase for an engagement."""
    engine = _get_engine(ctx)
    eng = engine.resume_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    confirmed = bool(yes or engine.config.auto_confirm_exploits)
    if not confirmed:
        if not click.confirm(f"Run active exploitation against {eng.target}?", default=False):
            console.print("[yellow]Exploitation cancelled.[/]")
            return
        confirmed = True

    console.print(f"[bold red]💥 Exploiting[/] → {eng.target}")
    _run_async(engine.run_exploit(eng.id, confirm=confirmed))
    console.print("[green]✓[/] Exploitation complete.")


# ── report ────────────────────────────────────────────────────────


@click.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID.")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["pdf", "html", "md", "docx", "json", "sarif"]),
    default="md",
)
@click.option(
    "--output", "-o", type=click.Path(), default=None, help="Output file path or directory."
)
def report(engagement, fmt, output):
    """Generate a penetration test report for an engagement."""
    config, db = _get_store()

    eng = db.get_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    default_name = f"nexus_report_{engagement}.{fmt}"
    if output:
        out_p = Path(output)
        target_path = out_p if out_p.suffix else (out_p / default_name)
    else:
        target_path = config.output_dir / engagement / default_name

    target_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        data = db.export_engagement_json(engagement)
        target_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]✓[/] JSON report saved to [cyan]{target_path}[/]")
    elif fmt == "sarif":
        from nexus.reporter.generator import ReportData, build_report_data
        from nexus.reporter.sarif import render_sarif

        data = build_report_data(db, engagement)
        sarif_data = ReportData(
            meta=data.meta,
            engagement=data.engagement,
            targets=data.targets,
            findings=data.findings + data.suppressed_findings,
            chains=data.chains,
            credentials=data.credentials,
            severity_counts=data.severity_counts,
            executive_summary=data.executive_summary,
            methodology=data.methodology,
            suppressed_findings=data.suppressed_findings,
        )
        target_path.write_text(render_sarif(sarif_data), encoding="utf-8")
        console.print(f"[green]✓[/] SARIF report saved to [cyan]{target_path}[/]")
    else:
        from nexus.reporter.generator import generate_report

        generated = generate_report(
            db,
            engagement,
            target_path.parent,
            formats=[fmt],
        )
        if generated:
            gen_path = Path(generated[0])
            if gen_path.resolve() != target_path.resolve():
                if target_path.exists():
                    target_path.unlink()
                gen_path.replace(target_path)
                generated = [str(target_path)]
            for path in generated:
                console.print(f"[green]✓[/] {fmt.upper()} report saved to [cyan]{path}[/]")
        else:
            console.print("[yellow]⚠[/] No report generated — check dependencies.")


# ── engagements (list / resume / delete) ──────────────────────────


@click.group()
def engagements():
    """Manage past engagements."""
    pass


@engagements.command("list")
def engagements_list():
    """List all engagements."""
    _, db = _get_store()

    engs = db.list_engagements()
    if not engs:
        console.print("[dim]No engagements found.[/]")
        return

    table = Table(title="Engagements", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Target", style="green")
    table.add_column("Phase")
    table.add_column("Created")

    for e in engs:
        phase_color = {
            "complete": "green",
            "exploit": "red",
            "scan": "yellow",
            "recon": "cyan",
            "init": "dim",
        }.get(e.phase.value, "white")
        table.add_row(
            e.id,
            e.name,
            e.target,
            f"[{phase_color}]{e.phase.value}[/]",
            e.created_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


@engagements.command("show")
@click.argument("eng_id")
def engagements_show(eng_id):
    """Show detailed engagement summary."""
    _, db = _get_store()
    eng = db.get_engagement(eng_id)
    if not eng:
        console.print(f"[red]Engagement {eng_id} not found.[/]")
        raise SystemExit(1)

    summary = {
        "id": eng.id,
        "name": eng.name,
        "target": eng.target,
        "phase": eng.phase.value,
        "created": eng.created_at.isoformat(),
        "targets_found": len(db.get_targets(eng_id)),
        "chains_found": len(db.get_chains(eng_id)),
        "credentials_found": len(db.get_credentials(eng_id)),
        "severity_counts": db.count_findings_by_severity(eng_id),
    }

    console.print(
        Panel(
            f"ID:          {summary['id']}\n"
            f"Name:        {summary['name']}\n"
            f"Target:      {summary['target']}\n"
            f"Phase:       {summary['phase']}\n"
            f"Created:     {summary['created']}\n"
            f"Targets:     {summary['targets_found']}\n"
            f"Chains:      {summary['chains_found']}\n"
            f"Credentials: {summary['credentials_found']}\n"
            f"Findings:    {summary['severity_counts']}",
            title="📋 Engagement Summary",
        )
    )


@engagements.command("delete")
@click.argument("eng_id")
@click.confirmation_option(prompt="Delete this engagement and all its data?")
def engagements_delete(eng_id):
    """Delete an engagement and all associated data."""
    _, db = _get_store()
    db.delete_engagement(eng_id)
    console.print(f"[green]✓[/] Engagement {eng_id} deleted.")


# ── kb (knowledge base) ──────────────────────────────────────────


@click.group()
def kb():
    """Knowledge base management."""
    pass


@kb.command("stats")
@click.pass_context
def kb_stats(ctx):
    """Show brain/knowledge base statistics."""
    engine = _get_engine(ctx, connect_ai=False)
    stats = engine.brain_stats()

    table = Table(title="🧠 NEXUS Brain Statistics")
    table.add_column("Component", style="cyan")
    table.add_column("Count", justify="right", style="green")

    for key, val in stats.items():
        label = key.replace("_", " ").title()
        table.add_row(label, str(val))
    console.print(table)


@kb.command("search")
@click.argument("query")
@click.pass_context
def kb_search(ctx, query):
    """Search the knowledge base for CVEs, payloads, or remediations."""
    engine = _get_engine(ctx, connect_ai=False)

    console.print(f"[bold]Searching for:[/] {query}\n")

    # Search payloads
    if engine.payloads:
        results = engine.payloads.search(keyword=query)
        if results:
            console.print(f"[cyan]Payloads ({len(results)}):[/]")
            for p in results[:10]:
                console.print(f"  • [{p.category}] {p.name} — {p.description}")
            console.print()

    # Search remediations
    if engine.remediation:
        results = engine.remediation.search(query)
        if results:
            console.print(f"[cyan]Remediations ({len(results)}):[/]")
            for r in results[:10]:
                console.print(f"  • [{r.id}] {r.title} — {r.short_fix[:80]}")
            console.print()

    # Search knowledge graph (returns list of (service, VulnEntry) tuples)
    if engine.knowledge:
        cve_results = engine.knowledge.search(query)
        if cve_results:
            console.print(f"[cyan]CVEs ({len(cve_results)}):[/]")
            for svc_name, entry in cve_results[:10]:
                console.print(
                    f"  • {entry.cve} [{entry.severity.upper()}] ({svc_name}) — {entry.description[:80]}"
                )
            console.print()

    # Semantic / TF-IDF VectorSearch across CVEs & remediations
    if engine.vector:
        vec_results = engine.vector.search(query, top_k=10)
        if vec_results:
            console.print(f"[cyan]Vector Search Matches ({len(vec_results)}):[/]")
            for doc_id, score, meta in vec_results[:10]:
                kind = meta.get("type", "entry")
                sev = str(meta.get("severity", "")).upper()
                svc = meta.get("service", "")
                extra = f" ({svc})" if svc else ""
                console.print(f"  • {doc_id} [{kind}{extra}] {sev} (score={score:.2f})")


@kb.command("import-kev")
@click.argument("kev_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def kb_import_kev(kev_file):
    """Import an offline CISA KEV JSON file into NEXUS's CVE knowledge graph."""
    from nexus.brain.cve_sync import import_cisa_kev_file

    cfg = NexusConfig.load()
    cfg.ensure_dirs()
    count, dest = import_cisa_kev_file(kev_file, cfg.data_dir)
    console.print(f"[green]✓[/] Imported [bold]{count}[/] KEV CVEs → [cyan]{dest}[/]")


@kb.command("import-nvd")
@click.argument("nvd_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def kb_import_nvd(nvd_file):
    """Import an offline NVD v2 JSON file into NEXUS's CVE knowledge graph."""
    from nexus.brain.cve_sync import import_nvd_json_file

    cfg = NexusConfig.load()
    cfg.ensure_dirs()
    count, dest = import_nvd_json_file(nvd_file, cfg.data_dir)
    console.print(f"[green]✓[/] Imported [bold]{count}[/] NVD CVEs → [cyan]{dest}[/]")


@kb.command("sync")
@click.option("--url", default="", help="Override CISA KEV JSON feed URL.")
def kb_sync(url):
    """Fetch the CISA Known Exploited Vulnerabilities (KEV) feed for offline correlation."""
    from nexus.brain.cve_sync import CISA_KEV_URL, sync_cisa_kev

    cfg = NexusConfig.load()
    cfg.ensure_dirs()
    target_url = url.strip() or CISA_KEV_URL
    count, dest = _run_async(sync_cisa_kev(cfg.data_dir, url=target_url))
    console.print(f"[green]✓[/] Synced [bold]{count}[/] CISA KEV entries → [cyan]{dest}[/]")


# ── ai ────────────────────────────────────────────────────────────


@click.group()
def ai():
    """AI boost layer management (optional)."""
    pass


@ai.command("status")
def ai_status():
    """Check if Ollama is running and which models are available."""
    from nexus.ai.ollama_client import OllamaClient

    config = NexusConfig.load()
    with OllamaClient(config.ollama_host) as client:
        if client.is_alive():
            models = client.list_models()
            configured_ok = client.has_model(config.model_name)
            console.print(f"[green]✓ Ollama is running[/] at [cyan]{config.ollama_host}[/]")
            console.print(
                f"  Configured model: [bold]{config.model_name}[/] "
                f"({'[green]installed[/]' if configured_ok else '[yellow]not pulled[/]'})"
            )
            if models:
                console.print(f"  Available models ({len(models)}): {', '.join(models)}")
            else:
                console.print("  No models pulled yet. Run: nexus ai setup")
            return

    if not shutil.which("ollama"):
        console.print(
            f"[yellow]⚠ Ollama is not reachable at {config.ollama_host} and CLI is not installed.[/]"
        )
        console.print("  Install: curl -fsSL https://ollama.com/install.sh | sh")
    else:
        console.print(f"[yellow]⚠ Could not connect to Ollama at {config.ollama_host}.[/]")
        console.print("  Start with: ollama serve")


@ai.command("setup")
@click.option(
    "--model",
    "-m",
    default="dolphin-mistral",
    help="Model to pull (dolphin-mistral, whiterabbitneo, qwen2.5:0.5b).",
)
def ai_setup(model):
    """Pull a recommended AI model for NEXUS."""
    import subprocess

    from nexus.ai.ollama_client import OllamaClient

    config = NexusConfig.load()
    console.print(f"[bold]Pulling model:[/] {model} (host: {config.ollama_host})")
    console.print("[dim]This may take a while depending on your connection...[/]\n")

    with OllamaClient(config.ollama_host) as client:
        if client.is_alive():
            if client.pull_model(model):
                console.print(f"[green]✓[/] Model '{model}' pulled successfully.")
                return
            console.print(
                f"[yellow]⚠ HTTP pull failed for '{model}', checking local ollama CLI...[/]"
            )

    if not shutil.which("ollama"):
        console.print(
            f"[red]✗ Ollama is not reachable at {config.ollama_host} and CLI is not installed.[/]"
        )
        console.print("  Install: curl -fsSL https://ollama.com/install.sh | sh")
        raise SystemExit(1)

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model or ""):
        console.print(f"[red]✗ Invalid Ollama model name: {model!r}[/]")
        raise SystemExit(2)
    res = subprocess.run(["ollama", "pull", "--", model], check=False)
    if res.returncode != 0:
        raise SystemExit(res.returncode)


# ── dashboard ─────────────────────────────────────────────────────


@click.command()
@click.option("--host", default="127.0.0.1", help="Bind address.")
@click.option("--port", "-p", default=8477, type=int, help="Port number.")
@click.option(
    "--token",
    default="",
    envvar="NEXUS_DASHBOARD_TOKEN",
    help="Require Bearer/X-Nexus-Token auth (prefer NEXUS_DASHBOARD_TOKEN env var).",
)
@click.pass_context
def dashboard(ctx, host, port, token):
    """Launch the NEXUS web dashboard."""
    try:
        from nexus.dashboard.app import run_dashboard
    except ImportError:
        console.print("[red]✗ Dashboard requires FastAPI.[/]")
        console.print("  Install: pip install 'nexus[dashboard]'")
        raise SystemExit(1)

    src = ctx.get_parameter_source("token")
    if token and src == click.core.ParameterSource.COMMANDLINE:
        console.print(
            "[yellow]⚠ Passing --token on the CLI exposes it in process listings; "
            "prefer setting NEXUS_DASHBOARD_TOKEN instead.[/]"
        )

    engine = _get_engine(ctx)
    console.print(f"[bold cyan]⚡ NEXUS Dashboard[/] → http://{host}:{port}")
    run_dashboard(host=host, port=port, engine=engine, api_token=token or None)


# ── init ──────────────────────────────────────────────────────────


@click.command("init")
def init_cmd():
    """First-time setup: detect hardware, pick tier, configure."""
    hw = detect_hardware()
    tier = auto_select_tier(hw)

    console.print(
        Panel(
            f"[bold]System Detection[/]\n"
            f"RAM Total:  {hw.ram_total_mb} MB\n"
            f"RAM Free:   {hw.ram_free_mb} MB\n"
            f"CPU Cores:  {hw.cpu_cores}\n"
            f"GPU:        {hw.gpu_name}\n"
            f"\n[bold]Selected Tier:[/] [cyan]{tier.value}[/]\n"
            f"  {tier_description(tier)}",
            title="🚀 NEXUS Init",
        )
    )

    config = NexusConfig(tier=tier)
    saved = config.save()
    console.print(f"\n[green]✓[/] Configuration saved to [cyan]{saved}[/]")
    console.print("[bold]Run:[/] nexus engage <target> --scope scope.yaml")


# ── audit ─────────────────────────────────────────────────────────


@click.group("audit")
def audit_cmd():
    """Audit trail management."""
    pass


@audit_cmd.command("verify")
def audit_verify():
    """Verify the integrity of the audit log chain."""
    from nexus.core.audit import AuditLogger

    config = NexusConfig.load()
    audit = AuditLogger(config.data_dir / "audit.jsonl")
    valid, count = audit.verify_chain()

    if valid:
        console.print(f"[green]✓ Audit chain is VALID[/] — {count} entries verified.")
    else:
        console.print(
            f"[red]✗ Audit chain is BROKEN[/] — integrity compromised at entry {count + 1}."
        )
        raise SystemExit(1)


# ── version ───────────────────────────────────────────────────────


@click.command()
def version():
    """Show NEXUS version and system info."""
    hw = detect_hardware()
    tier = auto_select_tier(hw)
    console.print(f"[bold cyan]{__codename__}[/] v{__version__}")
    console.print(
        f"  Tier: {tier.value} | RAM: {hw.ram_total_mb}MB | CPUs: {hw.cpu_cores} | GPU: {hw.gpu_name}"
    )


@click.command()
@click.argument("old_id")
@click.argument("new_id")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option(
    "--fail-on-new",
    default="",
    help="Exit code 2 if new findings match comma-separated severities (e.g. critical,high or any).",
)
def diff(old_id, new_id, fmt, fail_on_new):
    """Compare two engagements and report new, resolved, and persistent findings."""
    from nexus.correlator.diff import diff_engagements

    _, db = _get_store()
    try:
        result = diff_engagements(db, old_id, new_id)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise SystemExit(1)

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        c = result["counts"]
        console.print(
            Panel(
                f"Baseline:   [cyan]{old_id}[/] ({result['old_target']})\n"
                f"Current:    [cyan]{new_id}[/] ({result['new_target']})\n"
                f"New:        [red]{c['new']}[/]\n"
                f"Resolved:   [green]{c['resolved']}[/]\n"
                f"Persistent: [yellow]{c['persistent']}[/]\n"
                f"Suppressed: [dim]{c['suppressed']}[/]",
                title="🔀 Engagement Diff",
            )
        )
        if result["new"]:
            tbl = Table(title="New Findings (Regressions)", show_lines=True)
            tbl.add_column("Severity")
            tbl.add_column("Host:Port")
            tbl.add_column("Title")
            for f in result["new"]:
                loc = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
                tbl.add_row(str(f["severity"]).upper(), loc, f["title"])
            console.print(tbl)

    if fail_on_new:
        thresholds = {s.strip().lower() for s in fail_on_new.split(",") if s.strip()}
        if "any" in thresholds and result["new"]:
            raise SystemExit(2)
        for f in result["new"]:
            if str(f.get("severity", "")).lower() in thresholds:
                raise SystemExit(2)


# ── proxy ─────────────────────────────────────────────────────────


@click.command("proxy")
@click.option("--host", default="127.0.0.1", show_default=True, help="Proxy listen host.")
@click.option("--port", "-p", default=8080, show_default=True, type=int, help="Proxy listen port.")
@click.option(
    "--scope", "-s", type=click.Path(exists=True), default=None, help="Path to scope.yaml."
)
@click.option(
    "--engagement", "-e", default="", help="Optional engagement ID to attach history & findings."
)
def proxy_cmd(host, port, scope, engagement):
    """Start scoped MITM HTTP proxy with live passive DAST + Dashboard history."""
    from nexus.core.scope import ScopeEnforcer
    from nexus.scanner.proxy import NexusProxyRecorder, build_mitmproxy_master

    cfg, store = _get_store()
    enforcer = ScopeEnforcer.from_file(scope) if scope else None
    if engagement and enforcer is None:
        eng = store.get_engagement(engagement)
        if eng and eng.scope_file:
            enforcer = ScopeEnforcer.from_file(eng.scope_file)
        elif eng and eng.target:
            enforcer = ScopeEnforcer.for_target(eng.target)

    rules_dir = cfg.knowledge_dir / "rules" if cfg.knowledge_dir else None
    recorder = NexusProxyRecorder(
        engagement_id=engagement,
        scope=enforcer,
        store=store,
        rules_dir=rules_dir,
    )
    try:
        master, _ = build_mitmproxy_master(listen_host=host, listen_port=port, recorder=recorder)
    except ImportError as exc:
        console.print(f"[red]✗ {exc}[/]")
        raise SystemExit(1)

    console.print(f"[bold cyan]🕵️  NEXUS MITM Proxy[/] listening on http://{host}:{port}")
    console.print("[dim]Press Ctrl+C to stop capturing.[/]")
    _run_async(master.run())


# ── Collect all commands ──────────────────────────────────────────

ALL_COMMANDS = [
    engage,
    recon,
    scan,
    exploit,
    report,
    diff,
    proxy_cmd,
    engagements,
    kb,
    ai,
    dashboard,
    init_cmd,
    audit_cmd,
    version,
]
