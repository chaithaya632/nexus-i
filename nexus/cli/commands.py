"""NEXUS CLI commands — the full command set wired to NexusEngine."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nexus import __version__, __codename__
from nexus.core.config import NexusConfig, Tier, StealthLevel
from nexus.core.engine import NexusEngine
from nexus.core.hardware import detect_hardware, auto_select_tier, tier_description
from nexus.db.models import Severity

console = Console()


def _get_engine(ctx: click.Context) -> NexusEngine:
    """Create and boot an engine, caching it on the Click context."""
    if "engine" not in ctx.ensure_object(dict):
        config = NexusConfig.load()
        engine = NexusEngine(config)
        engine.boot()
        ctx.obj["engine"] = engine
        ctx.call_on_close(engine.shutdown)
    return ctx.obj["engine"]


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
@click.argument("target")
@click.option("--name", "-n", default="", help="Engagement name.")
@click.option("--scope", "-s", type=click.Path(exists=True), help="Path to scope.yaml.")
@click.option("--stealth", type=click.Choice([s.value for s in StealthLevel]), default="medium")
@click.option("--tier", type=click.Choice([t.value for t in Tier]), default=None)
@click.option("--no-exploit", is_flag=True, help="Skip exploitation phase.")
@click.pass_context
def engage(ctx, target, name, scope, stealth, tier, no_exploit):
    """Start a full penetration test engagement against TARGET."""
    engine = _get_engine(ctx)

    if stealth:
        engine.config.stealth = StealthLevel(stealth)
    if tier:
        engine.config.tier = Tier(tier)

    console.print(Panel(
        f"[bold green]NEXUS Engagement[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Stealth: {engine.config.stealth.value}\n"
        f"Tier: {engine.config.tier.value}\n"
        f"Scope: {scope or 'unrestricted'}",
        title="🎯 New Engagement",
    ))

    eng_id = _run_async(engine.engage(target, name=name, scope_file=scope, skip_exploit=no_exploit))
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
@click.pass_context
def scan(ctx, target, engagement):
    """Run vulnerability scanning against TARGET within an engagement."""
    engine = _get_engine(ctx)
    eng = engine.resume_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    console.print(f"[bold yellow]🔎 Scanning[/] → {target}")
    _run_async(engine.run_scan(eng.id, target))
    console.print(f"[green]✓[/] Scan complete.")


# ── exploit ───────────────────────────────────────────────────────


@click.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID.")
@click.pass_context
def exploit(ctx, engagement):
    """Run exploitation phase for an engagement."""
    engine = _get_engine(ctx)
    eng = engine.resume_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    console.print(f"[bold red]💥 Exploiting[/] → {eng.target}")
    _run_async(engine.run_exploit(eng.id))
    console.print(f"[green]✓[/] Exploitation complete.")


# ── report ────────────────────────────────────────────────────────


@click.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID.")
@click.option("--format", "-f", "fmt", type=click.Choice(["pdf", "html", "md", "docx", "json"]), default="md")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.pass_context
def report(ctx, engagement, fmt, output):
    """Generate a penetration test report for an engagement."""
    engine = _get_engine(ctx)
    assert engine.db is not None

    eng = engine.db.get_engagement(engagement)
    if not eng:
        console.print(f"[red]Engagement {engagement} not found.[/]")
        raise SystemExit(1)

    if fmt == "json":
        data = engine.db.export_engagement_json(engagement)
        out_path = output or str(engine.config.output_dir / f"{engagement}_report.json")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]✓[/] JSON report saved to [cyan]{out_path}[/]")
    else:
        from nexus.reporter.generator import generate_report
        out_dir = Path(output) if output else engine.config.output_dir / engagement
        generated = generate_report(
            engine.db, engagement, out_dir,
            formats=[fmt],
        )
        if generated:
            for path in generated:
                console.print(f"[green]✓[/] {fmt.upper()} report saved to [cyan]{path}[/]")
        else:
            console.print(f"[yellow]⚠[/] No report generated — check dependencies.")


# ── engagements (list / resume / delete) ──────────────────────────


@click.group()
def engagements():
    """Manage past engagements."""
    pass


@engagements.command("list")
@click.pass_context
def engagements_list(ctx):
    """List all engagements."""
    engine = _get_engine(ctx)
    assert engine.db is not None

    engs = engine.db.list_engagements()
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
            "complete": "green", "exploit": "red", "scan": "yellow",
            "recon": "cyan", "init": "dim",
        }.get(e.phase.value, "white")
        table.add_row(
            e.id, e.name, e.target,
            f"[{phase_color}]{e.phase.value}[/]",
            e.created_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


@engagements.command("show")
@click.argument("eng_id")
@click.pass_context
def engagements_show(ctx, eng_id):
    """Show detailed engagement summary."""
    engine = _get_engine(ctx)
    summary = engine.engagement_summary(eng_id)
    if not summary:
        console.print(f"[red]Engagement {eng_id} not found.[/]")
        raise SystemExit(1)

    console.print(Panel(
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
    ))


@engagements.command("delete")
@click.argument("eng_id")
@click.confirmation_option(prompt="Delete this engagement and all its data?")
@click.pass_context
def engagements_delete(ctx, eng_id):
    """Delete an engagement and all associated data."""
    engine = _get_engine(ctx)
    assert engine.db is not None
    engine.db.delete_engagement(eng_id)
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
    engine = _get_engine(ctx)
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
    engine = _get_engine(ctx)

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


# ── ai ────────────────────────────────────────────────────────────


@click.group()
def ai():
    """AI boost layer management (optional)."""
    pass


@ai.command("status")
@click.pass_context
def ai_status(ctx):
    """Check if Ollama is running and which models are available."""
    import subprocess
    import shutil

    if not shutil.which("ollama"):
        console.print("[yellow]⚠ Ollama is not installed.[/]")
        console.print("  Install: curl -fsSL https://ollama.com/install.sh | sh")
        return

    try:
        result = subprocess.run(
            ["ollama", "list"], capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            console.print("[green]✓ Ollama is running.[/]\n")
            console.print(result.stdout)
        else:
            console.print("[yellow]⚠ Ollama is installed but may not be running.[/]")
            console.print(f"  Error: {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        console.print("[yellow]⚠ Could not connect to Ollama.[/]")
        console.print("  Start with: ollama serve")


@ai.command("setup")
@click.option("--model", "-m", default="dolphin-mistral",
              help="Model to pull (dolphin-mistral, whiterabbitneo, qwen2.5:0.5b).")
@click.pass_context
def ai_setup(ctx, model):
    """Pull a recommended AI model for NEXUS."""
    import subprocess
    import shutil

    if not shutil.which("ollama"):
        console.print("[red]✗ Ollama is not installed.[/]")
        console.print("  Install: curl -fsSL https://ollama.com/install.sh | sh")
        raise SystemExit(1)

    console.print(f"[bold]Pulling model:[/] {model}")
    console.print("[dim]This may take a while depending on your connection...[/]\n")
    subprocess.run(["ollama", "pull", model], check=False)


# ── dashboard ─────────────────────────────────────────────────────


@click.command()
@click.option("--host", default="127.0.0.1", help="Bind address.")
@click.option("--port", "-p", default=8477, type=int, help="Port number.")
@click.pass_context
def dashboard(ctx, host, port):
    """Launch the NEXUS web dashboard."""
    try:
        from nexus.dashboard.app import run_dashboard
    except ImportError:
        console.print("[red]✗ Dashboard requires FastAPI.[/]")
        console.print("  Install: pip install 'nexus[dashboard]'")
        raise SystemExit(1)

    engine = _get_engine(ctx)
    console.print(f"[bold cyan]⚡ NEXUS Dashboard[/] → http://{host}:{port}")
    run_dashboard(host=host, port=port, engine=engine)


# ── init ──────────────────────────────────────────────────────────


@click.command("init")
def init_cmd():
    """First-time setup: detect hardware, pick tier, configure."""
    hw = detect_hardware()
    tier = auto_select_tier(hw)

    console.print(Panel(
        f"[bold]System Detection[/]\n"
        f"RAM Total:  {hw.ram_total_mb} MB\n"
        f"RAM Free:   {hw.ram_free_mb} MB\n"
        f"CPU Cores:  {hw.cpu_cores}\n"
        f"GPU:        {hw.gpu_name}\n"
        f"\n[bold]Selected Tier:[/] [cyan]{tier.value}[/]\n"
        f"  {tier_description(tier)}",
        title="🚀 NEXUS Init",
    ))

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
@click.pass_context
def audit_verify(ctx):
    """Verify the integrity of the audit log chain."""
    from nexus.core.audit import AuditLogger
    config = NexusConfig.load()
    audit = AuditLogger(config.data_dir / "audit.jsonl")
    valid, count = audit.verify_chain()

    if valid:
        console.print(f"[green]✓ Audit chain is VALID[/] — {count} entries verified.")
    else:
        console.print(f"[red]✗ Audit chain is BROKEN[/] — integrity compromised at entry {count + 1}.")
        raise SystemExit(1)


# ── version ───────────────────────────────────────────────────────


@click.command()
def version():
    """Show NEXUS version and system info."""
    hw = detect_hardware()
    tier = auto_select_tier(hw)
    console.print(f"[bold cyan]{__codename__}[/] v{__version__}")
    console.print(f"  Tier: {tier.value} | RAM: {hw.ram_total_mb}MB | CPUs: {hw.cpu_cores} | GPU: {hw.gpu_name}")


# ── Collect all commands ──────────────────────────────────────────

ALL_COMMANDS = [
    engage,
    recon,
    scan,
    exploit,
    report,
    engagements,
    kb,
    ai,
    dashboard,
    init_cmd,
    audit_cmd,
    version,
]
