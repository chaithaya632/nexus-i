"""Rich TUI for NEXUS — live-updating terminal dashboard."""

from __future__ import annotations

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from nexus.db.models import Severity


console = Console()


# ── Severity colors ───────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def severity_text(severity: str | Severity) -> Text:
    """Return a colored Rich Text for a severity level."""
    val = severity.value if isinstance(severity, Severity) else severity
    color = SEVERITY_COLORS.get(severity, "white")
    return Text(val.upper(), style=color)


# ── Banner ────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/]
[dim]Network EXploration & Unified Security[/]
[dim]AI-Optional Autonomous Penetration Testing Framework[/]
"""


def print_banner() -> None:
    console.print(BANNER)


# ── Status Panel ──────────────────────────────────────────────────


def make_status_panel(
    target: str = "",
    phase: str = "init",
    tier: str = "minimal",
    stealth: str = "medium",
    elapsed: str = "0s",
) -> Panel:
    """Create the status info panel."""
    phase_icons = {
        "init": "⚙️", "recon": "🔍", "scan": "🔎",
        "correlate": "🧠", "exploit": "💥",
        "report": "📄", "complete": "✅",
    }
    icon = phase_icons.get(phase, "⚙️")

    content = (
        f"Target:   [cyan]{target}[/]\n"
        f"Phase:    {icon} {phase}\n"
        f"Tier:     {tier}\n"
        f"Stealth:  {stealth}\n"
        f"Elapsed:  {elapsed}"
    )
    return Panel(content, title="[bold]Status[/]", border_style="cyan")


# ── Findings Table ────────────────────────────────────────────────


def make_findings_table(
    findings: list[dict],
    title: str = "Findings",
    max_rows: int = 20,
) -> Table:
    """Create a Rich table of findings."""
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("#", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", width=6, justify="right")
    table.add_column("Title", ratio=2)
    table.add_column("Tool", width=12)

    for i, f in enumerate(findings[:max_rows], 1):
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            Text(sev.upper(), style=color),
            f.get("host", ""),
            str(f.get("port", "")),
            f.get("title", "")[:60],
            f.get("tool_source", ""),
        )

    if len(findings) > max_rows:
        table.add_row("...", "", "", "", f"({len(findings) - max_rows} more)", "")

    return table


# ── Severity Summary Bar ─────────────────────────────────────────


def make_severity_bar(counts: dict[str, int]) -> Panel:
    """Create a visual severity distribution bar."""
    total = sum(counts.values()) or 1
    parts = []
    for sev_name, color in [("critical", "red"), ("high", "bright_red"),
                             ("medium", "yellow"), ("low", "blue"), ("info", "dim")]:
        c = counts.get(sev_name, 0)
        if c > 0:
            width = max(1, int((c / total) * 40))
            parts.append(f"[{color}]{'█' * width}[/] {sev_name.upper()}: {c}")

    content = "\n".join(parts) if parts else "[dim]No findings yet[/]"
    return Panel(content, title="[bold]Severity Distribution[/]", border_style="yellow")


# ── Progress Tracker ──────────────────────────────────────────────


def create_progress() -> Progress:
    """Create a Rich progress bar for phase tracking."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


# ── Full TUI Layout ──────────────────────────────────────────────


def make_layout() -> Layout:
    """Create the full TUI layout with panels."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="status"),
        Layout(name="severity"),
    )
    return layout


def render_tui(
    target: str = "",
    phase: str = "init",
    tier: str = "minimal",
    stealth: str = "medium",
    elapsed: str = "0s",
    findings: list[dict] | None = None,
    severity_counts: dict[str, int] | None = None,
) -> Layout:
    """Render a full TUI frame."""
    layout = make_layout()

    layout["header"].update(Panel(
        Text("NEXUS — Autonomous Penetration Testing", justify="center", style="bold cyan"),
        border_style="cyan",
    ))

    layout["status"].update(make_status_panel(target, phase, tier, stealth, elapsed))
    layout["severity"].update(make_severity_bar(severity_counts or {}))
    layout["right"].update(make_findings_table(findings or []))

    layout["footer"].update(Panel(
        Text("Press Ctrl+C to abort | 'nexus engagements list' to see all", justify="center", style="dim"),
        border_style="dim",
    ))

    return layout
