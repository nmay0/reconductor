"""Run-directory management and the final terminal summary."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .tools import Port, ToolResult


def print_tool_block(console: Console, title: str, result: ToolResult) -> None:
    """Print one tool's raw output as a self-contained block when it finishes.

    Output is rendered as plain Text (no rich markup/highlighting) so brackets
    and other literal content in tool output are shown verbatim.
    """
    console.rule(f"[bold cyan]{title}[/bold cyan]", align="left")
    if result.command:
        console.print(f"[dim]$ {result.cmdline}[/dim]", highlight=False)
    if result.skipped:
        console.print(f"[yellow]skipped — {result.error}[/yellow]")
        return

    body = (result.stdout or "").strip("\n")
    if body:
        console.print(Text(body))
    else:
        console.print("[dim](no output)[/dim]")

    stderr = (result.stderr or "").strip()
    if stderr and not result.ok:
        console.print(Text(stderr, style="red"))
    if result.error:
        console.print(f"[yellow]! {result.error}[/yellow]")


def make_run_dir(output_dir: str, host: str) -> Path:
    """Create and return recon/<host>/<timestamp>/ — unique per run, never overwrites."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(output_dir).expanduser() / host / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def print_summary(
    console: Console,
    host: str,
    run_dir: Path,
    ports: list[Port],
    gobuster_hits: dict[str, list[str]],
    errors: list[str],
    ffuf_hits: dict[str, list[str]] | None = None,
    exploits: list[dict] | None = None,
    findings: list[dict] | None = None,
) -> None:
    """Print the per-host wrap-up: open ports, services, notable hits, exploits."""
    console.print()
    console.rule(f"[bold]Summary — {host}[/bold]")

    if ports:
        table = Table(title="Open ports / services", title_style="bold cyan",
                      header_style="bold")
        table.add_column("Port", justify="right", style="green")
        table.add_column("Proto")
        table.add_column("Service")
        table.add_column("Version", overflow="fold")
        for p in ports:
            table.add_row(str(p.number), p.proto, p.service or "-", p.version or "-")
        console.print(table)
    else:
        console.print("[yellow]No open ports found.[/yellow]")

    notable = {url: hits for url, hits in gobuster_hits.items() if hits}
    if notable:
        for url, hits in notable.items():
            table = Table(title=f"gobuster hits — {url}", title_style="bold magenta",
                          header_style="bold", show_header=False)
            table.add_column("hit", overflow="fold")
            for hit in hits[:40]:
                table.add_row(hit)
            if len(hits) > 40:
                table.add_row(f"... and {len(hits) - 40} more (see artifact)")
            console.print(table)
    elif gobuster_hits:
        console.print("[dim]No notable gobuster hits.[/dim]")

    ffuf_hits = ffuf_hits or {}
    for url, hits in ((u, h) for u, h in ffuf_hits.items() if h):
        table = Table(title=f"ffuf hits — {url}", title_style="bold blue",
                      header_style="bold", show_header=False)
        table.add_column("hit", overflow="fold")
        for hit in hits[:40]:
            table.add_row(hit)
        if len(hits) > 40:
            table.add_row(f"... and {len(hits) - 40} more (see artifact)")
        console.print(table)

    findings = findings or []
    if findings:
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}
        table = Table(title="nuclei — findings (most urgent first)",
                      title_style="bold red", header_style="bold")
        table.add_column("Severity")
        table.add_column("Finding", overflow="fold")
        table.add_column("Location", overflow="fold", style="dim")
        for f in findings[:40]:
            sev = f.get("severity", "unknown")
            style = sev_style.get(sev, "white")
            table.add_row(f"[{style}]{sev}[/{style}]",
                          f.get("name") or f.get("template_id", ""),
                          f.get("matched_at") or f.get("url", ""))
        if len(findings) > 40:
            table.add_row("", f"... and {len(findings) - 40} more (see artifact)", "")
        console.print(table)

    exploits = exploits or []
    if exploits:
        table = Table(title="searchsploit — possible exploits",
                      title_style="bold red", header_style="bold")
        table.add_column("Title", overflow="fold")
        table.add_column("Path", overflow="fold", style="dim")
        for ex in exploits[:40]:
            table.add_row(ex.get("title", ""), ex.get("path", ""))
        if len(exploits) > 40:
            table.add_row(f"... and {len(exploits) - 40} more (see artifact)", "")
        console.print(table)

    if errors:
        console.print(Panel("\n".join(errors), title="Warnings / skipped",
                            border_style="yellow", title_align="left"))

    console.print(f"[dim]Artifacts: {run_dir}[/dim]")
