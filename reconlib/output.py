"""Run-directory management and the final terminal summary."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .tools import Port


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
) -> None:
    """Print the per-host wrap-up: open ports, services, notable gobuster hits."""
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

    if errors:
        console.print(Panel("\n".join(errors), title="Warnings / skipped",
                            border_style="yellow", title_align="left"))

    console.print(f"[dim]Artifacts: {run_dir}[/dim]")
