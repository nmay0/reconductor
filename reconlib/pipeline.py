"""Per-host pipeline orchestration.

Stage flow for a single host:
  1. quick (top-ports) + 2. full (all ports)   -> run in parallel
  3. service/version/script scan                -> on the union of open ports
  4. gobuster + whatweb + curl                  -> in parallel, per web port

Hosts are processed one at a time by the caller; the parallelism here is
*within* a single host.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from . import tools
from .output import make_run_dir, print_summary
from .tools import Port, ToolResult

# Toggle keys, all default-on except the optional gobuster modes.
DEFAULT_TOGGLES: dict[str, bool] = {
    "nmap_quick": True,
    "nmap_full": True,
    "nmap_service": True,
    "gobuster_dir": True,
    "gobuster_dns": False,
    "gobuster_vhost": False,
    "whatweb": True,
    "curl": True,
}


@dataclass
class HostResult:
    host: str
    run_dir: Path
    ports: list[Port] = field(default_factory=list)
    gobuster_hits: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _record(result: ToolResult, errors: list[str]) -> None:
    if result.skipped:
        errors.append(f"{result.name}: skipped ({result.error})")
    elif result.error:
        errors.append(f"{result.name}: {result.error}")
    elif result.returncode not in (0, None):
        errors.append(f"{result.name}: exit {result.returncode}")


def _merge_ports(*groups: list[Port]) -> dict[int, Port]:
    merged: dict[int, Port] = {}
    for group in groups:
        for p in group:
            existing = merged.get(p.number)
            if existing is None:
                merged[p.number] = p
            else:
                # Prefer richer service/version info.
                if not existing.service and p.service:
                    existing.service = p.service
                if not existing.version and p.version:
                    existing.version = p.version
    return merged


def run_host(
    console: Console,
    host: str,
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None = None,
) -> HostResult:
    """Run the full pipeline against one host and return its results."""
    timing = config.get("nmap_timing", "-T4")
    tflags = config.get("tool_flags", {})
    wordlists = config.get("wordlists", {})
    run_dir = make_run_dir(config.get("output_dir", "./recon"), host)
    result = HostResult(host=host, run_dir=run_dir)

    console.rule(f"[bold cyan]Recon — {host}[/bold cyan]")
    console.print(f"[dim]Output: {run_dir}[/dim]")

    # ---- Stages 1 & 2: quick + full in parallel ----------------------------
    quick_ports: list[Port] = []
    full_ports: list[Port] = []
    scan_jobs: list[tuple[str, Callable[[], ToolResult]]] = []
    if toggles.get("nmap_quick", True):
        scan_jobs.append(("nmap_quick", lambda: tools.nmap_quick(
            host, run_dir / "nmap_quick.txt", timing=timing,
            extra=tflags.get("nmap_quick", ""))))
    if toggles.get("nmap_full", True):
        scan_jobs.append(("nmap_full", lambda: tools.nmap_full(
            host, run_dir / "nmap_full.txt", timing=timing,
            extra=tflags.get("nmap_full", ""))))

    if scan_jobs:
        with console.status("[bold]Port scanning (quick + full in parallel)…[/bold]"):
            with ThreadPoolExecutor(max_workers=len(scan_jobs)) as ex:
                futures = {ex.submit(fn): name for name, fn in scan_jobs}
                for fut in as_completed(futures):
                    name = futures[fut]
                    res = fut.result()
                    _record(res, result.errors)
                    found = tools.parse_grepable_ports(res.stdout)
                    if name == "nmap_quick":
                        quick_ports = found
                    else:
                        full_ports = found
                    console.print(
                        f"  [green]✓[/green] {name}: "
                        f"{len(found)} open" if res.ok
                        else f"  [yellow]•[/yellow] {name}: {res.error or res.returncode}"
                    )

    merged = _merge_ports(quick_ports, full_ports)
    open_ports = sorted(merged.values(), key=lambda p: p.number)
    if open_ports:
        console.print(
            "  Open ports: "
            + ", ".join(str(p.number) for p in open_ports)
        )

    # ---- Stage 3: service/version/script scan ------------------------------
    if open_ports and toggles.get("nmap_service", True):
        with console.status("[bold]Service / version / script scan…[/bold]"):
            res = tools.nmap_service(
                host, [p.number for p in open_ports],
                run_dir / "nmap_service.txt", timing=timing,
                extra=tflags.get("nmap_service", ""))
        _record(res, result.errors)
        svc_ports = tools.parse_grepable_ports(res.stdout)
        merged = _merge_ports(open_ports, svc_ports)
        # service scan is authoritative for service/version
        for sp in svc_ports:
            if sp.number in merged:
                if sp.service:
                    merged[sp.number].service = sp.service
                if sp.version:
                    merged[sp.number].version = sp.version
        open_ports = sorted(merged.values(), key=lambda p: p.number)
        console.print(f"  [green]✓[/green] nmap_service: {len(svc_ports)} ports detailed")

    result.ports = open_ports

    # ---- Stage 4: web tools, per detected web port -------------------------
    web_ports = [p for p in open_ports if p.is_web]
    if web_ports:
        console.print(
            "  Web ports: "
            + ", ".join(f"{p.number}({'https' if p.is_https else 'http'})"
                        for p in web_ports)
        )
        _run_web_stage(console, host, web_ports, config, toggles, domain,
                       wordlists, tflags, run_dir, result)
    else:
        console.print("  [dim]No web ports detected; skipping web tools.[/dim]")

    print_summary(console, host, run_dir, result.ports, result.gobuster_hits,
                  result.errors)
    return result


def _wordlist_ok(path: str, label: str, errors: list[str]) -> bool:
    if not path or not Path(path).expanduser().exists():
        errors.append(f"gobuster_{label}: wordlist not found ({path or 'unset'})")
        return False
    return True


def _run_web_stage(
    console: Console,
    host: str,
    web_ports: list[Port],
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None,
    wordlists: dict[str, str],
    tflags: dict[str, str],
    run_dir: Path,
    result: HostResult,
) -> None:
    """Run gobuster/whatweb/curl in parallel across all web ports."""
    jobs: list[tuple[str, str, Callable[[], ToolResult]]] = []
    dns_done = False

    for p in web_ports:
        scheme = "https" if p.is_https else "http"
        insecure = p.is_https
        url = f"{scheme}://{host}:{p.number}"
        tag = f"{scheme}_{p.number}"

        if toggles.get("gobuster_dir", True):
            wl = wordlists.get("dir", "")
            if _wordlist_ok(wl, "dir", result.errors):
                jobs.append((url, "dir", lambda url=url, wl=wl, p=p, insecure=insecure:
                             tools.gobuster_dir(
                                 url, wl, run_dir / f"gobuster_dir_{p.number}.txt",
                                 extra=tflags.get("gobuster", ""), insecure=insecure)))

        if toggles.get("gobuster_vhost", False) and domain:
            wl = wordlists.get("vhost", "")
            if _wordlist_ok(wl, "vhost", result.errors):
                jobs.append((f"{url} (vhost)", "vhost",
                             lambda url=url, wl=wl, p=p, insecure=insecure:
                             tools.gobuster_vhost(
                                 url, wl, run_dir / f"gobuster_vhost_{p.number}.txt",
                                 extra=tflags.get("gobuster", ""), insecure=insecure)))

        if toggles.get("gobuster_dns", False) and domain and not dns_done:
            wl = wordlists.get("dns", "")
            if _wordlist_ok(wl, "dns", result.errors):
                dns_done = True
                jobs.append((f"dns:{domain}", "dns", lambda wl=wl:
                             tools.gobuster_dns(
                                 domain, wl, run_dir / "gobuster_dns.txt",
                                 extra=tflags.get("gobuster", ""))))

        if toggles.get("whatweb", True):
            jobs.append((url, "whatweb", lambda url=url, p=p: tools.whatweb(
                url, run_dir / f"whatweb_{p.number}.txt",
                extra=tflags.get("whatweb", ""))))

        if toggles.get("curl", True):
            jobs.append((url, "curl", lambda url=url, p=p, insecure=insecure:
                         tools.curl_headers(
                             url, run_dir / f"curl_{p.number}.txt",
                             insecure=insecure, extra=tflags.get("curl", ""))))

    if not jobs:
        return

    with console.status("[bold]Web enumeration (gobuster / whatweb / curl)…[/bold]"):
        with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
            futures = {ex.submit(fn): (url, kind) for url, kind, fn in jobs}
            for fut in as_completed(futures):
                url, kind = futures[fut]
                res = fut.result()
                _record(res, result.errors)
                if kind in ("dir", "vhost", "dns"):
                    hits = tools.parse_gobuster_hits(res.stdout)
                    key = url
                    result.gobuster_hits[key] = hits
                    console.print(
                        f"  [green]✓[/green] gobuster {kind} {url}: {len(hits)} hits"
                        if res.ok else
                        f"  [yellow]•[/yellow] gobuster {kind} {url}: "
                        f"{res.error or res.returncode}")
                else:
                    console.print(
                        f"  [green]✓[/green] {kind} {url}"
                        if res.ok else
                        f"  [yellow]•[/yellow] {kind} {url}: {res.error or res.returncode}")
