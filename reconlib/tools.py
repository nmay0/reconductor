"""Subprocess wrappers around the external recon tools.

Every wrapper:
  * builds an argv list,
  * runs it (capturing stdout/stderr),
  * writes a human-readable artifact into the run directory,
  * returns a ToolResult describing what happened.

Parsing helpers turn nmap grepable output into structured port/service
data and pull notable hits out of gobuster output.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import flag_list

# Generous default; full port scans can take a while.
DEFAULT_TIMEOUT = 1800


@dataclass
class Port:
    """A single open port discovered by nmap."""

    number: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""

    @property
    def is_web(self) -> bool:
        name = self.service.lower()
        return (
            "http" in name
            or "https" in name
            or self.number in (80, 443, 8080, 8443)
        )

    @property
    def is_https(self) -> bool:
        name = self.service.lower()
        return "https" in name or "ssl" in name or self.number in (443, 8443)


@dataclass
class ToolResult:
    """Outcome of running one external tool."""

    name: str
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifact: Path | None = None
    skipped: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.skipped and not self.error and self.returncode == 0

    @property
    def cmdline(self) -> str:
        return " ".join(self.command)


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(
    name: str,
    command: list[str],
    artifact: Path,
    *,
    write_stdout: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Run *command*, writing an artifact, and return a ToolResult.

    When *write_stdout* is True the captured stdout is written to *artifact*
    (used for tools whose primary output is stdout). When False, the tool is
    assumed to have written *artifact* itself (e.g. nmap -oN) and we only
    record a header if it didn't.
    """
    binary = command[0]
    if not tool_available(binary):
        return ToolResult(name=name, command=command, skipped=True,
                          error=f"{binary} not installed")
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(name=name, command=command, error="timed out",
                          artifact=artifact)
    except OSError as exc:  # pragma: no cover - defensive
        return ToolResult(name=name, command=command, error=str(exc))

    result = ToolResult(
        name=name,
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        artifact=artifact,
    )

    artifact.parent.mkdir(parents=True, exist_ok=True)
    if write_stdout:
        header = f"$ {result.cmdline}\n\n"
        body = proc.stdout
        if proc.stderr.strip():
            body += f"\n--- stderr ---\n{proc.stderr}"
        artifact.write_text(header + body, encoding="utf-8")
    elif not artifact.exists():
        # Tool was meant to write the file but produced nothing useful.
        artifact.write_text(
            f"$ {result.cmdline}\n\n{proc.stdout}\n{proc.stderr}",
            encoding="utf-8",
        )
    return result


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #

def _nmap(
    name: str,
    mode_flags: list[str],
    target: str,
    artifact: Path,
    *,
    timing: str,
    extra: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Run nmap writing normal output to *artifact* and grepable to stdout."""
    command = [
        "nmap",
        *flag_list(timing),
        *mode_flags,
        *flag_list(extra),
        "-oN", str(artifact),
        "-oG", "-",
        target,
    ]
    return _run(name, command, artifact, write_stdout=False, timeout=timeout)


def nmap_sweep(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """Host-discovery ping sweep across a CIDR / range."""
    return _nmap("nmap_sweep", ["-sn"], target, artifact, timing=timing, extra=extra)


def nmap_quick(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """Fast top-ports scan (-F = top 100)."""
    return _nmap("nmap_quick", ["-F"], target, artifact, timing=timing, extra=extra)


def nmap_full(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """All 65535 TCP ports."""
    return _nmap("nmap_full", ["-p-"], target, artifact, timing=timing, extra=extra)


def nmap_service(
    target: str, ports: list[int], artifact: Path, *, timing: str, extra: str
) -> ToolResult:
    """Service/version + default-script scan limited to discovered ports."""
    port_arg = ",".join(str(p) for p in sorted(ports))
    return _nmap(
        "nmap_service",
        ["-sV", "-sC", "-p", port_arg],
        target,
        artifact,
        timing=timing,
        extra=extra,
    )


def parse_grepable_hosts(stdout: str) -> list[str]:
    """Return IPs reported 'Up' in nmap grepable (-sn) output."""
    hosts: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            # Format: "Host: 10.0.0.5 ()\tStatus: Up"
            parts = line.split()
            if len(parts) >= 2:
                hosts.append(parts[1])
    return hosts


def parse_grepable_ports(stdout: str) -> list[Port]:
    """Parse open ports from nmap grepable (-oG) output."""
    ports: list[Port] = []
    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        _, _, ports_section = line.partition("Ports:")
        # Strip a trailing "\tIgnored State: ..." if present.
        ports_section = ports_section.split("\tIgnored")[0]
        for entry in ports_section.split(","):
            fields = entry.strip().split("/")
            # port/state/proto/owner/service/rpc/version
            if len(fields) < 5 or fields[1] != "open":
                continue
            try:
                number = int(fields[0])
            except ValueError:
                continue
            version = fields[6] if len(fields) > 6 else ""
            ports.append(
                Port(
                    number=number,
                    proto=fields[2] or "tcp",
                    service=fields[4],
                    version=version.strip(),
                )
            )
    # De-dupe by port number, preferring entries that carry a service name.
    best: dict[int, Port] = {}
    for p in ports:
        existing = best.get(p.number)
        if existing is None or (not existing.service and p.service):
            best[p.number] = p
    return [best[n] for n in sorted(best)]


# --------------------------------------------------------------------------- #
# Web tools
# --------------------------------------------------------------------------- #

GOBUSTER_INTERESTING = {200, 204, 301, 302, 307, 308, 401, 403, 405}


def gobuster_dir(url: str, wordlist: str, artifact: Path, *, extra: str,
                 insecure: bool) -> ToolResult:
    command = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-color"]
    if insecure:
        command.append("-k")
    command += flag_list(extra)
    return _run("gobuster_dir", command, artifact)


def gobuster_dns(domain: str, wordlist: str, artifact: Path, *, extra: str) -> ToolResult:
    command = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-q", "--no-color"]
    command += flag_list(extra)
    return _run("gobuster_dns", command, artifact)


def gobuster_vhost(url: str, wordlist: str, artifact: Path, *, extra: str,
                   insecure: bool) -> ToolResult:
    command = ["gobuster", "vhost", "-u", url, "-w", wordlist, "-q", "--no-color",
               "--append-domain"]
    if insecure:
        command.append("-k")
    command += flag_list(extra)
    return _run("gobuster_vhost", command, artifact)


def whatweb(url: str, artifact: Path, *, extra: str) -> ToolResult:
    command = ["whatweb", "--color=never", *flag_list(extra), url]
    return _run("whatweb", command, artifact)


def curl_headers(url: str, artifact: Path, *, insecure: bool, extra: str) -> ToolResult:
    command = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", "20"]
    if insecure:
        command.append("-k")
    command += flag_list(extra)
    command.append(url)
    return _run("curl", command, artifact)


def parse_gobuster_hits(stdout: str) -> list[str]:
    """Return notable path lines from gobuster dir/vhost output."""
    hits: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("===", "Progress:", "[")):
            continue
        if "Status:" in line:
            status_token = line.split("Status:")[1].strip().split(")")[0].strip()
            try:
                status = int(status_token)
            except ValueError:
                hits.append(line)
                continue
            if status in GOBUSTER_INTERESTING:
                hits.append(line)
        elif line.startswith("Found:"):  # dns mode
            hits.append(line)
    return hits
