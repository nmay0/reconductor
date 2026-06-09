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

import json
import re
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
    # Secondary machine-parseable output captured to a side file (nmap grepable
    # or nuclei JSONL), kept separate from the human-readable stdout shown to the
    # user. Structured parsing reads from here, never from stdout.
    grepable: str = ""

    @property
    def ok(self) -> bool:
        return not self.skipped and not self.error and self.returncode == 0

    @property
    def cmdline(self) -> str:
        return " ".join(self.command)


@dataclass
class ToolRun:
    """One executed tool within a host run, plus the context needed to fold it
    into consolidated reports (which web target/port/vhost it belonged to)."""

    name: str
    title: str
    result: "ToolResult"
    kind: str = ""  # scan | dir | ffuf | vhost | dns | whatweb | curl | searchsploit | nuclei
    port: int | None = None
    vhost: str | None = None


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
    xml: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Run nmap with the human report on stdout (shown + saved) and grepable
    output to a side file (parsed into ports/hosts). When *xml* is given, an
    XML copy is emitted too (consumed by searchsploit --nmap)."""
    grep_path = artifact.with_suffix(".gnmap")
    command = [
        "nmap",
        *flag_list(timing),
        *mode_flags,
        *flag_list(extra),
        "-oN", "-",
        "-oG", str(grep_path),
    ]
    if xml is not None:
        command += ["-oX", str(xml)]
    command.append(target)
    result = _run(name, command, artifact, write_stdout=True, timeout=timeout)
    try:
        result.grepable = grep_path.read_text(encoding="utf-8")
    except OSError:
        result.grepable = result.stdout  # fall back to parsing the report
    return result


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
    target: str, ports: list[int], artifact: Path, *, timing: str, extra: str,
    xml_path: Path | None = None,
) -> ToolResult:
    """Service/version + default-script scan limited to discovered ports.

    *xml_path*, when given, captures an XML copy of the scan that searchsploit
    can consume via ``searchsploit --nmap``.
    """
    port_arg = ",".join(str(p) for p in sorted(ports))
    return _nmap(
        "nmap_service",
        ["-sV", "-sC", "-p", port_arg],
        target,
        artifact,
        timing=timing,
        extra=extra,
        xml=xml_path,
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
                 insecure: bool, host_header: str | None = None) -> ToolResult:
    command = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-color"]
    if insecure:
        command.append("-k")
    if host_header:
        # Target the IP but route to the right virtual host via the Host header,
        # so no /etc/hosts entry is required.
        command += ["-H", f"Host: {host_header}"]
    command += flag_list(extra)
    return _run("gobuster_dir", command, artifact)


def ffuf_dir(url: str, wordlist: str, artifact: Path, *, extra: str,
             host_header: str | None = None) -> ToolResult:
    """Fast content discovery: fuzz the FUZZ keyword at the URL path.

    ffuf ignores TLS cert errors by default, so no insecure flag is needed for
    https targets. Like gobuster_dir, a Host header can target a virtual host on
    the same IP without an /etc/hosts entry.
    """
    fuzz_url = url.rstrip("/") + "/FUZZ"
    command = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-noninteractive"]
    if host_header:
        command += ["-H", f"Host: {host_header}"]
    command += flag_list(extra)
    return _run("ffuf", command, artifact)


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


def whatweb(url: str, artifact: Path, *, extra: str,
            host_header: str | None = None) -> ToolResult:
    command = ["whatweb", "--color=never"]
    if host_header:
        command += ["--header", f"Host: {host_header}"]
    command += [*flag_list(extra), url]
    return _run("whatweb", command, artifact)


def curl_headers(url: str, artifact: Path, *, insecure: bool, extra: str,
                 resolve: tuple[str, int, str] | None = None) -> ToolResult:
    command = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", "20"]
    if insecure:
        command.append("-k")
    if resolve:
        # --resolve host:port:ip pins DNS *and* TLS SNI to the target IP while
        # the URL keeps the hostname — the rootless equivalent of /etc/hosts.
        host, port, ip = resolve
        command += ["--resolve", f"{host}:{port}:{ip}"]
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


# ffuf result line: "admin   [Status: 301, Size: 312, Words: 20, Lines: 10, ...]"
_FFUF_LINE_RE = re.compile(
    r"^\s*(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),"
    r"\s*Size:\s*(?P<size>\d+)"
)


def parse_ffuf_hits(stdout: str) -> list[str]:
    """Return notable result lines from ffuf output (status-filtered)."""
    hits: list[str] = []
    for line in stdout.splitlines():
        m = _FFUF_LINE_RE.match(line)
        if m and int(m.group("status")) in GOBUSTER_INTERESTING:
            hits.append(line.strip())
    return hits


def parse_ffuf_structured(stdout: str) -> list[dict]:
    """Parse ffuf output into {path, status, size} records."""
    hits: list[dict] = []
    for line in stdout.splitlines():
        m = _FFUF_LINE_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        if status not in GOBUSTER_INTERESTING:
            continue
        hits.append({
            "path": m.group("path"),
            "status": status,
            "size": int(m.group("size")),
        })
    return hits


# --------------------------------------------------------------------------- #
# Exploit search
# --------------------------------------------------------------------------- #

def searchsploit_nmap(xml_path: Path, artifact: Path, *, extra: str) -> ToolResult:
    """Search Exploit-DB for the services in an nmap service-scan XML file.

    `searchsploit --nmap` parses the XML itself and searches each product /
    version it finds — far more reliable than building search terms by hand.
    Output is uncoloured automatically when not attached to a tty.
    """
    command = ["searchsploit", "--nmap", str(xml_path)]
    command += flag_list(extra)
    return _run("searchsploit", command, artifact)


def parse_searchsploit(stdout: str) -> list[dict]:
    """Parse searchsploit's two-column table into {title, path} records.

    Tolerant of the box-drawing layout: data rows are 'Title | path'; header,
    separator and 'No Results' lines are skipped.
    """
    results: list[dict] = []
    for raw in stdout.splitlines():
        if "|" not in raw:
            continue
        stripped = raw.strip()
        if not stripped or set(stripped) <= set("-=| "):
            continue  # separator / rule line
        title, _, path = raw.rpartition("|")
        title, path = title.strip(), path.strip()
        if not title or not path:
            continue
        if title.lower().startswith(("exploit title", "shellcode title",
                                     "paper title")):
            continue  # column header
        results.append({"title": title, "path": path})
    return results


# --------------------------------------------------------------------------- #
# Recon scanning — nuclei (template-based, detection + version CVEs only)
# --------------------------------------------------------------------------- #

# Severity ranking for sorting findings most-urgent first (unknown sorts last).
NUCLEI_SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
}


def nuclei_severity_rank(severity: str) -> int:
    """Sort key for a nuclei severity (lower = more urgent)."""
    return NUCLEI_SEVERITY_ORDER.get((severity or "unknown").lower(), 5)


def nuclei(url: str, artifact: Path, *, extra: str,
           host_header: str | None = None) -> ToolResult:
    """Run nuclei against a single URL and capture its findings.

    Human-readable findings go to stdout (shown live + saved to *artifact*); a
    JSONL copy is exported to a side file and read into ToolResult.grepable for
    structured parsing — the same human/structured split as the nmap wrappers.

    Update checks are disabled so runs stay offline and deterministic: templates
    must already be installed (run ``nuclei -update-templates`` out of band).
    nuclei's HTTP client ignores TLS errors by default, so https needs no extra
    flag. A Host header targets a virtual host on the same IP — the rootless
    equivalent of an /etc/hosts entry. The recon-only template scope (detection
    + version CVEs, nothing intrusive) lives in config tool_flags["nuclei"].
    """
    jsonl_path = artifact.with_suffix(".jsonl")
    command = [
        "nuclei", "-target", url,
        "-jsonl-export", str(jsonl_path),
        "-disable-update-check", "-no-color",
    ]
    if host_header:
        command += ["-H", f"Host: {host_header}"]
    command += flag_list(extra)
    result = _run("nuclei", command, artifact)
    try:
        result.grepable = jsonl_path.read_text(encoding="utf-8")
    except OSError:
        result.grepable = ""  # no findings -> nuclei writes no export file
    return result


def parse_nuclei(jsonl: str) -> list[dict]:
    """Parse nuclei's JSONL export into severity-sorted finding records.

    Each line is one JSON finding; malformed/blank lines are skipped. Returns
    {template_id, name, severity, matched_at, tags, type} dicts, most-urgent
    first.
    """
    findings: list[dict] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info")
        info = info if isinstance(info, dict) else {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        findings.append({
            "template_id": obj.get("template-id") or "",
            "name": (info.get("name") or "").strip(),
            "severity": (info.get("severity") or "unknown").strip().lower(),
            "matched_at": (obj.get("matched-at") or obj.get("host") or "").strip(),
            "tags": list(tags),
            "type": (obj.get("type") or "").strip(),
        })
    findings.sort(key=lambda f: (nuclei_severity_rank(f["severity"]), f["name"]))
    return findings
