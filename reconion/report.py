"""Consolidated, multi-format run reports built from one structured model.

The pipeline records every tool it runs as a ToolRun. At the end of a host's
run we distill those into a single canonical document — open ports, web
findings, discovery, warnings — and render it into whatever formats the config
selects: summary txt, raw txt, JSON, XML, Markdown.

This is separate from the per-tool artifacts (nmap_quick.txt,
gobuster_dir_80.txt, ...) that tools.py writes as raw evidence; those are
always written regardless of the selected formats. These are the
*consolidated* reports.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .tools import (
    GOBUSTER_INTERESTING,
    ToolRun,
    parse_ffuf_structured,
    parse_gobuster_hits,
    parse_searchsploit,
)

SCHEMA_VERSION = 1

# Canonical selectable formats: key -> (label, filename). The config dict
# DEFAULT_CONFIG["output_formats"] uses these same keys.
REPORT_FORMATS: list[tuple[str, str, str]] = [
    ("summary", "Summary (human-readable txt)", "report.txt"),
    ("raw", "Raw combined tool output (txt)", "report.raw.txt"),
    ("json", "JSON (structured)", "report.json"),
    ("xml", "XML (structured)", "report.xml"),
    ("markdown", "Markdown report", "report.md"),
]


# --------------------------------------------------------------------------- #
# Parsing tool output into structured findings
# --------------------------------------------------------------------------- #

# gobuster dir line: "/admin   (Status: 301) [Size: 312] [--> /admin/]"
_GOBUSTER_DIR_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]*)\])?"
)


def parse_gobuster_structured(stdout: str) -> list[dict[str, Any]]:
    """Parse gobuster dir output into {path, status, size, redirect} records."""
    hits: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "Status:" not in line:
            continue
        m = _GOBUSTER_DIR_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        if status not in GOBUSTER_INTERESTING:
            continue
        size = m.group("size")
        redirect = (m.group("redirect") or "").strip()
        hits.append({
            "path": m.group("path"),
            "status": status,
            "size": int(size) if size is not None else None,
            "redirect": redirect or None,
        })
    return hits


def extract_whatweb(stdout: str) -> str:
    """Collapse whatweb's per-URL output into a single summary line."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return " ".join(lines)


def extract_headers(stdout: str) -> dict[str, Any]:
    """Pull the status line and a few key headers out of `curl -D -` output."""
    status_chain: list[str] = []
    headers: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("HTTP/"):
            status_chain.append(line.strip())
        elif ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    return {
        "status": status_chain[-1] if status_chain else "",
        "status_chain": status_chain,
        "server": headers.get("server", ""),
        "location": headers.get("location", ""),
        "content_type": headers.get("content-type", ""),
    }


# --------------------------------------------------------------------------- #
# Canonical document
# --------------------------------------------------------------------------- #

def build_document(
    *,
    host: str,
    run_dir: Path,
    started: datetime,
    finished: datetime,
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None,
    vhosts: list[str],
    ports: list[Any],
    tool_runs: list[ToolRun],
    warnings: list[str],
) -> dict[str, Any]:
    """Distill a host run into the single dict that drives every renderer."""
    ports_doc = [{
        "number": p.number,
        "proto": p.proto,
        "state": "open",
        "service": p.service,
        "version": p.version,
        "web": p.is_web,
        "https": p.is_https,
    } for p in ports]

    # Group content tools (dir/ffuf/whatweb/curl) by web context = (port, vhost).
    web_map: dict[tuple[int | None, str | None], dict[str, Any]] = {}
    discovery: dict[str, list[str]] = {"vhost": [], "dns": []}
    exploits: list[dict[str, str]] = []
    for tr in tool_runs:
        out = tr.result.stdout or ""
        if tr.kind in ("dir", "ffuf", "whatweb", "curl"):
            key = (tr.port, tr.vhost)
            entry = web_map.get(key)
            if entry is None:
                entry = {"url": tr.title, "port": tr.port, "vhost": tr.vhost,
                         "whatweb": "", "headers": {}, "gobuster": [], "ffuf": []}
                web_map[key] = entry
            if not entry["url"]:
                entry["url"] = tr.title
            if tr.kind == "dir":
                entry["gobuster"] = parse_gobuster_structured(out)
            elif tr.kind == "ffuf":
                entry["ffuf"] = parse_ffuf_structured(out)
            elif tr.kind == "whatweb":
                entry["whatweb"] = extract_whatweb(out)
            elif tr.kind == "curl":
                entry["headers"] = extract_headers(out)
        elif tr.kind == "vhost":
            discovery["vhost"] = parse_gobuster_hits(out)
        elif tr.kind == "dns":
            discovery["dns"] = parse_gobuster_hits(out)
        elif tr.kind == "searchsploit":
            exploits = parse_searchsploit(out)

    # Per-tool evidence files already in the run dir (reports not yet written).
    artifacts = sorted(
        p.name for p in run_dir.iterdir()
        if p.is_file() and not p.name.startswith("report.")
    ) if run_dir.exists() else []

    return {
        "tool": "reconion",
        "schema_version": SCHEMA_VERSION,
        "target": host,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "scan": {
            "nmap_timing": config.get("nmap_timing", "-T4"),
            "domain": domain,
            "vhosts": list(vhosts),
            "toggles": dict(toggles),
            "wordlists": dict(config.get("wordlists", {})),
        },
        "ports": ports_doc,
        "web": list(web_map.values()),
        "discovery": discovery,
        "exploits": exploits,
        "warnings": list(warnings),
        "artifacts": artifacts,
    }


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #

def _fmt_duration(seconds: float) -> str:
    return f"{seconds:.1f}s"


def _render_summary_text(doc: dict[str, Any]) -> str:
    lines: list[str] = ["recon onion — report"]
    lines.append(f"Target:        {doc['target']}")
    lines.append(f"Started:       {doc['started']}")
    lines.append(f"Finished:      {doc['finished']}")
    lines.append(f"Duration:      {_fmt_duration(doc['duration_seconds'])}")
    scan = doc["scan"]
    lines.append(f"nmap timing:   {scan.get('nmap_timing', '')}")
    if scan.get("domain"):
        lines.append(f"Domain:        {scan['domain']}")
    if scan.get("vhosts"):
        lines.append(f"Virtual hosts: {', '.join(scan['vhosts'])}")
    lines.append("")

    ports = doc["ports"]
    lines.append(f"Open ports ({len(ports)})")
    if ports:
        for p in ports:
            label = f"{p['number']}/{p['proto']}"
            svc = p["service"] or "-"
            ver = f"  {p['version']}" if p["version"] else ""
            lines.append(f"  {label:<10} {svc}{ver}")
    else:
        lines.append("  none")
    lines.append("")

    web = doc["web"]
    if web:
        lines.append("Web findings")
        for w in web:
            lines.append(f"  {w['url']}")
            if w.get("whatweb"):
                lines.append(f"    whatweb:  {w['whatweb']}")
            headers = w.get("headers") or {}
            if headers.get("status"):
                extra = []
                if headers.get("server"):
                    extra.append(f"Server: {headers['server']}")
                if headers.get("location"):
                    extra.append(f"Location: {headers['location']}")
                tail = ("  |  " + "  ".join(extra)) if extra else ""
                lines.append(f"    response: {headers['status']}{tail}")
            hits = w.get("gobuster") or []
            if hits:
                lines.append(f"    gobuster ({len(hits)}):")
                for hit in hits:
                    size = "" if hit["size"] is None else f"  size={hit['size']}"
                    redir = f"  --> {hit['redirect']}" if hit["redirect"] else ""
                    lines.append(f"      {hit['status']}  {hit['path']}{size}{redir}")
            ffuf_hits = w.get("ffuf") or []
            if ffuf_hits:
                lines.append(f"    ffuf ({len(ffuf_hits)}):")
                for hit in ffuf_hits:
                    size = "" if hit["size"] is None else f"  size={hit['size']}"
                    lines.append(f"      {hit['status']}  {hit['path']}{size}")
        lines.append("")

    exploits = doc.get("exploits", [])
    if exploits:
        lines.append(f"Exploits — searchsploit ({len(exploits)})")
        for ex in exploits:
            lines.append(f"  {ex['title']}")
            lines.append(f"    {ex['path']}")
        lines.append("")

    disc = doc.get("discovery", {})
    if disc.get("vhost") or disc.get("dns"):
        lines.append("Discovery")
        for item in disc.get("vhost", []):
            lines.append(f"  vhost: {item}")
        for item in disc.get("dns", []):
            lines.append(f"  dns:   {item}")
        lines.append("")

    warnings = doc.get("warnings", [])
    if warnings:
        lines.append(f"Warnings ({len(warnings)})")
        for w in warnings:
            lines.append(f"  - {w}")
        lines.append("")

    artifacts = doc.get("artifacts", [])
    if artifacts:
        lines.append("Artifacts")
        for a in artifacts:
            lines.append(f"  - {a}")

    return "\n".join(lines).rstrip("\n") + "\n"


def _md_escape(value: Any) -> str:
    """Escape pipe chars so values don't break Markdown table cells."""
    return str(value).replace("|", "\\|")


def _render_markdown(doc: dict[str, Any]) -> str:
    lines: list[str] = [f"# recon onion report — {doc['target']}", ""]
    lines.append(f"- **Target:** {doc['target']}")
    lines.append(f"- **Started:** {doc['started']}")
    lines.append(f"- **Finished:** {doc['finished']}")
    lines.append(f"- **Duration:** {_fmt_duration(doc['duration_seconds'])}")
    scan = doc["scan"]
    lines.append(f"- **nmap timing:** `{scan.get('nmap_timing', '')}`")
    if scan.get("domain"):
        lines.append(f"- **Domain:** {scan['domain']}")
    if scan.get("vhosts"):
        lines.append(f"- **Virtual hosts:** {', '.join(scan['vhosts'])}")
    lines.append("")

    lines.append("## Open ports")
    lines.append("")
    ports = doc["ports"]
    if ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|---:|---|---|---|")
        for p in ports:
            lines.append(
                f"| {p['number']} | {p['proto']} | "
                f"{_md_escape(p['service'] or '-')} | {_md_escape(p['version'] or '-')} |"
            )
    else:
        lines.append("_No open ports found._")
    lines.append("")

    web = doc["web"]
    if web:
        lines.append("## Web findings")
        lines.append("")
        for w in web:
            lines.append(f"### {w['url']}")
            lines.append("")
            if w.get("whatweb"):
                lines.append(f"- **whatweb:** {w['whatweb']}")
            headers = w.get("headers") or {}
            if headers.get("status"):
                bits = [f"`{headers['status']}`"]
                if headers.get("server"):
                    bits.append(f"Server: `{headers['server']}`")
                if headers.get("location"):
                    bits.append(f"Location: `{headers['location']}`")
                lines.append("- **Response:** " + " — ".join(bits))
            hits = w.get("gobuster") or []
            if hits:
                lines.append("")
                lines.append("| Path | Status | Size | Redirect |")
                lines.append("|---|---:|---:|---|")
                for hit in hits:
                    size = "" if hit["size"] is None else str(hit["size"])
                    lines.append(
                        f"| {_md_escape(hit['path'])} | {hit['status']} | "
                        f"{size} | {_md_escape(hit['redirect'] or '')} |"
                    )
            ffuf_hits = w.get("ffuf") or []
            if ffuf_hits:
                lines.append("")
                lines.append("| Path (ffuf) | Status | Size |")
                lines.append("|---|---:|---:|")
                for hit in ffuf_hits:
                    size = "" if hit["size"] is None else str(hit["size"])
                    lines.append(
                        f"| {_md_escape(hit['path'])} | {hit['status']} | {size} |"
                    )
            lines.append("")

    exploits = doc.get("exploits", [])
    if exploits:
        lines.append("## Exploits (searchsploit)")
        lines.append("")
        lines.append("| Title | Path |")
        lines.append("|---|---|")
        for ex in exploits:
            lines.append(f"| {_md_escape(ex['title'])} | {_md_escape(ex['path'])} |")
        lines.append("")

    disc = doc.get("discovery", {})
    if disc.get("vhost") or disc.get("dns"):
        lines.append("## Discovery")
        lines.append("")
        for item in disc.get("vhost", []):
            lines.append(f"- vhost: {_md_escape(item)}")
        for item in disc.get("dns", []):
            lines.append(f"- dns: {_md_escape(item)}")
        lines.append("")

    warnings = doc.get("warnings", [])
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {_md_escape(w)}")
        lines.append("")

    artifacts = doc.get("artifacts", [])
    if artifacts:
        lines.append("## Artifacts")
        lines.append("")
        for a in artifacts:
            lines.append(f"- `{a}`")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _sub(parent: ET.Element, tag: str, text: Any = None, **attrs: Any) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        el.text = str(text)
    return el


def _render_xml(doc: dict[str, Any]) -> str:
    root = ET.Element("reconReport", {
        "tool": doc["tool"], "schemaVersion": str(doc["schema_version"])})
    _sub(root, "target", doc["target"])
    _sub(root, "started", doc["started"])
    _sub(root, "finished", doc["finished"])
    _sub(root, "durationSeconds", _fmt_duration(doc["duration_seconds"]).rstrip("s"))

    scan = doc["scan"]
    scan_el = ET.SubElement(root, "scan")
    _sub(scan_el, "nmapTiming", scan.get("nmap_timing", ""))
    _sub(scan_el, "domain", scan.get("domain") or "")
    vhosts_el = ET.SubElement(scan_el, "vhosts")
    for vh in scan.get("vhosts", []):
        _sub(vhosts_el, "vhost", vh)
    toggles_el = ET.SubElement(scan_el, "toggles")
    for key, val in scan.get("toggles", {}).items():
        _sub(toggles_el, "toggle", name=key, enabled=str(bool(val)).lower())
    wl_el = ET.SubElement(scan_el, "wordlists")
    for mode, path in scan.get("wordlists", {}).items():
        _sub(wl_el, "wordlist", path, mode=mode)

    ports_el = ET.SubElement(root, "ports")
    for p in doc["ports"]:
        port_el = ET.SubElement(ports_el, "port", {
            "number": str(p["number"]), "proto": p["proto"], "state": p["state"],
            "web": str(p["web"]).lower(), "https": str(p["https"]).lower()})
        _sub(port_el, "service", p["service"] or "")
        _sub(port_el, "version", p["version"] or "")

    web_el = ET.SubElement(root, "web")
    for w in doc["web"]:
        target_el = ET.SubElement(web_el, "target", {
            "url": w["url"] or "",
            "port": "" if w["port"] is None else str(w["port"]),
            "vhost": w["vhost"] or ""})
        _sub(target_el, "whatweb", w.get("whatweb", ""))
        headers = w.get("headers") or {}
        headers_el = ET.SubElement(target_el, "headers",
                                   {"status": headers.get("status", "")})
        _sub(headers_el, "server", headers.get("server", ""))
        _sub(headers_el, "location", headers.get("location", ""))
        _sub(headers_el, "contentType", headers.get("content_type", ""))
        gob_el = ET.SubElement(target_el, "gobuster")
        for hit in w.get("gobuster", []):
            ET.SubElement(gob_el, "hit", {
                "path": hit["path"], "status": str(hit["status"]),
                "size": "" if hit["size"] is None else str(hit["size"]),
                "redirect": hit["redirect"] or ""})
        ffuf_el = ET.SubElement(target_el, "ffuf")
        for hit in w.get("ffuf", []):
            ET.SubElement(ffuf_el, "hit", {
                "path": hit["path"], "status": str(hit["status"]),
                "size": "" if hit["size"] is None else str(hit["size"])})

    exploits_el = ET.SubElement(root, "exploits")
    for ex in doc.get("exploits", []):
        ET.SubElement(exploits_el, "exploit",
                      {"title": ex["title"], "path": ex["path"]})

    disc = doc.get("discovery", {})
    disc_el = ET.SubElement(root, "discovery")
    disc_vhosts = ET.SubElement(disc_el, "vhosts")
    for item in disc.get("vhost", []):
        _sub(disc_vhosts, "item", item)
    disc_dns = ET.SubElement(disc_el, "dns")
    for item in disc.get("dns", []):
        _sub(disc_dns, "item", item)

    warnings_el = ET.SubElement(root, "warnings")
    for w in doc.get("warnings", []):
        _sub(warnings_el, "warning", w)

    artifacts_el = ET.SubElement(root, "artifacts")
    for a in doc.get("artifacts", []):
        _sub(artifacts_el, "artifact", a)

    ET.indent(root)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            + ET.tostring(root, encoding="unicode") + "\n")


def _render_raw(tool_runs: list[ToolRun]) -> str:
    blocks: list[str] = []
    for tr in tool_runs:
        res = tr.result
        head = "=" * 72 + f"\n{tr.title or tr.name}\n$ {res.cmdline}\n" + "-" * 72
        if res.skipped:
            body = f"skipped — {res.error}"
        else:
            body = (res.stdout or "").rstrip("\n") or "(no output)"
            if res.stderr and res.stderr.strip() and not res.ok:
                body += "\n\n--- stderr ---\n" + res.stderr.rstrip("\n")
            if res.error:
                body += f"\n! {res.error}"
        blocks.append(f"{head}\n{body}")
    return "\n\n\n".join(blocks).rstrip("\n") + "\n"


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def write_reports(
    run_dir: Path,
    document: dict[str, Any],
    tool_runs: list[ToolRun],
    formats: dict[str, bool],
) -> list[str]:
    """Write each selected consolidated report into *run_dir*; return filenames."""
    written: list[str] = []

    def emit(key: str, filename: str, text: str) -> None:
        if formats.get(key):
            (run_dir / filename).write_text(text, encoding="utf-8")
            written.append(filename)

    emit("summary", "report.txt", _render_summary_text(document))
    emit("raw", "report.raw.txt", _render_raw(tool_runs))
    emit("json", "report.json",
         json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    emit("xml", "report.xml", _render_xml(document))
    emit("markdown", "report.md", _render_markdown(document))
    return written
