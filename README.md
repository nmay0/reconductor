# recon

A Python recon-automation tool that orchestrates `nmap`, `gobuster`, `whatweb`,
and `curl` (for now) into a staged, partly-parallel pipeline with a small `rich`-based CLI.

> **Authorized testing only.** Use exclusively against systems you own or have
> explicit written permission to assess.

## Pipeline

For each target host:

1. **Quick scan** — `nmap -F` (top ports) fires immediately.
2. **Full scan** — `nmap -p-` runs *in parallel* with the quick scan.
3. **Service scan** — once ports are known, `nmap -sV -sC` runs against the
   union of all discovered open ports.
4. **Web enumeration** — for every detected web port, `gobuster` + `whatweb` +
   `curl -I` run *in parallel*.
   - HTTPS-aware: `https://` scheme for gobuster/whatweb and `-k` for curl on
     443/8443 (or any `ssl`/`https` service), so self-signed certs don't break.

CIDR ranges run an `nmap -sn` discovery sweep first, then **pause** so you can
review the live hosts and exclude any before enumeration. Each kept host is then
configured (config + tool toggles) and run **one at a time**.

## Install

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

External tools (install separately; missing ones are skipped with a warning):

```bash
brew install nmap gobuster whatweb   # curl ships with macOS
```

## Run

```bash
./.venv/bin/python -m reconlib
```

Menu:

- **1. Run** — prompts for an IP or CIDR, then which config (default/custom),
  then runs the pipeline. For a CIDR it sweeps → lets you exclude hosts →
  prompts config + toggles per kept host.
- **2. Edit config** — edit the custom config; only values that differ from the
  defaults are saved (to `./recon_config.json`).
- **3. Modify run** — toggle which tools run this session. Session-only; never
  saved to config.

### gobuster modes

`dir` is the default. Enable `gobuster_dns` / `gobuster_vhost` via *Modify run*
(or the per-host prompt on a CIDR); you'll be asked for a domain, since those
modes enumerate names rather than scan an IP.

## Configuration

Defaults are hardcoded; the custom config (`./recon_config.json`) stores **only
your overrides** and missing keys fall back to defaults automatically.

| Setting | Default |
| --- | --- |
| `nmap_timing` | `-T4` |
| `output_dir` | `./recon` |
| `wordlists.dir` | `/usr/share/wordlists/dirb/common.txt` |
| `wordlists.dns` / `wordlists.vhost` | seclists subdomains top-5000 |
| `tool_flags.<tool>` | empty (extra flags per stage) |

## Output

```
recon/<target-ip>/<timestamp>/
  nmap_quick.txt  nmap_full.txt  nmap_service.txt
  gobuster_dir_<port>.txt  gobuster_vhost_<port>.txt  gobuster_dns.txt
  whatweb_<port>.txt  curl_<port>.txt
```

One file per tool, timestamped per run, so previous runs are never overwritten.
A summary (open ports, services, notable gobuster hits) prints to the terminal
at the end of each host.
