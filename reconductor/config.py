"""Configuration: hardcoded defaults plus a JSON override file.

The custom config stores *only* the keys that differ from the defaults.
Loading deep-merges the overrides on top of the defaults so any missing
key transparently falls back to its default value.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

# Where the custom (override-only) config lives.
CONFIG_PATH = Path("./recon_config.json")

# The full default config. Anything not overridden falls back to this.
DEFAULT_CONFIG: dict[str, Any] = {
    # Wordlists used by the three gobuster modes.
    "wordlists": {
        "dir": "/usr/share/wordlists/dirb/common.txt",
        "dns": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "vhost": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    },
    # nmap timing template applied to every nmap stage.
    "nmap_timing": "-T4",
    # Root output directory; runs land under <output_dir>/<host>/<timestamp>/.
    "output_dir": "./recon",
    # Extra flags appended per tool/stage (a single string each, split on spaces).
    "tool_flags": {
        "nmap_sweep": "",
        "nmap_quick": "",
        "nmap_full": "",
        "nmap_service": "",
        "gobuster": "",
        "whatweb": "",
        "curl": "",
    },
}


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of *base* with *overrides* recursively merged in."""
    result = copy.deepcopy(base)
    for key, value in overrides.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _diff_overrides(base: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return only the parts of *current* that differ from *base* (recursively)."""
    overrides: dict[str, Any] = {}
    for key, value in current.items():
        if key not in base:
            overrides[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(base[key], dict):
            sub = _diff_overrides(base[key], value)
            if sub:
                overrides[key] = sub
        elif value != base[key]:
            overrides[key] = copy.deepcopy(value)
    return overrides


def load_overrides(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load the override-only JSON file, or an empty dict if none exists."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def load_config(use_custom: bool, path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Return the effective config.

    If *use_custom* is True, deep-merge the saved overrides onto the defaults;
    otherwise return a clean copy of the defaults.
    """
    if not use_custom:
        return copy.deepcopy(DEFAULT_CONFIG)
    return _deep_merge(DEFAULT_CONFIG, load_overrides(path))


def save_custom_config(current: dict[str, Any], path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Persist *current* as override-only JSON (diff against defaults). Returns the saved overrides."""
    overrides = _diff_overrides(DEFAULT_CONFIG, current)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(overrides, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return overrides


def flag_list(flags: str) -> list[str]:
    """Split a config flag string into argv tokens (empty string -> [])."""
    return flags.split() if flags and flags.strip() else []
