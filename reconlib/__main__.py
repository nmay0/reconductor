"""Entry point: `python -m recon`."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()  # leave a clean line on Ctrl-C / Ctrl-D
