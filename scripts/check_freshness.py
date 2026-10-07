#!/usr/bin/env python3
"""Verifica che i feed pubblicati siano aggiornati: fallisce se l'ultimo aggiornamento dei feed IP
(commit che ha modificato dist/ip/all-v4.txt) è più vecchio della soglia. Serve a scoprire un build
fermo prima che i firewall usino per giorni liste vecchie.
Uso: python scripts/check_freshness.py [--max-ore 24]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from build_ip import ROOT

WATCHED = "dist/ip/all-v4.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-ore", type=float, default=24, help="età massima accettata in ore")
    args = parser.parse_args()
    out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", WATCHED], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    if not out:
        print(f"::error::Nessun commit trovato per {WATCHED}: storico insufficiente o file mancante")
        return 1
    age_h = (time.time() - int(out)) / 3600
    stale = age_h > args.max_ore
    text = (f"## Aggiornamento feed\n\nUltimo aggiornamento di `{WATCHED}`: {age_h:.1f} ore fa "
            f"(soglia {args.max_ore:.0f} ore). " + ("**Feed fermi: controllare il workflow Build feed.**" if stale
                                                    else "Feed aggiornati."))
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if stale:
        print(f"::error::Feed non aggiornati da {age_h:.1f} ore", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
