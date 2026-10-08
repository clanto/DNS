#!/usr/bin/env python3
"""Verifica che feed e fonti siano aggiornati. Fallisce se l'ultimo aggiornamento dei feed IP
(commit che ha modificato dist/ip/all-v4.txt) è più vecchio della soglia. Serve a scoprire un build
fermo prima che i firewall usino per giorni liste vecchie. Fallisce anche se una fonte non cambia
contenuto da più giorni della sua soglia (source_max_age_days, max_age_days per fonte): fonte abbandonata.
Uso: python scripts/check_freshness.py [--max-ore 24]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import tomllib

from build_ip import ROOT

WATCHED = "dist/ip/all-v4.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-ore", type=float, default=24, help="età massima accettata in ore")
    args = parser.parse_args()
    out = last_change(WATCHED)
    if out is None:
        print(f"::error::Nessun commit trovato per {WATCHED}: storico insufficiente o file mancante")
        return 1
    age_h = (time.time() - out) / 3600
    stale = age_h > args.max_ore
    lines = [f"## Aggiornamento feed\n\nUltimo aggiornamento di `{WATCHED}`: {age_h:.1f} ore fa "
             f"(soglia {args.max_ore:.0f} ore). " + ("**Feed fermi: controllare il workflow Build feed.**" if stale
                                                     else "Feed aggiornati."), ""]
    if stale:
        print(f"::error::Feed non aggiornati da {age_h:.1f} ore", file=sys.stderr)

    # Fonti: una fonte il cui contenuto non cambia da troppo tempo è probabilmente abbandonata
    lines += ["## Aggiornamento delle singole fonti", "",
              "Giorni dall'ultimo cambiamento del contenuto (cache nel repository) e soglia.", "",
              "| Fonte | Giorni | Soglia | Stato |", "|---|---|---|---|"]
    stale_sources = []
    for cache, sid, limit in sources():
        changed = last_change(cache)
        if changed is None:
            continue
        days = (time.time() - changed) / 86400
        bad = days > limit
        lines.append(f"| {sid} | {days:.0f} | {limit} | {'**ferma**' if bad else 'ok'} |")
        if bad:
            stale_sources.append(sid)
            print(f"::error::Fonte {sid} senza cambiamenti da {days:.0f} giorni (soglia {limit})", file=sys.stderr)
    text = "\n".join(lines)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if stale or stale_sources else 0


def last_change(rel: str) -> int | None:
    out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", rel], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    return int(out) if out else None


def sources() -> list[tuple[str, str, int]]:
    """(cache, id, soglia in giorni) di tutte le fonti attive scaricate da URL."""
    found = []
    for cfg_path, cache_dir in (("ip/sources.toml", "ip/cache"), ("domains/domains.toml", "domains/cache")):
        cfg = tomllib.loads((ROOT / cfg_path).read_text(encoding="utf-8"))
        default = cfg.get("settings", {}).get("source_max_age_days", cfg.get("source_max_age_days", 7))
        for src in cfg.get("sources", []):
            if not src.get("enabled", True) or "path" in src:
                continue
            found.append((f"{cache_dir}/{src['id']}.txt", src["id"], src.get("max_age_days", default)))
    return found


if __name__ == "__main__":
    sys.exit(main())
