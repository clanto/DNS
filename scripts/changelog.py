#!/usr/bin/env python3
"""Registro delle variazioni delle liste pubblicate (dist/CHANGELOG.md).

Confronta ogni lista generata con la versione dell'ultimo commit (git HEAD) e aggiunge in cima al
registro una voce con aggiunte e rimozioni per lista, con esempi e, per gli IP, la fonte di provenienza.
Va eseguito dopo i build e prima del commit. Se nulla è cambiato non scrive niente.
Uso: python scripts/changelog.py
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys
from datetime import datetime, timezone

from build_ip import CACHE_DIR, ROOT, NetIndex

CHANGELOG = ROOT / "dist" / "CHANGELOG.md"
PATTERNS = ["dist/ip/*.txt", "dist/adguard/*.txt", "dist/opnsense/*.txt"]
EXAMPLES = 8
MAX_ENTRIES = 120
HEADER = ("# Registro variazioni delle liste\n\n"
          "> Generato da `scripts/changelog.py` a ogni build: aggiunte e rimozioni rispetto alla versione precedente.\n"
          "> Ultime voci in alto. Per gli IP è indicata la fonte (`ip/cache/`) o `manuale`.\n")


def previous(rel: str) -> set[str] | None:
    """Contenuto della lista all'ultimo commit; None se il file è nuovo."""
    r = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return set(r.stdout.split()) if r.returncode == 0 else None


def source_of(entry: str, caches: dict[str, NetIndex]) -> str:
    try:
        net = ipaddress.ip_network(entry)
    except ValueError:
        return ""
    found = [name for name, idx in caches.items() if idx.overlaps(net)]
    return ", ".join(found) if found else "manuale"


def fmt(entries: list[str], caches: dict[str, NetIndex] | None) -> str:
    shown = []
    for e in entries[:EXAMPLES]:
        src = source_of(e, caches) if caches else ""
        shown.append(f"`{e}`" + (f" ({src})" if src else ""))
    more = f" e altre {len(entries) - EXAMPLES}" if len(entries) > EXAMPLES else ""
    return ", ".join(shown) + more


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    caches = {p.stem: NetIndex(ipaddress.ip_network(l) for l in p.read_text(encoding="utf-8").split())
              for p in sorted(CACHE_DIR.glob("*.txt"))}
    lines: list[str] = []
    for pattern in PATTERNS:
        for path in sorted(ROOT.glob(pattern)):
            rel = path.relative_to(ROOT).as_posix()
            now = set(path.read_text(encoding="utf-8").split())
            before = previous(rel)
            if before is None:
                lines.append(f"- `{rel}`: nuova lista, {len(now)} voci")
                continue
            added, removed = sorted(now - before), sorted(before - now)
            if not added and not removed:
                continue
            ip_list = rel.startswith("dist/ip/")
            row = f"- `{rel}`: +{len(added)} / -{len(removed)} (totale {len(now)})"
            if added:
                row += f"\n  - aggiunte: {fmt(added, caches if ip_list else None)}"
            if removed:
                row += f"\n  - rimosse: {fmt(removed, None)}"
            lines.append(row)
    if not lines:
        print("Nessuna variazione nelle liste")
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = f"## {stamp}\n\n" + "\n".join(lines) + "\n"
    old_entries: list[str] = []
    if CHANGELOG.exists():
        body = CHANGELOG.read_text(encoding="utf-8").split("\n## ")[1:]
        old_entries = ["## " + e.rstrip("\n") + "\n" for e in body]
    entries = [entry] + old_entries[:MAX_ENTRIES - 1]
    CHANGELOG.parent.mkdir(parents=True, exist_ok=True)
    CHANGELOG.write_text(HEADER + "\n" + "\n".join(entries), encoding="utf-8", newline="\n")
    print(entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
