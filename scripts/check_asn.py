#!/usr/bin/env python3
"""Verifica che le reti annunciate dagli AS dei provider DNS dedicati ([[asn_checks]] in ip/sources.toml)
siano coperte dalle voci manuali della categoria (ip/custom/<categoria>.txt).

I dati di routing (RIPEstat) servono solo al confronto e non vengono pubblicati: se il provider annuncia
una rete nuova il job fallisce e la rete va aggiunta a mano, dopo verifica, al file della categoria.

Uso: python scripts/check_asn.py
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import tomllib
from datetime import date

from build_ip import CONFIG_PATH, CUSTOM_DIR, FAMILIES, fetch, load_annotated

RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = ["## Verifica reti dei provider DNS dedicati", ""]
    missing_total = 0
    for chk in cfg.get("asn_checks", []):
        asn, name, cat = chk["asn"], chk.get("name", ""), chk["category"]
        data = json.loads(fetch(RIPESTAT.format(asn=asn)))["data"]["prefixes"]
        announced = [ipaddress.ip_network(p["prefix"]) for p in data]
        announced = [n for v in FAMILIES for n in ipaddress.collapse_addresses(x for x in announced if x.version == v)]
        path = CUSTOM_DIR / f"{cat}.txt"
        errors: list[str] = []
        ours = [e.net for e in load_annotated(path, min_prefix=None, today=date.today(), errors=errors)[0]] \
            if path.exists() else []
        missing = [n for n in announced if not any(n.version == o.version and n.subnet_of(o) for o in ours)]
        missing_total += len(missing)
        state = "ok" if not missing else f"{len(missing)} reti non coperte"
        report.append(f"- AS{asn} {name} ({cat}): {len(announced)} reti annunciate, {state}")
        report += [f"  - `{n}` da aggiungere a ip/custom/{cat}.txt" for n in missing]
    text = "\n".join(report)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if missing_total else 0


if __name__ == "__main__":
    sys.exit(main())
