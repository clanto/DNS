#!/usr/bin/env python3
"""Genera dist/unbound/safesearch.conf: SafeSearch forzato via DNS per Unbound.

Per ogni motore (domains/safesearch.toml) risolve il nome ufficiale di destinazione (es.
forcesafesearch.google.com) e scrive record A e AAAA per tutti i suoi domini. Gli IP vengono
riletti a ogni build: quando un motore li cambia il file si aggiorna da solo.
Unbound crea per ogni nome una zona "transparent": per i tipi non presenti (es. AAAA se la
destinazione non ha IPv6) risponde NODATA, quindi niente aggiramento via IPv6.
Se una destinazione non risolve, il file non viene riscritto (resta la versione precedente).
Uso: python scripts/build_safesearch.py
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import tomllib

from build_ip import ROOT, warn

CONFIG_PATH = ROOT / "domains" / "safesearch.toml"
OUT_PATH = ROOT / "dist" / "unbound" / "safesearch.conf"


def resolve(name: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    nat64 = ipaddress.ip_network("64:ff9b::/96")
    # scartati sinkhole e indirizzi NAT64 sintetizzati dal resolver locale
    return sorted((a for a in addrs if a.is_global and not (a.version == 6 and a in nat64)),
                  key=lambda a: (a.version, int(a)))


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    engines = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("engines", [])
    lines = ["# SafeSearch forzato per Unbound - generato da scripts/build_safesearch.py, non modificare a mano.",
             "# Domini e destinazioni in domains/safesearch.toml."]
    for eng in engines:
        addrs = resolve(eng["target"])
        if not any(a.version == 4 for a in addrs):
            warn(f"SafeSearch: {eng['target']} ({eng['name']}) non risolve: file invariato")
            return 0
        lines += ["", f"# {eng['name']}: {eng['target']} → {', '.join(map(str, addrs))}"]
        for domain in eng["domains"]:
            for a in addrs:
                rtype = "A" if a.version == 4 else "AAAA"
                lines.append(f'local-data: "{domain} {rtype} {a}"')
        print(f"- {eng['name']}: {len(eng['domains'])} domini → {', '.join(map(str, addrs))}")
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
