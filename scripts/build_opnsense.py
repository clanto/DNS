#!/usr/bin/env python3
"""Genera le liste FQDN per alias OPNsense dalle blocklist domini con 'opnsense = true'.

OPNsense risolve ogni FQDN dell'alias e blocca gli IP ottenuti. Per evitare danni e carico inutile
vengono scartati:
  - domini che non risolvono (morti): solo carico sul resolver
  - domini che risolvono su IP non instradabili (sinkhole)
  - domini su IP di CDN condivise (Cloudflare, CloudFront, Fastly): bloccarli fermerebbe migliaia di siti

Gli intervalli CDN vengono scaricati solo per il filtro e non sono pubblicati.
Va eseguito su una rete con DNS non filtrato (runner GitHub Actions).

Output: dist/opnsense/<categoria>.txt (un FQDN per riga) e dist/opnsense/README.md
Uso: python scripts/build_opnsense.py
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import sys
import tomllib

from build_domains import CONFIG_PATH, PLAIN_DIR
from build_ip import RAW_BASE, ROOT, fetch, warn

OUT_DIR = ROOT / "dist" / "opnsense"
CDN_SOURCES = {
    "Cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
    "CloudFront": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
    "Fastly": ["https://api.fastly.com/public-ip-list"],
}
MIN_RESOLVED_RATIO = 0.2  # sotto questa quota di domini risolti si presume un problema di rete
MAX_DROP_RATIO = 0.5

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def cdn_ranges() -> list[Network]:
    nets: list[Network] = []
    for name, urls in CDN_SOURCES.items():
        for url in urls:
            text = fetch(url)
            if url.endswith("ip-ranges.json"):
                data = json.loads(text)
                cidrs = [p["ip_prefix"] for p in data["prefixes"] if p["service"] == "CLOUDFRONT"]
                cidrs += [p["ipv6_prefix"] for p in data["ipv6_prefixes"] if p["service"] == "CLOUDFRONT"]
            elif url.endswith("public-ip-list"):
                data = json.loads(text)
                cidrs = data.get("addresses", []) + data.get("ipv6_addresses", [])
            else:
                cidrs = text.split()
            nets += [ipaddress.ip_network(c, strict=False) for c in cidrs]
        print(f"- intervalli CDN {name}: caricati")
    return nets


def resolve(name: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return list({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos})


def classify(name: str, cdn: list[Network]) -> str:
    addrs = resolve(name)
    if not addrs:
        return "morto"
    if any(not a.is_global for a in addrs):
        return "sinkhole"
    if any(a in n for a in addrs for n in cdn if n.version == a.version):
        return "cdn"
    return "ok"


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cats = {c: o for c, o in cfg.get("block", {}).items() if o.get("opnsense")}
    try:
        cdn = cdn_ranges()
    except Exception as exc:  # senza filtro CDN non si pubblica: meglio tenere la versione precedente
        warn(f"intervalli CDN non disponibili ({exc}): liste OPNsense invariate")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for cat, opts in cats.items():
        names = [l for l in (PLAIN_DIR / f"block-{cat}.txt").read_text(encoding="utf-8").split() if l]
        with cf.ThreadPoolExecutor(64) as ex:
            verdicts = dict(zip(names, ex.map(lambda n: classify(n, cdn), names)))
        ok = sorted(n for n, v in verdicts.items() if v == "ok")
        counts = {k: sum(1 for v in verdicts.values() if v == k) for k in ("ok", "morto", "sinkhole", "cdn")}
        out = OUT_DIR / f"{cat}.txt"
        prev = len(out.read_text(encoding="utf-8").split()) if out.exists() else 0
        resolved = len(names) - counts["morto"]
        reason = ""
        if names and resolved / len(names) < MIN_RESOLVED_RATIO:
            reason = f"risolti solo {resolved}/{len(names)} domini, probabile problema DNS"
        elif prev and len(ok) < prev * (1 - MAX_DROP_RATIO):
            reason = f"calo sospetto {prev} → {len(ok)}"
        if reason:
            warn(f"{cat}: {reason}: lista invariata")
            rows.append((cat, opts.get("description", ""), len(names), None))
            continue
        out.write_text("".join(f"{n}\n" for n in ok), encoding="utf-8", newline="\n")
        rows.append((cat, opts.get("description", ""), len(names), counts))
        print(f"- {cat}: {counts['ok']} pubblicati su {len(names)} "
              f"(morti {counts['morto']}, sinkhole {counts['sinkhole']}, CDN condivise {counts['cdn']})")

    if rows:
        lines = [
            "# Liste FQDN per alias OPNsense",
            "",
            "> File generato da `scripts/build_opnsense.py`: **non modificare a mano**.",
            "",
            "OPNsense risolve ogni dominio dell'alias e blocca gli IP ottenuti, quindi segue anche gli anycast.",
            "Rispetto alle liste AdGuard sono esclusi i domini morti, quelli su IP non instradabili e quelli",
            "su IP di CDN condivise (Cloudflare, CloudFront, Fastly), che bloccherebbero anche siti legittimi.",
            "",
            "| Lista | Descrizione | Pubblicati | Morti | CDN condivise | Totale AdGuard |",
            "|---|---|---|---|---|---|",
        ]
        for cat, desc, total, c in rows:
            if c is None:
                lines.append(f"| [{cat}.txt]({RAW_BASE}/dist/opnsense/{cat}.txt) | {desc} | "
                             f"versione precedente (ultimo build non valido) | | | {total} |")
                continue
            lines.append(f"| [{cat}.txt]({RAW_BASE}/dist/opnsense/{cat}.txt) | {desc} | {c['ok']} | "
                         f"{c['morto'] + c['sinkhole']} | {c['cdn']} | {total} |")
        (OUT_DIR / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
