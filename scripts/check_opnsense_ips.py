#!/usr/bin/env python3
"""Controllo settimanale delle liste FQDN per OPNsense (dist/opnsense/*.txt).

Risolve ogni dominio e associa gli IP al proprio AS (database iptoasn.com, licenza PDDL, usato solo
per l'analisi e non pubblicato). Segnala gli IP che OPNsense bloccherebbe insieme ad altri siti:
  - IP in AS di CDN/hosting condivisi ([opnsense_check] in domains/domains.toml)
  - IP che ospitano almeno N domini diversi della lista (tipico dell'hosting condiviso)

Rimedio: aggiungere la rete a ip/condivisi.txt (esclusa da feed e liste OPNsense) oppure togliere il
dominio dalla fonte manuale. Va eseguito su rete con DNS non filtrato (runner GitHub Actions).
Uso: python scripts/check_opnsense_ips.py
"""
from __future__ import annotations

import bisect
import concurrent.futures as cf
import ipaddress
import os
import socket
import sys
import tomllib
from collections import defaultdict

import asn
from build_domains import CONFIG_PATH
from build_ip import ROOT

OPNSENSE_DIR = ROOT / "dist" / "opnsense"
MAX_WARNINGS = 30


class AsnDb:
    """Ricerca IP → (asn, paese, descrizione) su intervalli ordinati."""

    def __init__(self, raw: bytes):
        self.tables: dict[int, tuple[list[int], list[int], list[tuple[int, str, str]]]] = {}
        rows: dict[int, list] = {4: [], 6: []}
        for line in asn.gunzip(raw).decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 5 or parts[2] == "0":
                continue
            start, end = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
            rows[start.version].append((int(start), int(end), (int(parts[2]), parts[3], parts[4])))
        for v, r in rows.items():
            r.sort()
            self.tables[v] = ([x[0] for x in r], [x[1] for x in r], [x[2] for x in r])

    def lookup(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[int, str, str] | None:
        starts, ends, info = self.tables[ip.version]
        i = bisect.bisect_right(starts, int(ip)) - 1
        return info[i] if i >= 0 and int(ip) <= ends[i] else None


def resolve(name: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    return [a for a in addrs if a.is_global]  # i sinkhole (0.0.0.0, ecc.) non contano


def registrable(name: str) -> str:
    return ".".join(name.split(".")[-2:])


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    opts = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("opnsense_check", {})
    keywords = [k.upper() for k in opts.get("shared_as_keywords", [])]
    shared_asn = set(opts.get("shared_asn", []))
    min_domains = opts.get("min_domains_per_ip", 3)
    ignore = set(opts.get("ignore", []))

    db = AsnDb(asn.download_raw())  # stessi limiti di dimensione e redirect solo HTTPS dei build

    report = ["## Controllo liste OPNsense: IP su infrastrutture condivise", ""]
    flagged_total = 0
    warnings = 0
    for path in sorted(OPNSENSE_DIR.glob("*.txt")):
        names = [n for n in path.read_text(encoding="utf-8").split() if n not in ignore]
        with cf.ThreadPoolExecutor(64) as ex:
            resolved = dict(zip(names, ex.map(resolve, names)))
        by_ip: dict = defaultdict(set)
        for name, addrs in resolved.items():
            for a in addrs:
                by_ip[a].add(name)
        by_as: dict = defaultdict(lambda: {"ips": 0, "desc": ""})
        flagged = []
        for ip, doms in by_ip.items():
            info = db.lookup(ip)
            asn, country, desc = info if info else (0, "", "sconosciuto")
            by_as[asn]["ips"] += 1
            by_as[asn]["desc"] = desc
            reasons = []
            if asn in shared_asn or any(k in desc.upper() for k in keywords):
                reasons.append(f"AS{asn} {desc} condiviso")
            if len({registrable(d) for d in doms}) >= min_domains:
                reasons.append(f"{len(doms)} domini sullo stesso IP")
            if reasons:
                flagged.append((ip, asn, desc, sorted(doms), "; ".join(reasons)))
        flagged_total += len(flagged)
        dead = sum(1 for a in resolved.values() if not a)
        report += [f"### {path.name}: {len(names)} domini, {len(by_ip)} IP, {dead} non risolti, "
                   f"**{len(flagged)} IP segnalati**", ""]
        if flagged:
            report += ["| IP | AS | Motivo | Domini |", "|---|---|---|---|"]
            for ip, asn, desc, doms, why in sorted(flagged, key=lambda f: (f[1], str(f[0]))):
                report.append(f"| `{ip}` | AS{asn} {desc} | {why} | {', '.join(doms[:5])}"
                              f"{'…' if len(doms) > 5 else ''} |")
                if warnings < MAX_WARNINGS:
                    print(f"::warning::{path.name}: {ip} ({why}) da {', '.join(doms[:3])}", file=sys.stderr)
                    warnings += 1
            report.append("")
        top = sorted(by_as.items(), key=lambda x: -x[1]["ips"])[:10]
        report += ["AS con più IP: " + ", ".join(f"AS{a} {d['desc']} ({d['ips']})" for a, d in top), ""]
    report += ["Rimedio: aggiungere la rete a `ip/condivisi.txt` (esclusa da feed IP e liste OPNsense) "
               "oppure togliere il dominio dalla fonte manuale."]
    text = "\n".join(report)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if flagged_total else 0


if __name__ == "__main__":
    sys.exit(main())
