#!/usr/bin/env python3
"""Controlli online sulle liste curate.

- allowlist che copre un dominio di bypass DNS/VPN/proxy (HaGeZi, dibdot) → errore
- allowlist con dominio NXDOMAIN: quasi sempre un refuso → errore
- blocklist con dominio NXDOMAIN su due resolver diversi: morto → segnalato; con --fix viene tolto
  dalle blocklist manuali (domains/blocklist/*.txt, esclusi i TLD) e il workflow apre una PR

Va eseguito su una rete con DNS non filtrato (runner GitHub Actions).
Uso: python scripts/check_domains.py [--fix]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import re
import subprocess
import sys
import tomllib

from build_domains import CONFIG_PATH, DOMAIN_RE, DOMAINS_DIR, KINDS, covers
from build_ip import fetch

RESOLVER = os.environ.get("CHECK_RESOLVER", "1.1.1.1")
CONFIRM_RESOLVER = "8.8.8.8"  # un dominio è morto solo se NXDOMAIN anche qui
BYPASS_LISTS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",
    "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt",
]


def bypass_domains() -> set[str]:
    found: set[str] = set()
    for url in BYPASS_LISTS:
        for line in fetch(url).splitlines():
            line = line.strip().lower()
            if not line or line[0] in "#!":
                continue
            m = re.match(r"^\|\|([^\^/$]+)\^", line)
            found.add(m.group(1) if m else line.split()[0])
    return found


def status(domain: str, resolver: str = RESOLVER) -> str:
    out = subprocess.run(["dig", f"@{resolver}", "+time=3", "+tries=2", "+noall", "+comments", domain, "SOA"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "status:" in line:
            return line.split("status:")[1].split(",")[0].strip()
    return "TIMEOUT"


def remove_dead(dead: list[tuple[str, str, str, str]]) -> list[str]:
    """Toglie le voci morte dai file manuali delle blocklist; restituisce le righe di riepilogo."""
    by_file: dict[str, set[str]] = {}
    for _, cat, name, _ in dead:
        by_file.setdefault(cat, set()).add(name)
    removed = []
    for cat, names in sorted(by_file.items()):
        path = DOMAINS_DIR / "blocklist" / f"{cat}.txt"
        kept = []
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = line.split("|")[0].strip().lower().removeprefix("*.")
            if line.strip() and not line.startswith("#") and entry in names:
                removed.append(f"- `{entry}` tolto da domains/blocklist/{cat}.txt")
                continue
            kept.append(line)
        path.write_text("\n".join(kept) + "\n", encoding="utf-8", newline="\n")
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fix", action="store_true", help="toglie i domini morti dalle blocklist manuali")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    entries: list[tuple[str, str, str]] = []
    for kind, sub in KINDS.items():
        for path in sorted((DOMAINS_DIR / sub).glob("*.txt")):
            if path.stem == "tld":
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append((kind, path.stem, line.split("|")[0].strip().lower().removeprefix("*.")))
    # Il controllo bypass include le wildcard; la risoluzione DNS solo i nomi esatti e validi: una riga
    # arbitraria (es. '-f/percorso' in una PR) diventerebbe un'opzione di dig
    targets = [e for e in entries if DOMAIN_RE.match(e[2])]
    own = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("own_domains", [])
    bypass = {d for d in bypass_domains() if not any(covers(o, d) for o in own)}
    bypass_hits = [(cat, name, sorted(d for d in bypass if covers(name, d))[:5])
                   for kind, cat, name in entries if kind == "allow"]
    bypass_hits = [h for h in bypass_hits if h[2]]

    with cf.ThreadPoolExecutor(16) as ex:
        results = list(ex.map(lambda t: (*t, status(t[2])), targets))

    bad_allow = [r for r in results if r[0] == "allow" and r[3] != "NOERROR"]
    candidates = [r for r in results if r[0] == "block" and r[3] == "NXDOMAIN"]
    with cf.ThreadPoolExecutor(16) as ex:
        confirmed = list(ex.map(lambda r: status(r[2], CONFIRM_RESOLVER) == "NXDOMAIN", candidates))
    dead_block = [r for r, ok in zip(candidates, confirmed) if ok]
    report = [f"## Verifica liste curate ({len(results)} domini, {len(bypass)} domini di bypass)", ""]
    if bypass_hits:
        report += ["### Allowlist che sbloccano domini di bypass DNS/VPN/proxy (da togliere)", ""]
        report += [f"- `{name}` ({cat}) sblocca: {', '.join(ds)}" for cat, name, ds in bypass_hits] + [""]
    if bad_allow:
        report += ["### Allowlist: domini inesistenti o irrisolvibili (probabile refuso)", ""]
        report += [f"- `{d}` ({cat}): {st}" for _, cat, d, st in bad_allow] + [""]
    if dead_block:
        report += ["### Blocklist: domini non più esistenti (NXDOMAIN su due resolver)", ""]
        if args.fix:
            report += remove_dead(dead_block) + [""]
        else:
            report += [f"- `{d}` ({cat})" for _, cat, d, _ in dead_block] + [""]
    if not bad_allow and not dead_block and not bypass_hits:
        report.append("Nessun problema trovato.")
    text = "\n".join(report)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if bad_allow or bypass_hits else 0


if __name__ == "__main__":
    sys.exit(main())
