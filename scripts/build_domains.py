#!/usr/bin/env python3
"""Genera le liste domini curate da domains/allowlist/ e domains/blocklist/ (config: domains/domains.toml).

Output:
  dist/adguard/allow-<cat>.txt, allow-base.txt   '@@||dominio^$important'
  dist/adguard/block-<cat>.txt                   '||dominio^'
  dist/domains/block-<cat>.txt                   domini semplici (pfBlockerNG, OPNsense)
  dist/unbound/block-<cat>.conf                  local-zone always_nxdomain
  dist/adguard/README.md                         feed + catalogo liste upstream (domains/upstream.toml)

Uso: python scripts/build_domains.py [--check]
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import tomllib
from datetime import date
from pathlib import Path

from build_ip import EMAIL_RE, RAW_BASE, ROOT, TICKET_RE, contains_pii, fail, valid_date

DOMAINS_DIR = ROOT / "domains"
CONFIG_PATH = DOMAINS_DIR / "domains.toml"
UPSTREAM_PATH = DOMAINS_DIR / "upstream.toml"
ADGUARD_DIR = ROOT / "dist" / "adguard"
PLAIN_DIR = ROOT / "dist" / "domains"
UNBOUND_DIR = ROOT / "dist" / "unbound"
KINDS = {"allow": "allowlist", "block": "blocklist"}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
# Pattern AdGuard con '*' dentro un'etichetta (es. *-pa.googleapis.com): solo output AdGuard
PATTERN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9*_-]+(?:\.[a-z0-9_-]+)+$")
TLD_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")


def normalize(token: str) -> str:
    token = token.strip().lower().rstrip(".")
    if token.startswith("*."):
        token = token[2:]
    if "*" in token:
        return token
    return token.encode("idna").decode("ascii")


def load(path: Path, *, tld: bool, today: date, errors: list[str]) -> tuple[list[str], int]:
    names: list[str] = []
    seen: dict[str, str] = {}
    expired = 0
    rel = path.relative_to(ROOT).as_posix()
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{rel}:{no}"
        fields = [f.strip() for f in line.split("|")]
        if not 3 <= len(fields) <= 5:
            errors.append(f"{where}: formato atteso 'dominio | AAAA-MM-GG | motivo | ticket | scadenza'")
            continue
        token, added, reason, ticket, expires = fields + [""] * (5 - len(fields))
        try:
            name = normalize(token)
        except UnicodeError:
            name = ""
        ok = TLD_RE.match(name) if tld else (DOMAIN_RE.match(name) or ("*" in name and PATTERN_RE.match(name)))
        if not ok:
            errors.append(f"{where}: {'TLD' if tld else 'dominio'} non valido '{token}'")
            continue
        if not valid_date(added):
            errors.append(f"{where}: data inserimento non valida '{added}' (AAAA-MM-GG)")
            continue
        if not reason:
            errors.append(f"{where}: motivo obbligatorio")
            continue
        if contains_pii(reason) or EMAIL_RE.search(ticket):
            errors.append(f"{where}: possibile dato personale nel motivo/ticket (ISO 27701): usare solo ID ticket")
            continue
        if ticket and ticket != "-" and not TICKET_RE.match(ticket):
            errors.append(f"{where}: ticket non valido '{ticket}'")
            continue
        if expires:
            if not valid_date(expires):
                errors.append(f"{where}: scadenza non valida '{expires}' (AAAA-MM-GG)")
                continue
            if date.fromisoformat(expires) < today:
                expired += 1
                continue
        if name in seen:
            errors.append(f"{where}: {name} duplicato di {seen[name]}")
            continue
        seen[name] = where
        names.append(name)
    return names, expired


def drop_covered(names: set[str]) -> list[str]:
    """Rimuove i sottodomini già coperti da un dominio padre presente in lista."""
    def covered(d: str) -> bool:
        parts = d.split(".")
        return any(".".join(parts[i:]) in names for i in range(1, len(parts)))
    return sorted((d for d in names if not covered(d)), key=lambda d: d.split(".")[::-1])


def covers(rule: str, host: str) -> bool:
    """True se la regola (dominio o pattern con '*') copre host o un suo sottodominio."""
    if "*" in rule:
        return fnmatch.fnmatch(host, rule) or fnmatch.fnmatch(host, f"*.{rule}")
    return host == rule or host.endswith(f".{rule}")


def overlaps(a: str, b: str) -> bool:
    """True se una delle due voci copre l'altra (stesso dominio, padre o figlio)."""
    return covers(a, b) or covers(b, a)


def render_readme(outputs: dict[str, tuple[str, str, int]], upstream: list[dict]) -> str:
    lines = [
        "# Liste domini per AdGuard",
        "",
        "> File generato da `scripts/build_domains.py`: **non modificare a mano**.",
        "> Voci in [`domains/allowlist/`](../../domains/allowlist/) e [`domains/blocklist/`](../../domains/blocklist/).",
        "",
        "In AdGuard Home: allowlist in *Filtri → Allowlist DNS*, blocklist in *Filtri → Blocklist DNS*.",
        "Le liste valgono per **tutti** i client: le policy (streaming, social, gaming, AI) vanno applicate",
        "solo su istanze dedicate ai clienti che le richiedono.",
        "",
        "## Liste pubblicate",
        "",
        "| Lista | Descrizione | Voci | AdGuard | Formato semplice |",
        "|---|---|---|---|---|",
    ]
    for name, (desc, plain, count) in outputs.items():
        adg = f"[adguard]({RAW_BASE}/dist/adguard/{name})"
        pl = f"[domini]({RAW_BASE}/dist/domains/{plain})" if plain else "—"
        lines.append(f"| `{name}` | {desc} | {count} | {adg} | {pl} |")
    lines += [
        "",
        "## Catalogo liste upstream (abbonamento diretto su AdGuard)",
        "",
        "| Lista | Categoria | Licenza | Stato | Note |",
        "|---|---|---|---|---|",
    ]
    for u in upstream:
        lines.append(f"| [{u['name']}]({u['url']}) | {u['category']} | {u['license']} | {u['status']} | {u.get('note', '')} |")
    lines += ["", "Pubblicato sotto GPL-3.0.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="solo validazione, nessuna scrittura")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    errors: list[str] = []
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    upstream = tomllib.loads(UPSTREAM_PATH.read_text(encoding="utf-8")).get("lists", [])
    for u in upstream:
        missing = {"name", "url", "category", "license", "status"} - u.keys()
        if missing:
            errors.append(f"upstream.toml: '{u.get('name', '?')}' senza {', '.join(sorted(missing))}")
    today = date.today()

    # nome file → (descrizione, file semplice o "", voci) per il README; contenuti separati
    meta: dict[str, tuple[str, str, int]] = {}
    adguard: dict[str, str] = {}
    plain: dict[str, str] = {}
    unbound: dict[str, str] = {}
    base: set[str] = set()
    entries: dict[str, list[tuple[str, str]]] = {"allow": [], "block": []}  # kind → (categoria, voce)

    for kind, sub in KINDS.items():
        cats = cfg.get(kind, {})
        for path in sorted((DOMAINS_DIR / sub).glob("*.txt")):
            cat = path.stem
            if cat not in cats:
                errors.append(f"{path.relative_to(ROOT).as_posix()}: categoria '{cat}' non definita in [{kind}] di domains.toml")
                continue
            opts = cats[cat]
            names, expired = load(path, tld=opts.get("tld", False), today=today, errors=errors)
            final = drop_covered(set(names))
            important = opts.get("important", kind == "allow")
            suffix = "$important" if important else ""
            prefix = "@@||" if kind == "allow" else "||"
            fname = f"{kind}-{cat}.txt"
            adguard[fname] = "".join(f"{prefix}{d}^{suffix}\n" for d in final)
            if kind == "block":
                entries["block"] += [(cat, d) for d in names]
                simple = [d for d in final if "*" not in d]
                plain[fname] = "".join(f"{d}\n" for d in simple)
                unbound[f"block-{cat}.conf"] = "".join(f'local-zone: "{d}." always_nxdomain\n' for d in simple)
            else:
                entries["allow"] += [(cat, d) for d in names]
                if opts.get("in_base", True):
                    base.update(names)
            meta[fname] = (opts.get("description", ""), fname if kind == "block" else "", len(final))
            print(f"- {kind}/{cat}: {len(final)} voci, {expired} scadute")

    # Un'allowlist non deve mai annullare una nostra blocklist (es. sbloccare nordvpn e bloccare le VPN)
    for acat, a in entries["allow"]:
        for bcat, b in entries["block"]:
            if overlaps(a, b):
                errors.append(f"conflitto: allow/{acat} '{a}' contraddice block/{bcat} '{b}'")

    final_base = drop_covered(base)
    adguard["allow-base.txt"] = "".join(f"@@||{d}^$important\n" for d in final_base)
    in_base = [c for c, o in cfg.get("allow", {}).items() if o.get("in_base", True)]
    meta = {"allow-base.txt": (f"Aggregato allowlist: {', '.join(in_base)}", "", len(final_base)), **meta}

    if not args.check:
        for directory, files, pattern in ((ADGUARD_DIR, adguard, "*.txt"), (PLAIN_DIR, plain, "*.txt"),
                                          (UNBOUND_DIR, unbound, "*.conf")):
            directory.mkdir(parents=True, exist_ok=True)
            for stale in directory.glob(pattern):
                if stale.name not in files:
                    stale.unlink()
            for name, content in files.items():
                (directory / name).write_text(content, encoding="utf-8", newline="\n")
        (ADGUARD_DIR / "README.md").write_text(render_readme(meta, upstream), encoding="utf-8", newline="\n")

    for e in errors:
        fail(e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
