#!/usr/bin/env python3
"""Genera le liste domini curate da domains/allowlist/ e domains/blocklist/ (config: domains/domains.toml).

Output:
  dist/adguard/allow-<cat>.txt, allow-base.txt   '@@||dominio^$important'
  dist/adguard/block-<cat>.txt                   '||dominio^'
  dist/domains/block-<cat>.txt                   domini semplici (pfBlockerNG, OPNsense)
  dist/unbound/block-<cat>.conf                  local-zone always_nxdomain
  dist/adguard/README.md                         feed + catalogo liste upstream (domains/upstream.toml)
  dist/adguard/block-<cat>-strict.txt (+ dist/domains/) livello strict, dist/perche/ indice «Perché è bloccato?»
                                                 (scripts/punteggio.py, configurazione [punteggio])

Uso: python scripts/build_domains.py [--check] [--offline] [--report FILE]
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import os
import re
import sys
import tomllib
from datetime import date
from pathlib import Path

import punteggio
from build_ip import EMAIL_RE, RAW_BASE, ROOT, SOURCE_ID_RE, TICKET_RE, contains_pii, fail, fetch, valid_date, warn

DOMAINS_DIR = ROOT / "domains"
CACHE_DIR = DOMAINS_DIR / "cache"
CONFIG_PATH = DOMAINS_DIR / "domains.toml"
EXCLUDE_PATH = DOMAINS_DIR / "escludi.txt"  # esclusioni di cura dalle fonti esterne
UPSTREAM_PATH = DOMAINS_DIR / "upstream.toml"
PSL_CACHE = CACHE_DIR / "psl-private.txt"  # sezione privata della Public Suffix List (MPL-2.0)
ADGUARD_DIR = ROOT / "dist" / "adguard"
PLAIN_DIR = ROOT / "dist" / "domains"
UNBOUND_DIR = ROOT / "dist" / "unbound"
KINDS = {"allow": "allowlist", "block": "blocklist"}
SOURCE_FORMATS = ("domains", "adblock", "ublock", "hosts", "tweetfeed")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
# Pattern AdGuard con '*' dentro un'etichetta (es. *-pa.googleapis.com): solo output AdGuard
PATTERN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9*_-]+(?:\.[a-z0-9_-]+)+$")
TLD_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
ADBLOCK_RE = re.compile(r"^\|\|([^\^/$|]+)\^(?:\$(.+))?$")
IDNA_DEVIATIONS = frozenset("\u00df\u03c2\u200c\u200d")  # ß, ς, ZWNJ, ZWJ


def normalize(token: str) -> str:
    token = token.strip().lower().rstrip(".")
    if token.startswith("*."):
        token = token[2:]
    if "*" in token:
        return token
    if token.isascii():
        return token  # caso comune: il codec idna non cambia un nome ASCII (etichette vuote o lunghe le scarta DOMAIN_RE)
    if any(c in IDNA_DEVIATIONS for c in token):
        # il codec idna di Python è IDNA 2003: 'faß.de' diventerebbe 'fass.de', un dominio diverso
        raise UnicodeError(f"carattere con codifica ambigua tra IDNA 2003 e 2008 in '{token}'")
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


def parse_domain_text(text: str, fmt: str) -> tuple[set[str], int]:
    """Estrae domini da liste 'domains', 'adblock' (||dominio^), 'ublock' (anche $doc/$all), 'hosts' o 'tweetfeed' (CSV). Restituisce (domini, scartati)."""
    names: set[str] = set()
    rejected = 0
    if fmt == "tweetfeed":
        # CSV data,utente,tipo,valore,...: solo i domini (gli URL possono puntare a host condivisi)
        text = "\n".join(cols[3] for cols in csv.reader(io.StringIO(text)) if len(cols) >= 4 and cols[2] == "domain")
        fmt = "domains"
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line[0] in "#!":
            continue
        if fmt in ("adblock", "ublock"):
            m = ADBLOCK_RE.match(line)
            if not m:
                continue  # regole su percorsi, eccezioni o cosmetiche: non sono domini da bloccare
            opts = set(m.group(2).split(",")) if m.group(2) else set()
            # ublock: anche $doc/$document/$all (sito intero, come al DNS); mai regole limitate (domain=, 3p...)
            allowed = {"doc", "document", "all", "important"} if fmt == "ublock" else set()
            if any(o not in allowed and not o.startswith("reason=") for o in opts) or (opts and fmt == "adblock"):
                continue
            token = m.group(1)
        else:
            parts = line.split("#", 1)[0].split()
            if not parts:
                continue
            token = parts[1] if fmt == "hosts" and len(parts) > 1 else parts[0]
        try:
            name = normalize(token)
        except UnicodeError:
            name = ""
        if DOMAIN_RE.match(name):
            names.add(name)
        else:
            rejected += 1
    return names, rejected


def load_domain_source(src: dict, offline: bool, persist: bool, max_drop: float = 0.5) -> tuple[set[str], str]:
    """Fonte di una blocklist: file locale (path) o URL con cache e guardrail come i feed IP."""
    fmt = src.get("format", "domains")
    if "path" in src:
        names, rejected = parse_domain_text((ROOT / src["path"]).read_text(encoding="utf-8"), fmt)
        return names, f"locale, {len(names)} voci" + (f", scartate {rejected}" if rejected else "")
    cache_path = CACHE_DIR / f"{src['id']}.txt"
    cached: set[str] = set()
    if cache_path.exists():
        cached, _ = parse_domain_text(cache_path.read_text(encoding="utf-8"), "domains")
    if offline:
        return cached, f"cache, {len(cached)} voci"
    try:
        names, rejected = parse_domain_text(fetch(src["url"]), fmt)
        if not names:
            raise ValueError("nessuna voce valida")
        if cached and len(names) < len(cached) * (1 - max_drop):
            raise ValueError(f"calo sospetto {len(cached)} → {len(names)} voci")
    except Exception as exc:  # qualsiasi errore di rete/parsing: si ripiega sulla cache
        warn(f"fonte {src['id']}: {exc}; uso la cache ({len(cached)} voci)")
        return cached, f"cache ({exc}), {len(cached)} voci"
    if persist:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("".join(f"{d}\n" for d in sorted(names)), encoding="utf-8", newline="\n")
    return names, f"ok, {len(names)} voci" + (f", scartate {rejected}" if rejected else "")


def parse_psl_private(text: str) -> set[str]:
    """Suffissi della sezione privata della PSL: piattaforme dove chiunque crea sottodomini
    (github.io, pages.dev, blogspot.com...). Le regole *.x diventano x, le eccezioni !x si ignorano."""
    found: set[str] = set()
    inside = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// ===BEGIN PRIVATE DOMAINS==="):
            inside = True
        elif line.startswith("// ===END PRIVATE DOMAINS==="):
            break
        elif inside and line and not line.startswith(("//", "!")):
            try:
                name = normalize(line.split()[0])
            except UnicodeError:
                continue
            if DOMAIN_RE.match(name):
                found.add(name)
    return found


def load_psl(cfg: dict, offline: bool, persist: bool) -> tuple[set[str], str]:
    """Suffissi privati PSL con cache e guardrail di calo come le altre fonti."""
    cached = set(parse_domain_text(PSL_CACHE.read_text(encoding="utf-8"), "domains")[0]) if PSL_CACHE.exists() else set()
    url = cfg.get("psl_url")
    if offline or not url:
        return cached, f"cache, {len(cached)} suffissi"
    try:
        names = parse_psl_private(fetch(url))
        if not names or (cached and len(names) < len(cached) * 0.5):
            raise ValueError(f"calo sospetto {len(cached)} → {len(names)} suffissi")
    except Exception as exc:  # errore di rete/parsing: si ripiega sulla cache
        warn(f"Public Suffix List: {exc}; uso la cache ({len(cached)} suffissi)")
        return cached, f"cache ({exc}), {len(cached)} suffissi"
    if persist:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        PSL_CACHE.write_text(f"# Public Suffix List, sezione privata. Fonte: {url} (MPL-2.0)\n"
                             + "".join(f"{d}\n" for d in sorted(names)), encoding="utf-8", newline="\n")
    return names, f"ok, {len(names)} suffissi"


def covered_by(name: str, pool) -> bool:
    """True se un dominio padre di name (escluso name stesso) è in pool."""
    i = name.find(".")
    while i != -1:  # senza split/join: le liste hanno centinaia di migliaia di voci
        if name[i + 1:] in pool:
            return True
        i = name.find(".", i + 1)
    return False


def drop_covered(names: set[str]) -> list[str]:
    """Rimuove i sottodomini già coperti da un dominio padre presente in lista."""
    return sorted((d for d in names if not covered_by(d, names)), key=lambda d: d.split(".")[::-1])


def covers(rule: str, host: str) -> bool:
    """True se la regola (dominio o pattern con '*') copre host o un suo sottodominio."""
    if "*" in rule:
        return fnmatch.fnmatch(host, rule) or fnmatch.fnmatch(host, f"*.{rule}")
    return host == rule or host.endswith(f".{rule}")


def overlaps(a: str, b: str) -> bool:
    """True se una delle due voci copre l'altra (stesso dominio, padre o figlio)."""
    return covers(a, b) or covers(b, a)


def contribution(per_source: dict[str, dict[str, set[str]]], manual: dict[str, set[str]],
                 final: dict[str, set[str]]) -> list[str]:
    """Per ogni lista con più fonti: quante voci pubblicate arrivano solo da ciascuna fonte."""
    lines = ["## Contributo delle fonti", "",
             "Voci pubblicate che arrivano **solo** da una fonte: misura quanto una lista dipende da ciascuna.", "",
             "| Lista | Fonte | Voci esclusive | Quota |", "|---|---|---|---|"]
    for cat, sources in sorted(per_source.items()):
        named = dict(sources)
        if manual.get(cat):
            named["manuale"] = manual[cat]
        published = final[cat]
        for sid, names in sorted(named.items()):
            others = set().union(*(v for k, v in named.items() if k != sid))
            only = len((names - others) & published)
            share = 100 * only / len(published) if published else 0
            lines.append(f"| block-{cat} | {sid} | {only} | {share:.1f}% |")
    return lines + [""]


def render_readme(outputs: dict[str, tuple[str, str, int]], upstream: list[dict],
                  extra: list[str] | None = None) -> str:
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
        "## Liste upstream consigliate (abbonamento diretto su AdGuard)",
        "",
        "| Lista | Categoria | Licenza | Ambito | Note |",
        "|---|---|---|---|---|",
    ]
    for u in upstream:
        lines.append(f"| [{u['name']}]({u['url']}) | {u['category']} | {u['license']} | {u['ambito']} | {u.get('note', '')} |")
    lines += [""] + (extra or []) + ["Pubblicato sotto GPL-3.0.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="solo validazione, nessuna scrittura")
    parser.add_argument("--offline", action="store_true", help="fonti upstream solo dalla cache")
    parser.add_argument("--report", type=Path, help="aggiunge a questo file le variazioni anomale (report del build)")
    args = parser.parse_args()
    offline = args.offline or args.check
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    errors: list[str] = []
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    upstream = tomllib.loads(UPSTREAM_PATH.read_text(encoding="utf-8")).get("lists", [])
    for u in upstream:
        missing = {"name", "url", "category", "license", "ambito"} - u.keys()
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

    own = cfg.get("own_domains", [])
    source_report: list[str] = []
    collected: dict[tuple[str, str], tuple[set[str], int]] = {}  # (kind, cat) → (voci, scadute)
    for kind, sub in KINDS.items():
        cats = cfg.get(kind, {})
        for path in sorted((DOMAINS_DIR / sub).glob("*.txt")):
            if path.stem not in cats:
                errors.append(f"{path.relative_to(ROOT).as_posix()}: categoria '{path.stem}' non definita in [{kind}] di domains.toml")
        for cat, opts in cats.items():
            path = DOMAINS_DIR / sub / f"{cat}.txt"
            names, expired = (load(path, tld=opts.get("tld", False), today=today, errors=errors)
                              if path.exists() else ([], 0))
            collected[(kind, cat)] = (set(names), expired)
    # voci manuali delle blocklist: un conflitto con l'allowlist su queste è un errore
    manual = {cat: set(collected[("block", cat)][0]) for cat in cfg.get("block", {})}

    ids: set[str] = set()
    per_source: dict[str, dict[str, set[str]]] = {}  # categoria → fonte → voci (per il contributo delle fonti)
    for src in cfg.get("sources", []):
        sid, cat = src.get("id", "?"), src.get("category")
        if sid in ids:
            errors.append(f"domains.toml: fonte '{sid}' duplicata")
        ids.add(sid)
        if ("block", cat) not in collected:
            errors.append(f"domains.toml: fonte '{sid}' con categoria block inesistente '{cat}'")
            continue
        if not src.get("license") or not (src.get("path") or str(src.get("url", "")).startswith("https://")):
            errors.append(f"domains.toml: fonte '{sid}' senza licenza o senza URL HTTPS/path")
            continue
        if not SOURCE_ID_RE.match(str(sid)) or src.get("format", "domains") not in SOURCE_FORMATS:
            errors.append(f"domains.toml: fonte '{sid}' con id non valido o formato sconosciuto '{src.get('format')}'")
            continue
        names, status = load_domain_source(src, offline, persist=not args.check)
        collected[("block", cat)][0].update(names)
        per_source.setdefault(cat, {})[sid] = names
        source_report.append(f"- fonte `{sid}` ({cat}): {status}")
    # voci di ogni blocklist prima dei filtri: per l'indice «Perché è bloccato?» (voci tolte e motivo)
    raw = {cat: set(collected[("block", cat)][0]) for cat in cfg.get("block", {})}

    # Esclusioni di cura: nomi esatti tolti dalle voci delle fonti esterne (le voci manuali restano)
    curated = set(load(EXCLUDE_PATH, tld=False, today=today, errors=errors)[0]) if EXCLUDE_PATH.exists() else set()
    # Piattaforme (sezione privata PSL): nelle categorie con exclude_platforms il dominio della piattaforma
    # arrivato da una fonte esterna si toglie, i singoli sottodomini malevoli restano
    platforms: set[str] = set()
    if any(o.get("exclude_platforms") for o in cfg.get("block", {}).values()):
        platforms, status = load_psl(cfg, offline, persist=not args.check)
        source_report.append(f"- Public Suffix List (piattaforme): {status}")
        if not platforms:
            errors.append("Public Suffix List vuota: exclude_platforms non applicabile")
        for cat, opts in cfg.get("block", {}).items():
            if not opts.get("exclude_platforms"):
                continue
            names = collected[("block", cat)][0]
            dropped = (names & platforms) - manual[cat]
            names -= dropped
            if dropped:
                source_report.append(f"- piattaforme escluse da block/{cat}: {len(dropped)} ({', '.join(sorted(dropped)[:8])})")

    for cat in cfg.get("block", {}):
        names = collected[("block", cat)][0]
        dropped = (names & curated) - manual[cat]
        names -= dropped
        if dropped:
            source_report.append(f"- esclusioni di cura in block/{cat}: {len(dropped)} ({', '.join(sorted(dropped)[:5])})")

    for cat, opts in cfg.get("block", {}).items():
        names = collected[("block", cat)][0]
        for other in opts.get("exclude", []):
            names -= collected.get(("block", other), (set(), 0))[0]
        # I domini propri (es. dns.clanto.cloud) non devono mai finire in blocco
        names -= {n for n in names if any(covers(o, n) for o in own)}

    # Servizi protetti: tolti dalle blocklist (voce identica); se una blocklist ne contiene il dominio padre
    # la voce resta (AdGuard sblocca comunque con $important) e viene segnalata
    protected = {n for (kind, cat), (cat_names, _) in collected.items()
                 if kind == "allow" and cfg["allow"][cat].get("protect") for n in cat_names}
    protect_report: list[str] = []
    for cat in cfg.get("block", {}):
        names = collected[("block", cat)][0]
        removed = names & protected
        names -= removed
        protect_report += [f"- protetto `{d}` tolto da block/{cat}" for d in sorted(removed)]
        for p in protected:
            parts = p.split(".")
            parents = {".".join(parts[i:]) for i in range(1, len(parts) - 1)} & names
            protect_report += [f"- protetto `{p}` coperto dal padre `{x}` in block/{cat} (sbloccato solo su AdGuard)"
                               for x in sorted(parents)]

    # Un'allowlist non deve mai annullare una nostra blocklist (es. sbloccare nordvpn e bloccare le VPN).
    # Voce manuale in conflitto → errore. Voce da fonte upstream: tolta se l'allowlist la copre, segnalata se
    # ne è il dominio padre (AdGuard sblocca comunque l'host con $important). Ricerca per insiemi: le liste
    # dinamiche hanno centinaia di migliaia di voci.
    allow_items = [(cat, a) for (kind, cat), (cat_names, _) in collected.items()
                   if kind == "allow" and not cfg["allow"][cat].get("protect") for a in cat_names]
    allow_exact = {a: cat for cat, a in allow_items if "*" not in a}
    allow_wild = [(cat, a) for cat, a in allow_items if "*" in a]
    conflict_report: list[str] = []

    def suffixes(name: str) -> list[str]:
        parts = name.split(".")
        return [".".join(parts[i:]) for i in range(len(parts))]

    for cat in cfg.get("block", {}):
        names = collected[("block", cat)][0]
        # ordinamento solo delle voci da controllare, non dell'intera lista (centinaia di migliaia di voci)
        candidates = [b for b in names if b in allow_exact or covered_by(b, allow_exact)
                      or any(covers(a, b) for _, a in allow_wild)]
        for b in sorted(candidates):
            hits = [(allow_exact[s], s) for s in suffixes(b) if s in allow_exact]
            hits += [(acat, a) for acat, a in allow_wild if covers(a, b)]
            if not hits:
                continue
            acat, a = hits[0]
            if b in manual[cat]:
                errors.append(f"conflitto: allow/{acat} '{a}' contraddice block/{cat} '{b}'")
            else:
                names.discard(b)
                conflict_report.append(f"- `{b}` (fonte upstream) tolto da block/{cat}: in allow/{acat} '{a}'")
        for a, acat in allow_exact.items():
            for parent in suffixes(a)[1:]:
                if parent in names:
                    if parent in manual[cat]:
                        errors.append(f"conflitto: allow/{acat} '{a}' contraddice block/{cat} '{parent}'")
                    else:
                        conflict_report.append(f"- allow/{acat} `{a}` coperto da `{parent}` (fonte upstream) in "
                                               f"block/{cat}: sbloccato solo su AdGuard")

    # Punteggio per voce e livello strict (solo nuovi file: le liste complete restano l'unione delle fonti)
    ctx = punteggio.Contesto(curated, platforms, protected, {
        cat: names for (kind, cat), (names, _) in collected.items() if kind == "allow" and not cfg["allow"][cat].get("protect")},
        own, covers, drop_covered)
    livelli = punteggio.applica(cfg, raw, {cat: collected[("block", cat)][0] for cat in cfg.get("block", {})},
                                per_source, manual, ctx, normalize, scrivi=not args.check)
    errors += livelli.errori

    for (kind, cat), (name_set, expired) in collected.items():
        opts = cfg[kind][cat]
        names = sorted(name_set)
        final = drop_covered(name_set)
        important = opts.get("important", kind == "allow")
        suffix = "$important" if important else ""
        prefix = "@@||" if kind == "allow" else "||"
        fname = f"{kind}-{cat}.txt"
        outputs = opts.get("outputs", ["adguard", "domains", "unbound"])
        if "adguard" in outputs or kind == "allow":
            adguard[fname] = "".join(f"{prefix}{d}^{suffix}\n" for d in final)
        if kind == "block":
            simple = [d for d in final if "*" not in d]
            if "domains" in outputs:
                # Lista completa, senza deduplica per dominio padre: OPNsense risolve solo il nome esatto
                plain[fname] = "".join(f"{d}\n" for d in names if "*" not in d)
            if "unbound" in outputs:
                unbound[f"block-{cat}.conf"] = "".join(f'local-zone: "{d}." always_nxdomain\n' for d in simple)
        elif opts.get("in_base", True):
            base.update(names)
        meta[fname] = (opts.get("description", ""), fname if kind == "block" and "domains" in outputs else "",
                       len(final))
        print(f"- {kind}/{cat}: {len(final)} voci, {expired} scadute")

    print("\n".join(source_report + livelli.log))
    for line in protect_report + conflict_report:
        warn(line.lstrip("- ").replace("`", ""))
    print("\n".join(protect_report + conflict_report))

    final_base = drop_covered(base)
    adguard["allow-base.txt"] = "".join(f"@@||{d}^$important\n" for d in final_base)
    in_base = [c for c, o in cfg.get("allow", {}).items() if o.get("in_base", True)]
    meta = {"allow-base.txt": (f"Aggregato allowlist: {', '.join(in_base)}", "", len(final_base)), **meta, **livelli.meta}
    adguard.update(livelli.adguard)
    plain.update(livelli.plain)
    if livelli.anomalie:
        text = "\n".join(["### Variazioni anomale delle liste strict", ""] + [f"- {a}" for a in livelli.anomalie] + [""])
        warn(text.replace("\n", " "))
        if args.report:
            with open(args.report, "a", encoding="utf-8") as fh:
                fh.write("\n" + text)
    if gh_out := os.environ.get("GITHUB_OUTPUT"):
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"anomaly={'true' if livelli.anomalie else 'false'}\n")

    if not args.check:
        for directory, files, pattern in ((ADGUARD_DIR, adguard, "*.txt"), (PLAIN_DIR, plain, "*.txt"),
                                          (UNBOUND_DIR, unbound, "*.conf")):
            directory.mkdir(parents=True, exist_ok=True)
            for stale in directory.glob(pattern):
                # solo file generati da qui: dist/unbound contiene anche safesearch.conf (build_safesearch.py)
                if stale.name.startswith(("block-", "allow-")) and stale.name not in files:
                    stale.unlink()
            for name, content in files.items():
                (directory / name).write_text(content, encoding="utf-8", newline="\n")
        finals = {cat: collected[("block", cat)][0] for cat in cfg.get("block", {})}
        extra = contribution(per_source, manual, finals) + livelli.readme(
            {cat: meta[f"block-{cat}.txt"][2] for cat in livelli.strict})
        (ADGUARD_DIR / "README.md").write_text(render_readme(meta, upstream, extra), encoding="utf-8", newline="\n")

    for e in errors:
        fail(e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
