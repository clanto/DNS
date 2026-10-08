#!/usr/bin/env python3
"""Genera i feed IP per i firewall da fonti upstream (ip/sources.toml) e liste manuali (ip/custom/).

Uso:
  python scripts/build_ip.py              build completo (download + scrittura dist/ip)
  python scripts/build_ip.py --offline    build dalla cache, senza rete
  python scripts/build_ip.py --check      valida config e liste manuali, nessuna scrittura (CI su PR)
"""
from __future__ import annotations

import argparse
import bisect
import concurrent.futures as cf
import csv
import io
import ipaddress
import json
import os
import re
import socket
import sys
import tomllib
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import asn

ROOT = Path(__file__).resolve().parent.parent
IP_DIR = ROOT / "ip"
CONFIG_PATH = IP_DIR / "sources.toml"
CUSTOM_DIR = IP_DIR / "custom"
ALLOWLIST_PATH = IP_DIR / "allowlist.txt"
SHARED_PATH = IP_DIR / "condivisi.txt"
PROTECTED_PATH = ROOT / "domains" / "allowlist" / "protetti.txt"
CACHE_DIR = IP_DIR / "cache"
DIST_DIR = ROOT / "dist" / "ip"
RAW_BASE = "https://raw.githubusercontent.com/clanto/DNS/main"
USER_AGENT = "clanto-dns-ip-builder/1.0 (+https://github.com/clanto/DNS)"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
FAMILIES = (4, 6)

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TICKET_RE = re.compile(r"^[A-Za-z0-9#._/-]{1,40}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
PHONE_RE = re.compile(r"\+?\d[\d /-]{7,}\d")
IN_GHA = os.environ.get("GITHUB_ACTIONS") == "true"

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Entry:
    net: Network
    added: str
    reason: str
    ticket: str
    expires: str
    origin: str


@dataclass
class SourceResult:
    id: str
    category: str
    license: str
    homepage: str
    enabled: bool
    status: str
    entries: int
    detail: str = ""


def warn(msg: str) -> None:
    print(f"::warning::{msg}" if IN_GHA else f"ATTENZIONE: {msg}", file=sys.stderr)


def fail(msg: str) -> None:
    print(f"::error::{msg}" if IN_GHA else f"ERRORE: {msg}", file=sys.stderr)


def sort_key(net: Network) -> tuple[int, int, int]:
    return net.version, int(net.network_address), net.prefixlen


def fmt(net: Network) -> str:
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def parse_token(token: str) -> list[Network]:
    """Accetta IP singolo, CIDR o intervallo 'a-b'."""
    if "-" in token and "/" not in token:
        start, end = (ipaddress.ip_address(p.strip()) for p in token.split("-", 1))
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(token, strict=False)]


def reject_reason(net: Network, min_prefix: dict[int, int]) -> str | None:
    if (net.is_private or net.is_multicast or net.is_reserved or net.is_loopback
            or net.is_link_local or net.is_unspecified or not net.is_global):
        return "non instradabile"
    if net.prefixlen < min_prefix[net.version]:
        return "troppo ampia"
    return None


def parse_source_text(text: str, min_prefix: dict[int, int] | None) -> tuple[set[Network], Counter]:
    """Estrae le reti da liste plain, hosts, 'IP # commento', 'CIDR ; SBL' e JSON per riga.

    min_prefix None = nessun filtro (categorie con reti riservate, es. bogon).
    """
    nets: set[Network] = set()
    rejected: Counter = Counter()
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line[0] in "#;!":
            continue
        if line.startswith("{"):
            try:
                token = json.loads(line).get("cidr")
            except json.JSONDecodeError:
                token = None
            if not token:
                continue
        else:
            token = re.split(r"[#;\s,]", line, maxsplit=1)[0]
        try:
            parsed = parse_token(token)
        except (ValueError, TypeError):
            rejected["non valida"] += 1
            continue
        for net in parsed:
            reason = reject_reason(net, min_prefix) if min_prefix is not None else None
            if reason:
                rejected[reason] += 1
            else:
                nets.add(net)
    return nets, rejected


def onionoo_to_text(text: str) -> str:
    """Converte la risposta Onionoo (relay Tor) in un IP per riga: or_addresses è 'ip:porta' o '[ipv6]:porta'."""
    relays = json.loads(text).get("relays", [])
    return "\n".join(addr.rsplit(":", 1)[0].strip("[]") for r in relays for addr in r.get("or_addresses", []))


def tweetfeed_to_text(text: str, kind: str) -> str:
    """TweetFeed CSV (data,utente,tipo,valore,tag,tweet): solo i valori del tipo richiesto (ip o domain)."""
    return "\n".join(cols[3].strip() for cols in csv.reader(io.StringIO(text)) if len(cols) >= 4 and cols[2] == kind)


def valid_date(value: str) -> bool:
    if not DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def contains_pii(text: str) -> bool:
    if EMAIL_RE.search(text):
        return True
    return any(sum(c.isdigit() for c in m.group()) >= 9 for m in PHONE_RE.finditer(text))


def load_annotated(path: Path, *, min_prefix: dict[int, int] | None, today: date,
                   errors: list[str]) -> tuple[list[Entry], int]:
    """Legge un file 'IP | data | motivo | ticket | scadenza'. Restituisce (voci attive, voci scadute)."""
    entries: list[Entry] = []
    seen: dict[Network, str] = {}
    expired = 0
    rel = path.relative_to(ROOT).as_posix()
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{rel}:{no}"
        fields = [f.strip() for f in line.split("|")]
        if not 3 <= len(fields) <= 5:
            errors.append(f"{where}: formato atteso 'IP/CIDR | AAAA-MM-GG | motivo | ticket | scadenza'")
            continue
        token, added, reason, ticket, expires = fields + [""] * (5 - len(fields))
        try:
            nets = parse_token(token)
        except (ValueError, TypeError):
            errors.append(f"{where}: indirizzo non valido '{token}'")
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
        for net in nets:
            if min_prefix is not None and (bad := reject_reason(net, min_prefix)):
                errors.append(f"{where}: {net} {bad}")
                continue
            if net in seen:
                errors.append(f"{where}: {net} duplicato di {seen[net]}")
                continue
            seen[net] = where
            entries.append(Entry(net, added, reason, ticket or "-", expires, where))
    return entries, expired


def load_config(errors: list[str]) -> dict:
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg.setdefault("settings", {})
    categories = cfg.get("categories", {})
    ids: set[str] = set()
    for src in cfg.get("sources", []):
        sid = src.get("id", "?")
        if sid in ids:
            errors.append(f"sources.toml: id duplicato '{sid}'")
        ids.add(sid)
        if src.get("category") not in categories:
            errors.append(f"sources.toml: fonte '{sid}' con categoria inesistente '{src.get('category')}'")
        if not str(src.get("url", "")).startswith("https://"):
            errors.append(f"sources.toml: fonte '{sid}' deve usare HTTPS")
        if not src.get("license"):
            errors.append(f"sources.toml: fonte '{sid}' senza licenza dichiarata")
        if src.get("format", "text") not in ("text", "onionoo", "asn", "tweetfeed"):
            errors.append(f"sources.toml: fonte '{sid}' con formato sconosciuto '{src.get('format')}'")
    for name, agg in cfg.get("aggregates", {}).items():
        if name in categories:
            errors.append(f"sources.toml: aggregato '{name}' ha lo stesso nome di una categoria")
        for c in agg.get("categories", []):
            if c not in categories or categories[c].get("reserved"):
                errors.append(f"sources.toml: aggregato '{name}' con categoria non valida '{c}'")
    return cfg


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download oltre 50 MB")
    return data.decode("utf-8", errors="replace")


def load_source(src: dict, settings: dict, offline: bool, persist: bool,
                raw: bool = False) -> tuple[set[Network], SourceResult]:
    min_prefix = None if raw else {
        4: src.get("min_prefix_v4", settings.get("min_prefix_v4", 16)),
        6: src.get("min_prefix_v6", settings.get("min_prefix_v6", 32)),
    }
    result = SourceResult(src["id"], src["category"], src["license"], src.get("homepage", ""),
                          src.get("enabled", True), "disattivata", 0, src.get("note", ""))
    if not result.enabled:
        return set(), result
    cache_path = CACHE_DIR / f"{src['id']}.txt"
    cached: set[Network] = set()
    if cache_path.exists():
        cached, _ = parse_source_text(cache_path.read_text(encoding="utf-8"), min_prefix)
    if offline:
        result.status, result.entries = "cache", len(cached)
        return cached, result
    try:
        if src.get("format") == "asn":
            # Reti annunciate dagli AS indicati (iptoasn.com): url documenta la fonte
            text = "\n".join(str(n) for n in asn.networks(src["asns"]))
        else:
            text = fetch(src["url"])
        if src.get("format") == "onionoo":
            text = onionoo_to_text(text)
        elif src.get("format") == "tweetfeed":
            text = tweetfeed_to_text(text, "ip")
        nets, rejected = parse_source_text(text, min_prefix)
        if not nets:
            raise ValueError("nessuna voce valida")
        drop = settings.get("max_drop_ratio", 0.5)
        if cached and len(nets) < len(cached) * (1 - drop):
            raise ValueError(f"calo sospetto {len(cached)} → {len(nets)} voci")
    except Exception as exc:  # qualsiasi errore di rete/parsing: si ripiega sulla cache
        warn(f"fonte {src['id']}: {exc}; uso la cache ({len(cached)} voci)")
        result.status = "cache" if cached else "fallita"
        result.entries = len(cached)
        result.detail = str(exc)
        return cached, result
    if persist:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("".join(f"{fmt(n)}\n" for n in sorted(nets, key=sort_key)),
                              encoding="utf-8", newline="\n")
    result.status, result.entries = "ok", len(nets)
    if rejected:
        result.detail = ", ".join(f"scartate {v} {k}" for k, v in sorted(rejected.items()))
    return nets, result


def load_shared(cfg: dict, errors: list[str]) -> list[Network]:
    """Intervalli di CDN/hosting condivisi: fonti ufficiali + ip/condivisi.txt. Solleva eccezione se non raggiungibili."""
    nets: list[Network] = []
    keep: list[Network] = []
    for src in cfg.get("shared_sources", []):
        fmt_ = src.get("format", "text")
        keep += [ipaddress.ip_network(k) for k in src.get("keep", [])]
        if fmt_ == "asn":
            asn_nets = asn.networks(src["asns"])
            if not asn_nets:
                raise ValueError(f"intervalli condivisi '{src['id']}' vuoti")
            nets += asn_nets
            continue
        text = fetch(src["url"])
        if fmt_ == "aws":
            data = json.loads(text)
            services = set(src.get("services", []))
            cidrs = [p["ip_prefix"] for p in data["prefixes"] if p["service"] in services]
            cidrs += [p["ipv6_prefix"] for p in data["ipv6_prefixes"] if p["service"] in services]
        elif fmt_ == "fastly":
            data = json.loads(text)
            cidrs = data.get("addresses", []) + data.get("ipv6_addresses", [])
        elif fmt_ == "google":
            data = json.loads(text)
            cidrs = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in data["prefixes"]]
        else:
            cidrs = text.split()
        if not cidrs:
            raise ValueError(f"intervalli condivisi '{src['id']}' vuoti")
        src_nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        # subtract_url: reti da togliere (es. clienti Google Cloud, che hanno IP dedicati)
        if src.get("subtract_url"):
            sub = json.loads(fetch(src["subtract_url"])) if fmt_ == "google" else None
            minus = [ipaddress.ip_network(p.get("ipv4Prefix") or p.get("ipv6Prefix")) for p in sub["prefixes"]] \
                if sub else [ipaddress.ip_network(c, strict=False) for c in fetch(src["subtract_url"]).split()]
            src_nets = [n for v in FAMILIES for n in subtract(
                list(ipaddress.collapse_addresses(x for x in src_nets if x.version == v)),
                list(ipaddress.collapse_addresses(m for m in minus if m.version == v)))[0]]
        nets += src_nets
    if SHARED_PATH.exists():
        entries, _ = load_annotated(SHARED_PATH, min_prefix=None, today=date.today(), errors=errors)
        nets += [e.net for e in entries]
    merged = [n for v in FAMILIES for n in ipaddress.collapse_addresses(x for x in nets if x.version == v)]
    # keep vale su tutte le fonti: reti che restano bloccabili anche dentro un'infrastruttura condivisa
    # (es. 8.8.8.8 è sia in goog.json sia nell'AS15169)
    if keep:
        merged = [n for v in FAMILIES for n in subtract(
            [x for x in merged if x.version == v],
            list(ipaddress.collapse_addresses(k for k in keep if k.version == v)))[0]]
    return merged


def resolve_protected() -> dict[Network, set[str]]:
    """IP attuali dei servizi protetti (domains/allowlist/protetti.txt) → host che li usano."""
    if not PROTECTED_PATH.exists():
        return {}
    hosts = [line.split("|")[0].strip().lower() for line in PROTECTED_PATH.read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]

    def lookup(host: str) -> list[tuple[Network, str]]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
        return [(ipaddress.ip_network(a), host) for a in addrs if a.is_global]

    out: dict[Network, set[str]] = {}
    with cf.ThreadPoolExecutor(32) as ex:
        for pairs in ex.map(lookup, hosts):
            for net, host in pairs:
                out.setdefault(net, set()).add(host)
    return out


class NetIndex:
    """Ricerca veloce (binaria) delle reti di un insieme che si sovrappongono a una rete data."""

    def __init__(self, nets) -> None:
        nets = list(nets)  # può arrivare un generatore: va letto una volta per famiglia IP
        self._idx = {}
        for v in FAMILIES:
            col = list(ipaddress.collapse_addresses(n for n in nets if n.version == v))
            self._idx[v] = ([int(n.network_address) for n in col], [int(n.broadcast_address) for n in col], col)

    def overlapping(self, net: Network) -> list[Network]:
        starts, ends, col = self._idx[net.version]
        lo, hi = int(net.network_address), int(net.broadcast_address)
        i = bisect.bisect_right(starts, hi) - 1
        found = []
        # reti accorpate: ordinate e disgiunte, quindi anche le fine sono crescenti
        while i >= 0 and ends[i] >= lo:
            found.append(col[i])
            i -= 1
        return found

    def overlaps(self, net: Network) -> bool:
        return bool(self.overlapping(net))


def subtract(nets: list[Network], allow: list[Network]) -> tuple[list[Network], int]:
    """Rimuove le reti in allowlist, spezzando i CIDR che le contengono."""
    out: list[Network] = []
    touched = 0
    index = NetIndex(allow)
    for net in nets:
        pieces = [net]
        for a in index.overlapping(net):
            if a.version != net.version:
                continue
            nxt: list[Network] = []
            for p in pieces:
                if not p.overlaps(a):
                    nxt.append(p)
                elif not p.subnet_of(a):
                    nxt.extend(p.address_exclude(a))
            pieces = nxt
        if pieces != [net]:
            touched += 1
        out.extend(pieces)
    return out, touched


def finalize(nets: set[Network], allow: list[Network], version: int) -> tuple[list[Network], int]:
    same = [n for n in nets if n.version == version]
    collapsed = list(ipaddress.collapse_addresses(same))
    cleaned, touched = subtract(collapsed, allow)
    return sorted(ipaddress.collapse_addresses(cleaned), key=sort_key), touched


def count_lines(path: Path) -> int | None:
    if not path.exists():
        return None
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def render_readme(cfg: dict, outputs: dict[str, list[Network]], sources: list[SourceResult],
                  custom: dict[str, dict]) -> str:
    base = f"{RAW_BASE}/dist/ip"
    lines = [
        "# Feed IP per firewall",
        "",
        "> File generato da `scripts/build_ip.py`: **non modificare a mano**.",
        "> Fonti in [`ip/sources.toml`](../../ip/sources.toml), voci manuali in [`ip/custom/`](../../ip/custom/),",
        "> esclusioni in [`ip/allowlist.txt`](../../ip/allowlist.txt).",
        "",
        "## Feed",
        "",
        "| Feed | Descrizione | IPv4 | IPv6 |",
        "|---|---|---|---|",
    ]
    rows = [(n, f"{a.get('description', '')} — aggregato: {', '.join(a['categories'])}")
            for n, a in cfg.get("aggregates", {}).items()]
    rows += [(c, m.get("description", "")) for c, m in cfg["categories"].items()]
    for name, desc in rows:
        v4, v6 = f"{name}-v4.txt", f"{name}-v6.txt"
        lines.append(f"| `{name}` | {desc} | [{len(outputs[v4])}]({base}/{v4}) | [{len(outputs[v6])}]({base}/{v6}) |")
    lines += ["", "## Fonti", "", "| ID | Categoria | Licenza | Stato | Voci | Note |", "|---|---|---|---|---|---|"]
    for s in [s for s in sources if s.enabled]:
        sid = f"[{s.id}]({s.homepage})" if s.homepage else s.id
        lines.append(f"| {sid} | {s.category} | {s.license} | {s.status} | {s.entries} | {s.detail} |")
    lines += ["", "## Voci manuali", "", "| Categoria | Attive | Scadute |", "|---|---|---|"]
    for cat, st in sorted(custom.items()):
        lines.append(f"| {cat} | {st['attive']} | {st['scadute']} |")
    lines += ["", "Pubblicato sotto GPL-3.0. Attribuzioni: vedi tabella Fonti.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="solo validazione, nessuna scrittura")
    parser.add_argument("--offline", action="store_true", help="usa solo la cache locale")
    parser.add_argument("--report", type=Path, help="scrive il report markdown in questo file")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    offline = args.offline or args.check
    write = not args.check

    errors: list[str] = []
    cfg = load_config(errors)
    settings, categories = cfg["settings"], cfg.get("categories", {})
    min_prefix = {4: settings.get("min_prefix_v4", 16), 6: settings.get("min_prefix_v6", 32)}
    today = date.today()

    per_cat: dict[str, set[Network]] = {c: set() for c in categories}
    custom_stats: dict[str, dict] = {}
    for path in sorted(CUSTOM_DIR.glob("*.txt")):
        if path.stem not in categories:
            errors.append(f"{path.relative_to(ROOT).as_posix()}: categoria '{path.stem}' non definita in sources.toml")
            continue
        reserved = categories[path.stem].get("reserved", False)
        entries, expired = load_annotated(path, min_prefix=None if reserved else min_prefix,
                                          today=today, errors=errors)
        per_cat[path.stem].update(e.net for e in entries)
        custom_stats[path.stem] = {"attive": len(entries), "scadute": expired}

    allow_entries, _ = load_annotated(ALLOWLIST_PATH, min_prefix=None, today=today, errors=errors)
    allow = [e.net for e in allow_entries]

    source_results: list[SourceResult] = []
    outputs: dict[str, list[Network]] = {}
    for src in cfg.get("sources", []):
        if src.get("category") not in categories:
            continue
        reserved = categories[src["category"]].get("reserved", False)
        nets, res = load_source(src, settings, offline, persist=write, raw=reserved)
        per_cat[src["category"]].update(nets)
        source_results.append(res)

    shared: list[Network] = []
    if any(m.get("exclude_shared") for m in categories.values()):
        if args.check:
            # Solo validazione, nessuna scrittura: basta il file manuale
            shared = [e.net for e in load_annotated(SHARED_PATH, min_prefix=None, today=today, errors=errors)[0]] \
                if SHARED_PATH.exists() else []
        else:
            # Anche con --offline: un feed scritto senza filtro bloccherebbe siti legittimi.
            # Errore di rete → il build fallisce prima di scrivere, restano i feed precedenti.
            shared = load_shared(cfg, errors)

    shared_hits = 0
    shared_index = NetIndex(shared)
    for cat, meta in categories.items():
        if meta.get("exclude_shared"):
            before = len(per_cat[cat])
            per_cat[cat] = {n for n in per_cat[cat] if not shared_index.overlaps(n)}
            shared_hits += before - len(per_cat[cat])

    # Servizi protetti: i loro IP attuali non devono mai finire nei feed (solo in build, serve DNS).
    # Segnalati solo quelli rimasti dopo il filtro delle infrastrutture condivise: sono falsi positivi nuovi.
    protected = {} if args.check else resolve_protected()
    protected_hits: list[str] = []
    for cat, meta in categories.items():
        if meta.get("reserved") or not protected:
            continue
        cat_index = NetIndex(per_cat[cat])
        for p, hosts in protected.items():
            protected_hits += [f"{cat}: {n} usato da {', '.join(sorted(hosts))}" for n in cat_index.overlapping(p)]
    for hit in protected_hits:
        warn(f"servizio protetto nelle fonti, escluso: {hit}")
    allow = allow + list(protected)

    allow_hits = 0
    for cat, meta in categories.items():
        cat_allow = [] if meta.get("reserved") else allow
        for v in FAMILIES:
            outputs[f"{cat}-v{v}.txt"], touched = finalize(per_cat[cat], cat_allow, v)
            allow_hits += touched
    # Aggregati come unione dei feed di categoria già filtrati dall'allowlist
    for name, agg in cfg.get("aggregates", {}).items():
        valid = [c for c in agg.get("categories", []) if c in categories and not categories[c].get("reserved")]
        for v in FAMILIES:
            merged = (n for c in valid for n in outputs[f"{c}-v{v}.txt"])
            outputs[f"{name}-v{v}.txt"] = sorted(ipaddress.collapse_addresses(merged), key=sort_key)

    anomalies: list[str] = []
    threshold = settings.get("pr_threshold", 0.25)
    min_base = settings.get("anomaly_min_entries", 100)
    max_entries = settings.get("max_entries", 0)
    for name, nets in outputs.items():
        prev = count_lines(DIST_DIR / name)
        if prev and prev >= min_base and abs(len(nets) - prev) / prev > threshold:
            anomalies.append(f"`{name}`: {prev} → {len(nets)} voci")
        if max_entries and len(nets) > max_entries:
            anomalies.append(f"`{name}`: {len(nets)} voci oltre il limite max_entries={max_entries}")

    if write:
        DIST_DIR.mkdir(parents=True, exist_ok=True)
        for stale in DIST_DIR.glob("*.txt"):
            if stale.name not in outputs:
                stale.unlink()
        active = {f"{s['id']}.txt" for s in cfg.get("sources", []) if s.get("enabled", True)}
        for stale in CACHE_DIR.glob("*.txt"):
            if stale.name not in active:
                stale.unlink()
        for name, nets in outputs.items():
            (DIST_DIR / name).write_text("".join(f"{fmt(n)}\n" for n in nets), encoding="utf-8", newline="\n")
        for cat, meta in categories.items():
            for rel in meta.get("compat_v4", []):
                (ROOT / rel).write_text("".join(f"{fmt(n)}\n" for n in outputs[f"{cat}-v4.txt"]),
                                        encoding="utf-8", newline="\n")
        stats = {
            "feed": {name: len(nets) for name, nets in outputs.items()},
            "fonti": [vars(s) for s in source_results],
            "manuali": custom_stats,
            "allowlist": {"voci": len(allow), "reti_modificate": allow_hits},
            "condivisi": {"intervalli": len(shared), "voci_escluse": shared_hits},
            "protetti": {"ip_risolti": len(protected), "voci_escluse": protected_hits},
        }
        (DIST_DIR / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
                                             encoding="utf-8", newline="\n")
        (DIST_DIR / "README.md").write_text(render_readme(cfg, outputs, source_results, custom_stats),
                                            encoding="utf-8", newline="\n")

    report = ["## Build feed IP", ""]
    report += [f"- `{s.id}`: {s.status}, {s.entries} voci {s.detail}".rstrip() for s in source_results if s.enabled]
    report += [f"- allowlist: {len(allow)} voci, {allow_hits} reti modificate",
               f"- infrastrutture condivise: {len(shared)} intervalli, {shared_hits} voci escluse",
               f"- servizi protetti: {len(protected)} IP risolti, {len(protected_hits)} voci escluse dai feed", ""]
    if protected_hits:
        report += ["### Servizi protetti trovati nelle fonti (falsi positivi evitati)", ""]
        report += [f"- {h}" for h in protected_hits] + [""]
    if anomalies:
        report += ["### Variazioni anomale", ""] + [f"- {a}" for a in anomalies] + [""]
    if errors:
        report += ["### Errori nelle liste manuali (righe ignorate)", ""] + [f"- {e}" for e in errors] + [""]
    text = "\n".join(report)
    print(text)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if gh_out := os.environ.get("GITHUB_OUTPUT"):
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"anomaly={'true' if anomalies else 'false'}\nerrors={len(errors)}\n")
    for e in errors:
        fail(e)
    # In build le righe errate vengono saltate e i feed pubblicati comunque; il workflow fallisce dopo.
    return 1 if errors and args.check else 0


if __name__ == "__main__":
    sys.exit(main())
