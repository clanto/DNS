#!/usr/bin/env python3
"""Threat intelligence derivata: espansione dell'infrastruttura dei domini malevoli confermati.

Parte dai domini di block-malware, block-phishing e domains/blocklist/malevoli.txt (prima quelli presenti
in più fonti), ne risolve un campione limitato e propone come CANDIDATI:
  1. IP dedicati che ospitano più domini malevoli distinti → ip/custom/c2.txt
  2. domini nuovi sulla stessa infrastruttura, ricavati solo da dati nostri → domains/blocklist/malware.txt
     - nameserver i cui IP sono IP malevoli dedicati del punto 1
     - destinazioni CNAME comuni a più domini malevoli e ospitate solo su IP del punto 1

Un IP viene scartato se è in infrastrutture condivise (stesso filtro dei feed: CDN, hosting, ip/condivisi.txt,
AS di CDN, keep), è un sinkhole o un parcheggio, è di un servizio protetto o in ip/allowlist.txt, ospita
domini delle allowlist, ha PTR o AS di hosting condiviso, o non supera le soglie (ip/pivot.toml).
Nessun servizio esterno di passive DNS o reverse IP: vedi ip/README.md per le fonti valutate.

Le voci proposte hanno scadenza (expiry_days) e ticket "pivot-AAAAMMGG"; con --apply vengono aggiunte ai
file manuali e le voci derivate scadute vengono tolte. Il workflow pivot.yml le propone con una PR.
Le risoluzioni sono affidabili solo su una rete con DNS non filtrato (runner GitHub Actions).

Uso: python scripts/pivot_infra.py [--offline] [--apply] [--report FILE] [--json FILE]
"""
from __future__ import annotations

import argparse
import bisect
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

import asn
import build_domains as BD
from build_ip import (ALLOWLIST_PATH, CONFIG_PATH as IP_CONFIG, DIST_DIR, ROOT, NetIndex, contains_pii, fail, fmt,
                      load_annotated, load_shared, parse_source_text, resolve_protected, valid_date, warn)

PIVOT_CONFIG = ROOT / "ip" / "pivot.toml"
IP_TARGET = ROOT / "ip" / "custom" / "c2.txt"
DOMAIN_TARGET = BD.DOMAINS_DIR / "blocklist" / "malware.txt"
SEED_CATEGORIES = ("malware", "phishing")   # fonti upstream delle blocklist usate come semi
MANUAL_SEEDS = "malevoli"                     # voci manuali confermate da noi
TICKET_PREFIX = "pivot-"
NAT64 = ipaddress.ip_network("64:ff9b::/96")  # risposte sintetizzate da DNS64, non IP reali
COVERED_FEEDS = ("c2", "threat")              # IP già nei feed: non si ripropongono
MIN_RESOLVED_RATIO = 0.2                      # sotto questa quota di semi risolti si presume un problema DNS
MIN_ALIVE_RATIO = 0.05                        # quasi tutti NXDOMAIN: resolver che filtra i domini malevoli

DEFAULTS = {
    "max_seeds": 1500, "max_per_zone": 2, "min_sources_confirmed": 2, "max_legit": 400,
    "min_domains": 3, "min_confirmed": 1, "max_domains": 50, "max_ip_candidates": 100,
    "max_domain_candidates": 50, "expiry_days": 30, "max_queries": 8000, "qps": 40, "workers": 8,
    "timeout": 2.0, "max_seconds": 480, "sinkhole_ns": [], "sinkhole_ptr": [], "sinkhole_nets": [],
    "parking_ns": [], "shared_ptr": [], "shared_hosting_as": [],
}

Address = ipaddress.IPv4Address | ipaddress.IPv6Address

# ---------------------------------------------------------------------------
# Client DNS minimo (UDP, solo standard library): A, AAAA, NS, CNAME, SOA, PTR con rcode
# ---------------------------------------------------------------------------

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "AAAA": 28}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class Response:
    rcode: str
    answers: list[tuple[str, int, object]]    # (proprietario, tipo, valore)
    authority: list[tuple[str, int, object]]


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"etichetta non valida in '{name}'")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def build_query(qid: int, name: str, qtype: int) -> bytes:
    # flag 0x0100: richiesta ricorsiva standard
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, 1)


def read_name(data: bytes, pos: int) -> tuple[str, int]:
    """Nome DNS con compressione; restituisce (nome, posizione dopo il nome)."""
    labels: list[str] = []
    end = -1
    hops = 0
    while True:
        if pos >= len(data):
            raise ValueError("nome troncato")
        n = data[pos]
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("puntatore troncato")
            if end < 0:
                end = pos + 2
            hops += 1
            if hops > 30:
                raise ValueError("puntatori ciclici")
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            continue
        if n & 0xC0:
            raise ValueError("etichetta non supportata")
        if n == 0:
            return ".".join(labels), (end if end >= 0 else pos + 1)
        labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace").lower())
        pos += 1 + n


def parse_response(data: bytes, qid: int | None = None, qname: str | None = None,
                   qtype: int | None = None) -> Response:
    if len(data) < 12:
        raise ValueError("risposta troppo corta")
    rid, flags, qd, an, ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if qid is not None and rid != qid:
        raise ValueError("id di risposta diverso")
    if not flags & 0x8000:
        raise ValueError("non è una risposta")
    pos = 12
    for _ in range(qd):
        name, pos = read_name(data, pos)
        if pos + 4 > len(data):
            raise ValueError("domanda troncata")
        rtype = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 4
        # anti-spoofing minimo: la domanda deve essere quella inviata
        if (qname is not None and name != qname.rstrip(".").lower()) or (qtype is not None and rtype != qtype):
            raise ValueError("domanda diversa da quella inviata")
    sections: list[list[tuple[str, int, object]]] = []
    for count in (an, ns):
        recs: list[tuple[str, int, object]] = []
        for _ in range(count):
            owner, pos = read_name(data, pos)
            if pos + 10 > len(data):
                raise ValueError("record troncato")
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            start, pos = pos, pos + rdlen
            if pos > len(data):
                raise ValueError("dati del record troncati")
            if rtype == 1 and rdlen == 4:
                value: object = ipaddress.IPv4Address(data[start:pos])
            elif rtype == 28 and rdlen == 16:
                value = ipaddress.IPv6Address(data[start:pos])
            elif rtype in (2, 5, 6, 12):
                value = read_name(data, start)[0]  # per SOA conta il proprietario (apice della zona)
            else:
                continue
            recs.append((owner, rtype, value))
        sections.append(recs)
    return Response(RCODES.get(flags & 0xF, f"RCODE{flags & 0xF}"), sections[0], sections[1])


class BudgetExceeded(Exception):
    """Limite di query o di tempo raggiunto: non partono altre query."""


class Resolver:
    """Resolver con limite di query totali, di query al secondo e di tempo; cache per (nome, tipo)."""

    def __init__(self, server: str, *, qps: float, max_queries: int, timeout: float, deadline: float,
                 transport: Callable[[bytes], bytes] | None = None) -> None:
        self.server = server
        self.qps = max(float(qps), 0.1)
        self.max_queries = max_queries
        self.timeout = timeout
        self.deadline = deadline
        self.transport = transport or self._udp
        self.sent = 0
        self.failed = 0
        self._lock = threading.Lock()
        self._next = time.monotonic()
        self._cache: dict[tuple[str, str], Response | None] = {}

    def _udp(self, packet: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in self.server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:  # socket nuovo: porta sorgente casuale
            sock.settimeout(self.timeout)
            sock.connect((self.server, 53))
            sock.send(packet)
            return sock.recv(4096)

    def _slot(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self.sent >= self.max_queries or now > self.deadline:
                raise BudgetExceeded()
            self.sent += 1
            slot = max(now, self._next)
            self._next = slot + 1 / self.qps
        if slot > now:
            time.sleep(slot - now)

    def query(self, name: str, qtype: str) -> Response | None:
        key = (name, qtype)
        if key in self._cache:
            return self._cache[key]
        result = None
        for _ in range(2):
            self._slot()
            qid = secrets.randbits(16)
            try:
                result = parse_response(self.transport(build_query(qid, name, QTYPES[qtype])), qid, name,
                                        QTYPES[qtype])
                break
            except (OSError, ValueError):
                continue
        if result is None:
            with self._lock:
                self.failed += 1
        self._cache[key] = result
        return result


def system_resolver() -> str:
    """PIVOT_RESOLVER, altrimenti il resolver del sistema (runner: systemd-resolved), altrimenti 1.1.1.1."""
    candidates = [os.environ.get("PIVOT_RESOLVER", "")]
    try:
        candidates += [p[1] for p in (line.split() for line in Path("/etc/resolv.conf").read_text().splitlines())
                       if len(p) >= 2 and p[0] == "nameserver"]
    except OSError:
        pass
    for c in candidates:
        try:
            return str(ipaddress.ip_address(c.split("%")[0]))
        except ValueError:
            continue
    return "1.1.1.1"


# ---------------------------------------------------------------------------
# Osservazioni sui domini
# ---------------------------------------------------------------------------

CCSLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "ltd", "plc"}


def registrable_guess(name: str) -> str:
    """Dominio registrato approssimato (quando il DNS non indica l'apice della zona)."""
    parts = name.rstrip(".").lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in CCSLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def suffixes(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def routable(ip: Address) -> bool:
    return ip.is_global and ip not in NAT64


def matches(host: str, patterns: list[str]) -> bool:
    """Voce con punto = suffisso del nome (o nome esatto); senza punto = parola contenuta."""
    host = host.lower().rstrip(".")
    for p in patterns:
        p = p.lower()
        if "." in p:
            if host == p or host.endswith("." + p):
                return True
        elif p in host:
            return True
    return False


@dataclass
class Obs:
    name: str
    status: str = "ok"   # ok | morto | errore | non interrogato | sinkhole | parcheggio
    ips: set = field(default_factory=set)
    cnames: list = field(default_factory=list)
    zone: str = ""
    ns: set = field(default_factory=set)

    @property
    def domain(self) -> str:
        return self.zone or registrable_guess(self.name)


def zone_ns(resolver: Resolver, name: str) -> tuple[str, set[str]]:
    """Apice della zona e nameserver: NS sul nome, altrimenti la SOA in authority indica l'apice."""
    r = resolver.query(name, "NS")
    if r is None or r.rcode != "NOERROR":
        return "", set()
    ns = {v for o, t, v in r.answers if t == 2 and o == name}
    if ns:
        return name, ns
    soa = [o for o, t, _ in r.authority if t == 6]
    if soa and name.endswith("." + soa[0]):
        r2 = resolver.query(soa[0], "NS")
        return soa[0], ({v for o, t, v in r2.answers if t == 2} if r2 else set())
    return "", set()


def observe(resolver: Resolver, name: str, with_ns: bool = True) -> Obs:
    obs = Obs(name)
    try:
        r = resolver.query(name, "A")
        if r is None:
            obs.status = "errore"
            return obs
        if r.rcode == "NXDOMAIN":
            obs.status = "morto"
            return obs
        if r.rcode != "NOERROR":
            obs.status = "errore"
            return obs
        r6 = resolver.query(name, "AAAA")
        for resp in (r, r6):
            for _, t, v in (resp.answers if resp else []):
                if t in (1, 28):
                    obs.ips.add(v)
                elif t == 5 and v not in obs.cnames:
                    obs.cnames.append(v)
        if not obs.ips:
            obs.status = "morto"
            return obs
        if with_ns:
            obs.zone, obs.ns = zone_ns(resolver, name)
    except BudgetExceeded:
        obs.status = "non interrogato" if not obs.ips else obs.status
    return obs


def classify(obs: Obs, cfg: dict, sinkhole: NetIndex) -> None:
    """Segna sinkhole e parcheggi: non contano come infrastruttura malevola."""
    if obs.status != "ok":
        return
    if any(not routable(ip) for ip in obs.ips) or any(sinkhole.overlaps(ipaddress.ip_network(ip)) for ip in obs.ips) \
            or any(matches(h, cfg["sinkhole_ns"]) for h in obs.ns):
        obs.status = "sinkhole"
    elif any(matches(h, cfg["parking_ns"]) for h in obs.ns) or any(matches(c, cfg["parking_ns"]) for c in obs.cnames):
        obs.status = "parcheggio"


# ---------------------------------------------------------------------------
# Selezione dei semi
# ---------------------------------------------------------------------------

def select_seeds(per_source: dict[str, set[str]], excluded: Callable[[str], bool], max_seeds: int,
                 max_per_zone: int, salt: str) -> dict[str, set[str]]:
    """Domini da risolvere → fonti che li contengono (anche tramite dominio padre).

    Ordine: più fonti prima, poi pseudo-casuale con il sale (cambia ogni settimana)."""
    index: dict[str, set[str]] = defaultdict(set)
    for sid, names in per_source.items():
        for n in names:
            index[n].add(sid)
    scored: list[tuple[int, str, str, set[str]]] = []
    for name in index:
        if "*" in name or excluded(name):
            continue
        srcs = set().union(*(index.get(s, set()) for s in suffixes(name)))
        rank = hashlib.sha256(f"{salt}|{name}".encode()).hexdigest()
        scored.append((-len(srcs), rank, name, srcs))
    scored.sort()
    seeds: dict[str, set[str]] = {}
    per_zone: Counter = Counter()
    for _, _, name, srcs in scored:
        if len(seeds) >= max_seeds:
            break
        zone = registrable_guess(name)
        if per_zone[zone] >= max_per_zone:
            continue
        per_zone[zone] += 1
        seeds[name] = srcs
    return seeds


def is_confirmed(sources: set[str], cfg: dict) -> bool:
    return len(sources) >= cfg["min_sources_confirmed"] or "manuale" in sources


# ---------------------------------------------------------------------------
# Valutazione degli IP e dei domini
# ---------------------------------------------------------------------------

@dataclass
class Filters:
    shared: NetIndex
    keep: NetIndex
    protected: NetIndex
    allow: NetIndex
    sinkhole: NetIndex
    covered: NetIndex
    asn_of: Callable[[Address], tuple[int, str] | None]
    ptr_of: Callable[[Address], str]
    shared_asn: set[int] = field(default_factory=set)
    shared_as_keywords: list[str] = field(default_factory=list)


@dataclass
class IpCandidate:
    ip: Address
    domains: list[str]
    confirmed: int
    sources: list[str]
    asn: int
    as_name: str
    ptr: str


@dataclass
class DomainCandidate:
    name: str
    kind: str          # nameserver | cname
    domains: list[str]
    ips: list[str]


def evaluate_ips(seeds: dict[str, set[str]], obs: dict[str, Obs], legit_ips: set, f: Filters,
                 cfg: dict) -> tuple[list[IpCandidate], Counter, list[dict]]:
    """IP candidati, conteggio degli scarti per motivo, IP oltre la densità massima da verificare a mano."""
    hosts: dict[Address, set[str]] = defaultdict(set)
    flagged: dict[str, set] = {"sinkhole": set(), "parcheggio": set()}
    for name, o in obs.items():
        if o.status == "ok":
            for ip in o.ips:
                hosts[ip].add(name)
        elif o.status in flagged:
            flagged[o.status].update(o.ips)
    accepted: list[IpCandidate] = []
    rejected: Counter = Counter()
    review: list[dict] = []
    for ip in sorted(set(hosts) | flagged["sinkhole"] | flagged["parcheggio"], key=lambda a: (a.version, int(a))):
        names = hosts.get(ip, set())
        domains = sorted({obs[n].domain for n in names})
        confirmed = {obs[n].domain for n in names if is_confirmed(seeds.get(n, set()), cfg)}
        net = ipaddress.ip_network(ip)
        reason = None
        if not routable(ip):
            reason = "non instradabile"
        elif f.sinkhole.overlaps(net) or ip in flagged["sinkhole"]:
            reason = "sinkhole"
        elif ip in flagged["parcheggio"]:
            reason = "parcheggio"
        elif f.keep.overlaps(net):
            reason = "resolver pubblico (keep)"
        elif f.shared.overlaps(net):
            reason = "infrastruttura condivisa"
        elif f.protected.overlaps(net):
            reason = "servizio protetto"
        elif f.allow.overlaps(net):
            reason = "ip/allowlist.txt"
        elif ip in legit_ips:
            reason = "ospita domini delle allowlist"
        elif len(domains) < cfg["min_domains"]:
            reason = "sotto la soglia di domini"
        elif len(confirmed) < cfg["min_confirmed"]:
            reason = "conferme insufficienti"
        if reason:
            rejected[reason] += 1
            continue
        info = f.asn_of(ip) or (0, "")
        if info[0] in f.shared_asn or any(k.upper() in info[1].upper()
                                          for k in f.shared_as_keywords + cfg["shared_hosting_as"]):
            rejected["AS di hosting condiviso"] += 1
            continue
        if len(domains) > cfg["max_domains"]:
            rejected["densità oltre max_domains (da verificare)"] += 1
            review.append({"ip": str(ip), "domini": len(domains), "as": f"AS{info[0]} {info[1]}".strip(),
                           "esempi": domains[:5]})
            continue
        if f.covered.overlaps(net):
            rejected["già nei feed c2/threat"] += 1
            continue
        ptr = f.ptr_of(ip)
        if matches(ptr, cfg["sinkhole_ptr"]):
            rejected["sinkhole (PTR)"] += 1
            continue
        if matches(ptr, cfg["shared_ptr"]):
            rejected["PTR di hosting condiviso"] += 1
            continue
        sources = sorted(set().union(*(seeds.get(n, set()) for n in names)))
        accepted.append(IpCandidate(ip, domains, len(confirmed), sources, info[0], info[1], ptr))
    accepted.sort(key=lambda c: (-c.confirmed, -len(c.domains), c.ip.version, int(c.ip)))
    if len(accepted) > cfg["max_ip_candidates"]:
        rejected["oltre max_ip_candidates (prossima esecuzione)"] += len(accepted) - cfg["max_ip_candidates"]
        accepted = accepted[:cfg["max_ip_candidates"]]
    return accepted, rejected, review


def evaluate_domains(obs: dict[str, Obs], legit_obs: dict[str, Obs], accepted_ips: set,
                     resolve_hosts: Callable[[list[str]], set], known: Callable[[str], str | None],
                     cfg: dict) -> tuple[list[DomainCandidate], Counter]:
    """Domini nuovi dalla stessa infrastruttura, solo con dati nostri.

    known(nome) restituisce un motivo di esclusione (già bloccato, allowlist, piattaforma) o None."""
    ns_users: dict[str, set[str]] = defaultdict(set)
    ns_hosts: dict[str, set[str]] = defaultdict(set)
    cname_users: dict[str, set[str]] = defaultdict(set)
    cname_ips: dict[str, set] = defaultdict(set)
    for o in obs.values():
        if o.status != "ok":
            continue
        for h in o.ns:
            d = registrable_guess(h)
            if d != o.domain:  # nameserver nella zona stessa: il dominio è già tra i semi
                ns_users[d].add(o.domain)
                ns_hosts[d].add(h)
        # CNAME verso un altro dominio, con tutti gli IP finali dedicati malevoli
        if o.cnames and o.ips and all(ip in accepted_ips for ip in o.ips):
            for c in o.cnames:
                d = registrable_guess(c)
                if d != o.domain:
                    cname_users[d].add(o.domain)
                    cname_ips[d].update(o.ips)
    legit = {registrable_guess(h) for o in legit_obs.values() for h in list(o.ns) + o.cnames}
    legit |= {o.domain for o in legit_obs.values()}
    found: list[DomainCandidate] = []
    rejected: Counter = Counter()
    for kind, users in (("nameserver", ns_users), ("cname", cname_users)):
        for d in sorted(users):
            zones = users[d]
            if len(zones) < cfg["min_domains"]:
                continue  # non conteggiati: quasi tutti i nameserver condivisi da pochi domini
            if d in legit:
                rejected[f"{kind} usato da domini legittimi"] += 1
                continue
            if why := known(d):
                rejected[f"{kind}: {why}"] += 1
                continue
            if kind == "nameserver":
                ips = resolve_hosts(sorted(ns_hosts[d])[:2])
                if not ips & accepted_ips:
                    rejected["nameserver non su IP malevolo dedicato"] += 1
                    continue
            else:
                ips = cname_ips[d]
            found.append(DomainCandidate(d, kind, sorted(zones), sorted(str(i) for i in ips)))
    found.sort(key=lambda c: (-len(c.domains), c.name))
    if len(found) > cfg["max_domain_candidates"]:
        rejected["oltre max_domain_candidates"] += len(found) - cfg["max_domain_candidates"]
        found = found[:cfg["max_domain_candidates"]]
    return found, rejected


# ---------------------------------------------------------------------------
# Voci per i file manuali
# ---------------------------------------------------------------------------

def safe_reason(text: str, fallback: str) -> str:
    text = text.replace("|", "/").replace("\n", " ")[:180]
    return fallback if contains_pii(text) else text


def ip_line(c: IpCandidate, today: date, expiry_days: int) -> str:
    base = f"pivot infrastruttura: IP dedicato di {len(c.domains)} domini malevoli ({c.confirmed} in più fonti)"
    full = f"{base}, es. {', '.join(c.domains[:3])}, AS{c.asn} {c.as_name.split(' ')[0]}".strip()
    return (f"{fmt(ipaddress.ip_network(c.ip))} | {today.isoformat()} | {safe_reason(full, base)} | "
            f"{TICKET_PREFIX}{today:%Y%m%d} | {(today + timedelta(days=expiry_days)).isoformat()}")


def domain_line(c: DomainCandidate, today: date, expiry_days: int) -> str:
    what = "nameserver" if c.kind == "nameserver" else "destinazione CNAME"
    base = f"pivot infrastruttura: {what} di {len(c.domains)} domini malevoli su IP malevoli dedicati"
    full = f"{base}, es. {', '.join(c.domains[:3])}"
    return (f"{c.name} | {today.isoformat()} | {safe_reason(full, base)} | {TICKET_PREFIX}{today:%Y%m%d} | "
            f"{(today + timedelta(days=expiry_days)).isoformat()}")


def entry_key(token: str) -> str:
    token = token.strip().lower()
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return token.removeprefix("*.")


def apply_entries(path: Path, header: list[str], lines: list[str], today: date) -> tuple[int, int]:
    """Aggiunge le voci nuove e toglie le voci derivate scadute. Restituisce (aggiunte, tolte)."""
    current = path.read_text(encoding="utf-8").splitlines() if path.exists() else list(header)
    kept: list[str] = []
    existing: set[str] = set()
    pruned = 0
    for line in current:
        s = line.strip()
        if s and not s.startswith("#"):
            fields = [x.strip() for x in s.split("|")]
            if (len(fields) == 5 and fields[3].startswith(TICKET_PREFIX) and valid_date(fields[4])
                    and date.fromisoformat(fields[4]) < today):
                pruned += 1
                continue
            existing.add(entry_key(fields[0]))
        kept.append(line)
    added = [ln for ln in lines if entry_key(ln.split("|")[0]) not in existing]
    if added or pruned or not path.exists():
        path.write_text("\n".join(kept + added) + "\n", encoding="utf-8", newline="\n")
    return len(added), pruned


IP_HEADER = [
    "# Feed IP - c2: voci manuali (server di comando e controllo, infrastruttura malware dedicata)",
    "# Formato: IP/CIDR | data AAAA-MM-GG | motivo | ticket (o -) | scadenza AAAA-MM-GG (opzionale)",
    "# Le voci con ticket pivot-AAAAMMGG sono proposte da scripts/pivot_infra.py (PR settimanale): scadenza",
    "# obbligatoria, tolte in automatico quando scadono. Nel motivo MAI dati personali.",
]
DOMAIN_HEADER = [
    "# Blocklist domini - malware: voci manuali (le fonti upstream sono in domains/domains.toml)",
    "# Formato: dominio | data inserimento AAAA-MM-GG | motivo | ticket (o -) | scadenza AAAA-MM-GG (opzionale)",
    "# Le voci con ticket pivot-AAAAMMGG sono proposte da scripts/pivot_infra.py (PR settimanale): scadenza",
    "# obbligatoria, tolte in automatico quando scadono. Ogni dominio include i sottodomini.",
]


# ---------------------------------------------------------------------------
# Esecuzione
# ---------------------------------------------------------------------------

def load_config() -> dict:
    raw = tomllib.loads(PIVOT_CONFIG.read_text(encoding="utf-8")) if PIVOT_CONFIG.exists() else {}
    cfg = {**DEFAULTS, **raw.get("pivot", {})}
    unknown = set(raw.get("pivot", {})) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"ip/pivot.toml: chiavi sconosciute {sorted(unknown)}")
    for k in ("min_domains", "min_confirmed", "max_seeds", "expiry_days", "max_queries"):
        if not isinstance(cfg[k], int) or cfg[k] < 1:
            raise ValueError(f"ip/pivot.toml: {k} deve essere un intero positivo")
    if cfg["min_domains"] < 2:
        raise ValueError("ip/pivot.toml: min_domains deve essere almeno 2 (più domini malevoli distinti)")
    if cfg["expiry_days"] > 90:
        raise ValueError("ip/pivot.toml: expiry_days oltre 90 giorni")
    cfg["shared_sources"] = raw.get("shared_sources", [])
    cfg["sinkhole_nets"] = [ipaddress.ip_network(n) for n in cfg["sinkhole_nets"]]
    return cfg


class AsnIndex:
    """IP → (AS, descrizione) dal database iptoasn.com già scaricato da asn.py."""

    def __init__(self, rows) -> None:
        self.tables: dict[int, tuple[list[int], list[int], list[tuple[int, str]]]] = {}
        for v in (4, 6):
            r = sorted((s, e, a, d) for ver, s, e, a, d in rows if ver == v)
            self.tables[v] = ([x[0] for x in r], [x[1] for x in r], [(x[2], x[3]) for x in r])

    def lookup(self, ip: Address) -> tuple[int, str] | None:
        starts, ends, info = self.tables[ip.version]
        i = bisect.bisect_right(starts, int(ip)) - 1
        return info[i] if i >= 0 and int(ip) <= ends[i] else None


def reverse_name(ip: Address) -> str:
    return ip.reverse_pointer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="fonti dei domini dalla cache (il DNS serve comunque)")
    parser.add_argument("--apply", action="store_true", help="aggiunge i candidati ai file manuali con scadenza")
    parser.add_argument("--report", type=Path, help="report markdown")
    parser.add_argument("--json", type=Path, help="candidati e prove in JSON")
    parser.add_argument("--max-seeds", type=int, help="sovrascrive max_seeds (prove locali)")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    started = time.monotonic()
    today = date.today()
    try:
        cfg = load_config()
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        fail(str(exc))
        return 1
    if args.max_seeds:
        cfg["max_seeds"] = args.max_seeds

    # Semi: fonti upstream di block-malware e block-phishing + voci manuali confermate
    dcfg = tomllib.loads(BD.CONFIG_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    per_source: dict[str, set[str]] = {}
    for src in dcfg.get("sources", []):
        if src.get("category") in SEED_CATEGORIES and src.get("enabled", True):
            names, status = BD.load_domain_source(src, args.offline, persist=False)
            per_source[src["id"]] = names
            print(f"- fonte {src['id']}: {status}")
    manual_path = BD.DOMAINS_DIR / "blocklist" / f"{MANUAL_SEEDS}.txt"
    if manual_path.exists():
        per_source["manuale"] = set(BD.load(manual_path, tld=False, today=today, errors=errors)[0])

    allow_names: set[str] = set()
    for path in sorted((BD.DOMAINS_DIR / "allowlist").glob("*.txt")):
        allow_names.update(BD.load(path, tld=False, today=today, errors=errors)[0])
    allow_names.update(dcfg.get("own_domains", []))
    curated = set(BD.load(BD.EXCLUDE_PATH, tld=False, today=today, errors=errors)[0]) if BD.EXCLUDE_PATH.exists() else set()
    platforms, psl_status = BD.load_psl(dcfg, args.offline, persist=False)
    print(f"- Public Suffix List: {psl_status}")
    blocked_all = set().union(*per_source.values())
    if DOMAIN_TARGET.exists():
        blocked_all |= set(BD.load(DOMAIN_TARGET, tld=False, today=today, errors=errors)[0])

    def allowlisted(name: str) -> bool:
        return any(BD.covers(a, name) or BD.covers(name, a) for a in allow_names if "*" in a) or \
            any(s in allow_names for s in suffixes(name) + [name]) or name in curated

    def platform(name: str) -> bool:
        return any(s in platforms for s in suffixes(name) + [name])

    def known(name: str) -> str | None:
        if any(s in blocked_all for s in suffixes(name) + [name]):
            return "già bloccato"
        if allowlisted(name):
            return "in allowlist"
        if platform(name):
            return "piattaforma condivisa (PSL)"
        return None

    salt = f"{today.isocalendar().year}-W{today.isocalendar().week}"
    seeds = select_seeds(per_source, lambda n: allowlisted(n) or platform(n), cfg["max_seeds"],
                         cfg["max_per_zone"], salt)
    multi = sum(1 for s in seeds.values() if is_confirmed(s, cfg))
    print(f"- semi: {len(seeds)} ({multi} confermati da più fonti o manuali), sale {salt}")

    # Filtri condivisi: stessi dei feed (ip/sources.toml + ip/condivisi.txt) più quelli del pivot
    ip_cfg = tomllib.loads(IP_CONFIG.read_text(encoding="utf-8"))
    shared_cfg = {"shared_sources": ip_cfg.get("shared_sources", []) + cfg["shared_sources"]}
    try:
        shared = load_shared(shared_cfg, errors)
        asn_index = AsnIndex(asn.rows())
    except Exception as exc:  # senza filtro delle infrastrutture condivise non si propone nulla
        fail(f"intervalli condivisi non disponibili ({exc}): nessun candidato")
        return 1
    keep = [ipaddress.ip_network(k) for s in shared_cfg["shared_sources"] for k in s.get("keep", [])]
    allow_ips = [e.net for e in load_annotated(ALLOWLIST_PATH, min_prefix=None, today=today, errors=errors)[0]]
    protected = resolve_protected()
    covered: set = set()
    for cat in COVERED_FEEDS:
        for v in (4, 6):
            p = DIST_DIR / f"{cat}-v{v}.txt"
            if p.exists():
                covered |= parse_source_text(p.read_text(encoding="utf-8"), None)[0]
    own_c2 = [e.net for e in load_annotated(IP_TARGET, min_prefix=None, today=today, errors=errors)[0]] \
        if IP_TARGET.exists() else []
    opn = dcfg.get("opnsense_check", {})

    server = system_resolver()
    resolver = Resolver(server, qps=cfg["qps"], max_queries=cfg["max_queries"], timeout=cfg["timeout"],
                        deadline=started + cfg["max_seconds"])
    print(f"- resolver {server}: massimo {cfg['max_queries']} query, {cfg['qps']} al secondo")

    legit_hosts = sorted(n for n in allow_names if "*" not in n)[:cfg["max_legit"]]
    with cf.ThreadPoolExecutor(cfg["workers"]) as ex:
        legit_obs = dict(zip(legit_hosts, ex.map(lambda n: observe(resolver, n), legit_hosts)))
        obs = dict(zip(seeds, ex.map(lambda n: observe(resolver, n), seeds)))
    legit_ips = {ip for o in legit_obs.values() for ip in o.ips} | {n.network_address for n in protected}
    sink = NetIndex(cfg["sinkhole_nets"])
    for o in obs.values():
        classify(o, cfg, sink)
    statuses = Counter(o.status for o in obs.values())
    print("- esiti semi: " + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())))

    def ptr_of(ip: Address) -> str:
        try:
            r = resolver.query(reverse_name(ip), "PTR")
        except BudgetExceeded:
            return ""
        return next((v for _, t, v in (r.answers if r else []) if t == 12), "")

    filters = Filters(shared=NetIndex(shared), keep=NetIndex(keep), protected=NetIndex(protected),
                      allow=NetIndex(allow_ips), sinkhole=sink, covered=NetIndex(list(covered) + own_c2),
                      asn_of=asn_index.lookup, ptr_of=ptr_of, shared_asn=set(opn.get("shared_asn", [])),
                      shared_as_keywords=list(opn.get("shared_as_keywords", [])))
    resolved = sum(1 for o in obs.values() if o.status != "non interrogato" and o.status != "errore")
    alive = sum(1 for o in obs.values() if o.status in ("ok", "sinkhole", "parcheggio"))
    dns_ok = bool(seeds) and resolved / len(seeds) >= MIN_RESOLVED_RATIO and alive / len(seeds) >= MIN_ALIVE_RATIO
    ip_cands, ip_rejected, review = evaluate_ips(seeds, obs, legit_ips, filters, cfg) if dns_ok else ([], Counter(), [])
    accepted_ips = {c.ip for c in ip_cands}

    def resolve_hosts(hosts: list[str]) -> set:
        out: set = set()
        for h in hosts:
            o = observe(resolver, h, with_ns=False)
            out |= o.ips
        return out

    dom_cands, dom_rejected = evaluate_domains(obs, legit_obs, accepted_ips, resolve_hosts, known, cfg) \
        if dns_ok else ([], Counter())
    elapsed = time.monotonic() - started

    report = [f"## Pivot sull'infrastruttura dei domini malevoli ({today.isoformat()})", "",
              f"- semi risolti: {len(seeds)} ({multi} confermati), esiti: "
              + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())),
              f"- query DNS: {resolver.sent} su {cfg['max_queries']} (fallite {resolver.failed}), resolver `{server}`, "
              f"{elapsed:.0f} s",
              f"- controllo legittimi: {len(legit_obs)} host delle allowlist, {len(legit_ips)} IP",
              f"- IP candidati: **{len(ip_cands)}**, domini candidati: **{len(dom_cands)}**, scadenza "
              f"{cfg['expiry_days']} giorni", ""]
    if not dns_ok:
        report += ["**Risoluzione DNS insufficiente o filtrata (quasi tutti i semi senza risposta o NXDOMAIN): "
                   "nessun candidato.**", ""]
    if ip_cands:
        report += ["### IP candidati (ip/custom/c2.txt)", "",
                   "| IP | AS | Domini malevoli | Confermati | Fonti | Esempi | PTR |", "|---|---|---|---|---|---|---|"]
        report += [f"| `{c.ip}` | AS{c.asn} {c.as_name} | {len(c.domains)} | {c.confirmed} | {', '.join(c.sources)} | "
                   f"{', '.join(c.domains[:4])} | {c.ptr or '—'} |" for c in ip_cands] + [""]
    if dom_cands:
        report += ["### Domini candidati (domains/blocklist/malware.txt)", "",
                   "| Dominio | Tipo | Domini malevoli collegati | IP | Esempi |", "|---|---|---|---|---|"]
        report += [f"| `{c.name}` | {c.kind} | {len(c.domains)} | {', '.join(c.ips[:3])} | {', '.join(c.domains[:4])} |"
                   for c in dom_cands] + [""]
    if review:
        report += ["### Densità oltre soglia: da verificare a mano, non proposti", "",
                   "| IP | AS | Domini | Esempi |", "|---|---|---|---|"]
        report += [f"| `{r['ip']}` | {r['as']} | {r['domini']} | {', '.join(r['esempi'])} |" for r in review[:30]] + [""]
    if ip_rejected or dom_rejected:
        report += ["### Scartati", ""]
        report += [f"- IP, {k}: {v}" for k, v in sorted(ip_rejected.items())]
        report += [f"- domini, {k}: {v}" for k, v in sorted(dom_rejected.items())] + [""]
    report += ["Ogni voce va verificata prima dell'approvazione: un IP dedicato può passare a un altro cliente "
               "del provider. Le voci scadono da sole; un falso positivo va in `ip/allowlist.txt` o "
               "`domains/allowlist/`.", ""]

    if args.apply and dns_ok:
        ip_lines = [ip_line(c, today, cfg["expiry_days"]) for c in ip_cands]
        dom_lines = [domain_line(c, today, cfg["expiry_days"]) for c in dom_cands]
        a1, p1 = apply_entries(IP_TARGET, IP_HEADER, ip_lines, today)
        a2, p2 = apply_entries(DOMAIN_TARGET, DOMAIN_HEADER, dom_lines, today)
        report += [f"Applicati: {a1} IP e {a2} domini aggiunti, {p1 + p2} voci derivate scadute tolte.", ""]

    text = "\n".join(report)
    print(text)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    if args.json:
        payload = {
            "data": today.isoformat(), "resolver": server, "query": resolver.sent, "secondi": round(elapsed),
            "semi": len(seeds), "esiti": dict(statuses), "soglie": {k: cfg[k] for k in (
                "min_domains", "min_confirmed", "max_domains", "min_sources_confirmed", "expiry_days")},
            "ip": [{"ip": str(c.ip), "as": c.asn, "as_nome": c.as_name, "ptr": c.ptr, "domini": c.domains,
                    "confermati": c.confirmed, "fonti": c.sources} for c in ip_cands],
            "domini": [vars(c) for c in dom_cands],
            "scartati_ip": dict(ip_rejected), "scartati_domini": dict(dom_rejected), "da_verificare": review,
        }
        args.json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    for e in errors:
        warn(e)
    if not dns_ok:
        warn("risoluzione DNS insufficiente: nessun candidato proposto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
